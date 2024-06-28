#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_xdp_adjust_head,
    macros::{map, xdp},
    maps::{Array, PerCpuArray, ProgramArray},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use core::slice;
use memcached_ebpf_proxy_cache_common::{
    CacheEntry, CacheUsageStatistics, ProgTc, ProgXdp, CACHE_ENTRY_COUNT, MAX_KEYS_IN_PACKET,
    MAX_KEY_LENGTH, MAX_PACKET_LENGTH,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[repr(C)]
pub struct MemcachedUdpHeader {
    pub request_id: u16,
    pub seq_num: u16,
    pub num_dgram: u16,
    pub unused: u16,
}

#[map]
static MAP_KCACHE: Array<CacheEntry> = Array::with_max_entries(CACHE_ENTRY_COUNT, 0);

#[repr(C)]
pub struct MemcachedKey {
    pub hash: u32,
    pub data: [u8; MAX_KEY_LENGTH],
    pub len: u32,
}

#[map]
static MAP_KEYS: PerCpuArray<MemcachedKey> = PerCpuArray::with_max_entries(MAX_KEYS_IN_PACKET, 0);

#[repr(C)]
pub struct ParsingContext {
    pub key_count: u32,
    pub current_key: u32,

    pub write_packet_offset: u16,
    pub read_packet_offset: u16,
}

#[map]
static PARSING_CONTEXT: PerCpuArray<ParsingContext> = PerCpuArray::with_max_entries(1, 0);

#[map]
static CACHE_USAGE_STATS: PerCpuArray<CacheUsageStatistics> = PerCpuArray::with_max_entries(1, 0);

#[map]
static MAP_PROGS_XDP: ProgramArray = ProgramArray::with_max_entries(ProgXdp::Max as u32, 0);

#[map]
static MAP_PROGS_TC: ProgramArray = ProgramArray::with_max_entries(ProgTc::Max as u32, 0);

#[inline(always)]
pub fn compute_ip_checksum(ip: *const Ipv4Hdr) -> u16 {
    // SAFETY: num u16 chunks in *X
    //         = (num u8 chunks in *X) / 2
    //         = size_of::<X>() >> 1
    let ip_u16_chunks =
        unsafe { slice::from_raw_parts(ip as *const u16, mem::size_of::<Ipv4Hdr>() >> 1) };

    // use 32 bits for storing sum result to prevent integer overflow
    let csum = ip_u16_chunks
        .iter()
        .fold(0u32, |sum, chunk| sum + *chunk as u32);

    (!((csum & 0xffff) + (csum >> 16))) as u16
}

#[allow(clippy::result_unit_err)]
#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[allow(clippy::result_unit_err)]
#[inline(always)]
pub fn slice_at<T>(ctx: &XdpContext, offset: usize) -> Result<&[T], ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    let slice_len = (end - offset) / len;

    // SAFETY: slice contains number of T that can be acoomodated
    // within start..end
    Ok(unsafe { slice::from_raw_parts(ptr, slice_len) })
}

fn try_rx_filter(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; //

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Err(()),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    let protocol = unsafe { (*ipv4hdr).proto };

    let (dest, payload) = match protocol {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*tcphdr).dest }),
                slice_at::<u8>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN)?,
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*udphdr).dest }),
                slice_at::<u8>(
                    &ctx,
                    EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + size_of::<MemcachedUdpHeader>(),
                )?,
            )
        }
        _ => return Err(()),
    };

    if payload.len() < 4 {
        return Err(());
    }

    match (protocol, dest, &payload[..4]) {
        (IpProto::Udp, 11211, b"get ") => {
            let cache_usage_stats = CACHE_USAGE_STATS.get_ptr_mut(0).ok_or(())?;
            unsafe {
                (*cache_usage_stats).get_recv_count += 1;
            }

            let parsing_context = PARSING_CONTEXT.get_ptr_mut(0).ok_or(())?;

            unsafe {
                (*parsing_context).key_count = 0;
                (*parsing_context).current_key = 0;
                (*parsing_context).write_packet_offset = 0;
            }

            let first_non_space_char_pos = &payload[4..]
                .iter()
                .take(MAX_PACKET_LENGTH)
                .position(|&x| x != b' ')
                .ok_or(())?;

            unsafe {
                (*parsing_context).read_packet_offset = *first_non_space_char_pos as u16;
            }

            unsafe {
                bpf_xdp_adjust_head(
                    ctx.ctx,
                    (EthHdr::LEN
                        + Ipv4Hdr::LEN
                        + UdpHdr::LEN
                        + size_of::<MemcachedUdpHeader>()
                        + first_non_space_char_pos) as i32,
                )
            }
            .eq(&0)
            .then_some(())
            .ok_or(())?;

            unsafe { MAP_PROGS_XDP.tail_call(&ctx, ProgXdp::HashKeys as u32) }.map_err(|_| ())?;
        }
        (IpProto::Tcp, 11211, _) => {
            unsafe { MAP_PROGS_XDP.tail_call(&ctx, ProgXdp::InvalidateCache as u32) }
                .map_err(|_| ())?;
        }
        _ => Err(()),
    }
}

#[xdp]
pub fn rx_filter(ctx: XdpContext) -> u32 {
    match try_rx_filter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_memcached_ebpf_proxy_cache(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}

#[xdp]
pub fn memcached_ebpf_proxy_cache(ctx: XdpContext) -> u32 {
    match try_memcached_ebpf_proxy_cache(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
