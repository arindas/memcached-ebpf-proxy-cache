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

pub enum CacheError {
    HeaderParseError,
    PtrSliceCoercionError,
    MapLookupError,
    BadRequestPacket,
}

impl From<CacheError> for u32 {
    fn from(val: CacheError) -> Self {
        val as u32
    }
}

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

#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
pub fn slice_at<T>(ctx: &XdpContext, offset: usize, slice_len: usize) -> Option<&[T]> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + slice_len * len > end {
        return None;
    }

    Some(unsafe { slice::from_raw_parts((start + offset) as *const T, slice_len) })
}

fn try_rx_filter(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "rx_filter: received a packet");

    let ethhdr: *const EthHdr = ptr_at(&ctx, 0).ok_or(CacheError::HeaderParseError)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Err(CacheError::HeaderParseError.into()),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN).ok_or(CacheError::HeaderParseError)?;

    let protocol = unsafe { (*ipv4hdr).proto };

    let (dest, payload_offset) = match protocol {
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(CacheError::HeaderParseError)?;
            (
                u16::from_be(unsafe { (*udphdr).dest }),
                EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + size_of::<MemcachedUdpHeader>(),
            )
        }
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(CacheError::HeaderParseError)?;
            (
                u16::from_be(unsafe { (*tcphdr).dest }),
                EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN,
            )
        }
        _ => return Err(0u32),
    };

    let first_4_bytes =
        slice_at::<u8>(&ctx, payload_offset, 4).ok_or(CacheError::PtrSliceCoercionError)?;

    match (protocol, dest, first_4_bytes) {
        (IpProto::Udp, 11211, b"get ") => {
            let cache_usage_stats = CACHE_USAGE_STATS
                .get_ptr_mut(0)
                .ok_or(CacheError::MapLookupError)?;
            unsafe {
                (*cache_usage_stats).get_recv_count += 1;
            }

            let parsing_context = PARSING_CONTEXT
                .get_ptr_mut(0)
                .ok_or(CacheError::MapLookupError)?;

            unsafe {
                (*parsing_context).key_count = 0;
                (*parsing_context).current_key = 0;
                (*parsing_context).write_packet_offset = 0;
            }

            let mut pos = 4;

            while pos < MAX_PACKET_LENGTH
                && ctx.data() + pos + mem::size_of::<u8>() <= ctx.data_end()
                && unsafe { *((ctx.data() + pos) as *const u8) } == b' '
            {
                pos += 1;
            }

            if pos >= MAX_PACKET_LENGTH {
                return Err(CacheError::BadRequestPacket.into());
            }

            unsafe {
                (*parsing_context).read_packet_offset = pos as u16;
            }

            unsafe {
                bpf_xdp_adjust_head(
                    ctx.ctx,
                    (EthHdr::LEN
                        + Ipv4Hdr::LEN
                        + UdpHdr::LEN
                        + size_of::<MemcachedUdpHeader>()
                        + pos) as i32,
                )
            }
            .eq(&0)
            .then_some(())
            .ok_or(0u32)?;

            unsafe { MAP_PROGS_XDP.tail_call(&ctx, ProgXdp::HashKeys as u32) }.map_err(|_| 0u32)?;
        }
        (IpProto::Tcp, 11211, _) => {
            unsafe { MAP_PROGS_XDP.tail_call(&ctx, ProgXdp::InvalidateCache as u32) }
                .map_err(|_| 0u32)?;
        }
        _ => Err(0u32),
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
