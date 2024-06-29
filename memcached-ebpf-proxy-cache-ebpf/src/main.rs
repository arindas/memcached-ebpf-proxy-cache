#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_spin_lock, xdp_action},
    helpers::{bpf_spin_lock, bpf_spin_unlock, bpf_xdp_adjust_head},
    macros::{map, xdp},
    maps::{Array, PerCpuArray, ProgramArray},
    programs::XdpContext,
};
use aya_log_ebpf::{debug, error, info};
use core::mem;
use core::slice;
use memcached_ebpf_proxy_cache_common::{
    CacheEntry, CacheUsageStatistics, CallableProgTc, CallableProgXdp, Fnv1AHasher, Hasher,
    CACHE_ENTRY_COUNT, MAX_KEYS_IN_PACKET, MAX_KEY_LENGTH, MAX_PACKET_LENGTH, MEMCACHED_PORT,
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
static MAP_CALLABLE_PROGS_XDP: ProgramArray =
    ProgramArray::with_max_entries(CallableProgXdp::Max as u32, 0);

#[map]
static MAP_CALLABLE_PROGS_TC: ProgramArray =
    ProgramArray::with_max_entries(CallableProgTc::Max as u32, 0);

pub enum CacheError {
    PacketOffsetOutofBounds,
    HeaderParseError,
    PtrSliceCoercionError,
    MapLookupError,
    BadRequestPacket,
    TailCallError,
    UnsupportedProtocol,
    UnexpectedKeyLen,
    UnexpectedValLen,
}

impl AsRef<str> for CacheError {
    fn as_ref(&self) -> &str {
        match self {
            CacheError::PacketOffsetOutofBounds => "CacheError::PacketOffsetOutofBounds",
            CacheError::HeaderParseError => "CacheError::HeaderParseError",
            CacheError::PtrSliceCoercionError => "CacheError::PtrSliceCoercionError",
            CacheError::MapLookupError => "CacheError::MapLookupError",
            CacheError::BadRequestPacket => "CacheError::BadRequestPacket",
            CacheError::TailCallError => "CacheError::TailCallError",
            CacheError::UnsupportedProtocol => "CacheError::UnsupportedProtocol",
            CacheError::UnexpectedKeyLen => "CacheError::UnexpectedKeyLen",
            CacheError::UnexpectedValLen => "CacheError::UnexpectedValLen",
        }
    }
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

#[inline(always)]
/// Returns the position of the first byte after skipping the first consecutive sequence of the given
/// char in the current packet.
///
/// The position returned is guranteed to be within the provided upper bound and packet data end.
pub fn skip_chars_in_packet(
    ctx: &XdpContext,
    start_pos: usize,
    skip_char: u8,
    pos_upper_bound: usize,
) -> usize {
    let mut pos = start_pos;

    while pos < pos_upper_bound
        && ctx.data() + pos + mem::size_of::<u8>() <= ctx.data_end()
        && unsafe { *((ctx.data() + pos) as *const u8) } == skip_char
    {
        pos += 1;
    }

    pos
}

fn try_rx_filter(ctx: &XdpContext) -> Result<u32, CacheError> {
    let ethhdr: *const EthHdr = ptr_at(ctx, 0).ok_or(CacheError::HeaderParseError)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Err(CacheError::HeaderParseError),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN).ok_or(CacheError::HeaderParseError)?;

    let protocol = unsafe { (*ipv4hdr).proto };

    debug!(
        ctx,
        "rx_filter: recv Ipv4 packet with protocol: {}", protocol as u32
    );

    let (dest, payload_offset) = match protocol {
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(CacheError::HeaderParseError)?;
            (
                u16::from_be(unsafe { (*udphdr).dest }),
                EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + size_of::<MemcachedUdpHeader>(),
            )
        }
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(CacheError::HeaderParseError)?;
            (
                u16::from_be(unsafe { (*tcphdr).dest }),
                EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN,
            )
        }
        _ => return Err(CacheError::UnsupportedProtocol),
    };

    debug!(
        ctx,
        "rx_filter: recv packet with dest: {}, payload_offset: {}", dest, payload_offset
    );

    let first_4_bytes =
        slice_at::<u8>(ctx, payload_offset, 4).ok_or(CacheError::PtrSliceCoercionError)?;

    match (protocol, dest, first_4_bytes) {
        (IpProto::Udp, MEMCACHED_PORT, b"get ") => {
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

            let pos = skip_chars_in_packet(ctx, 4, b' ', MAX_PACKET_LENGTH);

            debug!(ctx, "rx_filter: get packet keys begin at {}", pos);

            if pos >= MAX_PACKET_LENGTH {
                return Err(CacheError::BadRequestPacket);
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
            .ok_or(CacheError::PacketOffsetOutofBounds)?;

            unsafe { MAP_CALLABLE_PROGS_XDP.tail_call(ctx, CallableProgXdp::HashKeys as u32) }
                .map_err(|_| CacheError::TailCallError)?;
        }
        (IpProto::Tcp, MEMCACHED_PORT, _) => {
            unsafe {
                MAP_CALLABLE_PROGS_XDP.tail_call(ctx, CallableProgXdp::InvalidateCache as u32)
            }
            .map_err(|_| CacheError::TailCallError)?;
        }
        _ => Err(CacheError::BadRequestPacket),
    }
}

#[xdp]
pub fn rx_filter(ctx: XdpContext) -> u32 {
    info!(&ctx, "rx_filter: received a packet");

    match try_rx_filter(&ctx) {
        Ok(ret) => {
            info!(&ctx, "rx_filter: done processing packet, action: {}", ret);

            ret
        }
        Err(err) => {
            error!(&ctx, "rx_filter: Err({})", err.as_ref());

            xdp_action::XDP_PASS
        }
    }
}

fn try_hash_keys(ctx: &XdpContext) -> Result<u32, CacheError> {
    let _payload_ptr: *const u8 = ptr_at(ctx, ctx.data()).ok_or(CacheError::BadRequestPacket)?;

    let parsing_context = PARSING_CONTEXT
        .get_ptr_mut(0)
        .ok_or(CacheError::MapLookupError)?;

    let memcached_key = MAP_KEYS
        .get_ptr_mut(unsafe { (*parsing_context).key_count })
        .ok_or(CacheError::MapLookupError)?;

    let mut hasher = Fnv1AHasher::new();

    let mut offset = 0;
    let mut done_parsing = false;
    let mut key_len = 0;

    // use MAX_KEY_LENGTH + 1 as upper bound to make it possible to detect if
    // key length is greater than MAX_KEY_LENGTH
    while offset < MAX_KEY_LENGTH + 1
        && ctx.data() + offset + mem::size_of::<u8>() <= ctx.data_end()
    {
        match unsafe { *((ctx.data() + offset) as *const u8) } {
            b'\r' => {
                done_parsing = true;
                break;
            }

            b' ' => break,

            byte => {
                hasher.write_byte(byte);
                key_len += 1;
            }
        }

        offset += 1;
    }

    unsafe { (*memcached_key).hash = hasher.finish() };

    if key_len == 0 || key_len > MAX_KEY_LENGTH {
        unsafe {
            bpf_xdp_adjust_head(
                ctx.ctx,
                0 - (EthHdr::LEN
                    + Ipv4Hdr::LEN
                    + UdpHdr::LEN
                    + size_of::<MemcachedUdpHeader>()
                    + (*parsing_context).read_packet_offset as usize) as i32,
            )
        }
        .eq(&0)
        .then_some(())
        .ok_or(CacheError::PacketOffsetOutofBounds)?;

        return Err(CacheError::UnexpectedKeyLen);
    }

    let cache_idx = unsafe { (*memcached_key).hash } % CACHE_ENTRY_COUNT;

    let cache_entry = MAP_KCACHE
        .get_ptr_mut(cache_idx)
        .ok_or(CacheError::MapLookupError)?;

    unsafe {
        bpf_spin_lock(&mut (*cache_entry).lock as *mut bpf_spin_lock);
    }

    if unsafe { (*cache_entry).valid != 0 && (*cache_entry).hash == (*memcached_key).hash } {
        unsafe { bpf_spin_unlock(&mut (*cache_entry).lock as *mut bpf_spin_lock) };

        let key = slice_at::<u8>(ctx, 0, key_len).ok_or(CacheError::PtrSliceCoercionError)?;

        unsafe {
            (*memcached_key).data.copy_from_slice(key);
            (*parsing_context).key_count += 1;
        }
    } else {
        unsafe { bpf_spin_unlock(&mut (*cache_entry).lock as *mut bpf_spin_lock) };

        let cache_usage_stats = CACHE_USAGE_STATS
            .get_ptr_mut(0)
            .ok_or(CacheError::MapLookupError)?;

        unsafe { (*cache_usage_stats).miss_count += 1 };
    }

    if done_parsing {
        // reached end of request

        // pop headers + "get " + previous keys
        unsafe {
            bpf_xdp_adjust_head(
                ctx.ctx,
                0 - (EthHdr::LEN
                    + Ipv4Hdr::LEN
                    + UdpHdr::LEN
                    + size_of::<MemcachedUdpHeader>()
                    + (*parsing_context).read_packet_offset as usize) as i32,
            )
        }
        .eq(&0)
        .then_some(())
        .ok_or(CacheError::PacketOffsetOutofBounds)?;

        if unsafe { (*parsing_context).key_count > 0 } {
            unsafe { MAP_CALLABLE_PROGS_XDP.tail_call(ctx, CallableProgXdp::PreparePacket as u32) }
                .map_err(|_| CacheError::TailCallError)?;
        }
    } else {
        // more keys to process

        // move offset to start of next key
        offset += 1;
        unsafe { (*parsing_context).read_packet_offset += offset as u16 };

        unsafe { bpf_xdp_adjust_head(ctx.ctx, offset as i32) } // push previous key
            .eq(&0)
            .then_some(())
            .ok_or(CacheError::PacketOffsetOutofBounds)?;

        unsafe { MAP_CALLABLE_PROGS_XDP.tail_call(ctx, CallableProgXdp::HashKeys as u32) }
            .map_err(|_| CacheError::TailCallError)?;
    }

    Ok(xdp_action::XDP_PASS)
}

#[xdp]
pub fn hash_keys(ctx: XdpContext) -> u32 {
    info!(&ctx, "hash_keys: received a packet");

    match try_hash_keys(&ctx) {
        Ok(ret) => {
            info!(&ctx, "hash_keys: done processing packet, action: {}", ret);

            ret
        }
        Err(err) => {
            error!(&ctx, "hash_keys: Err({})", err.as_ref());

            xdp_action::XDP_PASS
        }
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
