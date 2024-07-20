#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(core_intrinsics)]

#[allow(unused)]
use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_xdp_adjust_head,
    macros::{map, xdp},
    maps::{Array, PerCpuArray, ProgramArray},
    programs::XdpContext,
};
#[allow(unused)]
use aya_log_ebpf::{debug, error, info};
use core::intrinsics::atomic_xchg_seqcst;
use core::{mem, slice};
#[allow(unused)]
use memcached_ebpf_proxy_cache_common::{
    CacheEntry, CacheUsageStatistics, CallableProgTc, CallableProgXdp, Fnv1AHasher, Hasher,
    CACHE_ENTRY_COUNT, MAX_KEYS_IN_PACKET, MAX_KEY_LENGTH, MAX_PACKET_LENGTH,
    MAX_SPIN_LOCK_ITER_RETRY_LIMIT, MAX_TAIL_CALL_LOCK_RETRY_LIMIT, MEMCACHED_PORT,
};
use memcached_network_types::{
    binary::{Opcode, PacketHeader as MemcachedPacketHeader, ReqMagicByte},
    integer_enum_variant_constants,
    udp::MemcachedUdpHeader,
};
#[allow(unused)]
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map]
static MAP_KCACHE: Array<CacheEntry> = Array::with_max_entries(CACHE_ENTRY_COUNT, 0);

#[repr(C)]
pub struct MemcachedKey {
    pub hash: u32,
    pub data: [u8; MAX_KEY_LENGTH],
    pub len: u32,
}

#[repr(C)]
pub struct ParsingContext {
    memcached_packet_offset: usize,
    memcached_packet_header: MemcachedPacketHeader,
}

#[map]
static PARSING_CONTEXT: PerCpuArray<ParsingContext> = PerCpuArray::with_max_entries(1, 0);

#[map]
static MAP_KEYS: PerCpuArray<MemcachedKey> = PerCpuArray::with_max_entries(MAX_KEYS_IN_PACKET, 0);

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
    LockRetryLimitHit,
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
            CacheError::LockRetryLimitHit => "CacheError::LockRetryLimitHit",
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
    let item_len = mem::size_of::<T>();

    if start + offset + item_len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    Some(ptr_at::<T>(ctx, offset)? as *mut T)
}

#[inline(always)]
pub fn slice_at<T>(ctx: &XdpContext, offset: usize, slice_len: usize) -> Option<&[T]> {
    let start = ctx.data();
    let end = ctx.data_end();
    let item_len = mem::size_of::<T>();

    if start + offset + slice_len * item_len >= end {
        return None;
    }

    Some(unsafe { slice::from_raw_parts((start + offset) as *const T, slice_len) })
}

#[allow(unused)]
fn try_spin_lock_acquire(lock: &mut u64, retry_limit: u32) -> Result<(), u32> {
    let mut retries = 0;

    while retries < retry_limit && unsafe { atomic_xchg_seqcst(lock as *mut u64, 1) } != 0 {
        retries += 1;
    }

    (retries < retry_limit).then_some(()).ok_or(retries)
}

#[allow(unused)]
fn spin_lock_release(lock: &mut u64) {
    unsafe { atomic_xchg_seqcst(lock as *mut u64, 0) };
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

    let (dest_port, payload_offset) = match protocol {
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(CacheError::HeaderParseError)?;
            (
                u16::from_be(unsafe { (*udphdr).dest }),
                EthHdr::LEN
                    + Ipv4Hdr::LEN
                    + UdpHdr::LEN
                    + core::mem::size_of::<MemcachedUdpHeader>(),
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
        "rx_filter: dest_port={}, protocol={}", dest_port, protocol as u32
    );

    if let (IpProto::Tcp, MEMCACHED_PORT) = (protocol, dest_port) {
        unsafe { MAP_CALLABLE_PROGS_XDP.tail_call(ctx, CallableProgXdp::InvalidateCache as u32) }
            .map_err(|_| CacheError::TailCallError)?;
    }

    let memcached_packet_header =
        unsafe { &mut *ptr_at_mut(ctx, payload_offset).ok_or(CacheError::HeaderParseError)? }
            as &mut MemcachedPacketHeader;

    let magic_byte = memcached_packet_header.magic_byte;
    let opcode = memcached_packet_header.opcode;
    let key_length = memcached_packet_header.key_length.get();

    debug!(
        ctx,
        "rx_filter: dest_port={}, memcached_packet_header: magic_byte={}, opcode={}, key_length={}",
        dest_port,
        magic_byte,
        opcode,
        key_length
    );

    if key_length > MAX_KEY_LENGTH as u16 {
        return Err(CacheError::UnexpectedKeyLen);
    }

    const REQ_MAGIC_BYTE: u8 = ReqMagicByte::ReqPacket as u8;

    integer_enum_variant_constants!(
        Opcode,
        u8,
        (GET, Get),
        (GETK, GetK),
        (GETQ, GetQ),
        (GETKQ, GetKQ)
    );

    match match (dest_port, magic_byte, opcode) {
        (MEMCACHED_PORT, REQ_MAGIC_BYTE, GETK | GETKQ) => Some(CallableProgXdp::HashKey),
        (MEMCACHED_PORT, REQ_MAGIC_BYTE, GET) => {
            memcached_packet_header.opcode = GETK;
            Some(CallableProgXdp::HashKey)
        }
        (MEMCACHED_PORT, REQ_MAGIC_BYTE, GETQ) => {
            memcached_packet_header.opcode = GETKQ;
            Some(CallableProgXdp::HashKey)
        }
        _ => None,
    } {
        Some(callable_prog_xdp) => {
            let parsing_context = PARSING_CONTEXT
                .get_ptr_mut(0)
                .ok_or(CacheError::MapLookupError)?;

            unsafe {
                (*parsing_context).memcached_packet_header =
                    MemcachedPacketHeader::from_packet_header_without_opaque_and_cas(
                        &*memcached_packet_header,
                    );
                (*parsing_context).memcached_packet_offset = payload_offset;

                MAP_CALLABLE_PROGS_XDP
                    .tail_call(ctx, callable_prog_xdp as u32)
                    .map_err(|_| CacheError::TailCallError)?;
            }
        }
        None => Err(CacheError::BadRequestPacket),
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

#[xdp]
pub fn hash_key(ctx: XdpContext) -> u32 {
    info!(&ctx, "hash_key: received a packet");

    xdp_action::XDP_PASS
}

#[xdp]
pub fn invalidate_cache(ctx: XdpContext) -> u32 {
    info!(&ctx, "invalidate_cache: received a packet");

    xdp_action::XDP_PASS
}

fn try_memcached_ebpf_proxy_cache(ctx: XdpContext) -> Result<u32, u32> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0).ok_or(0u32)?; //

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN).ok_or(0u32)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    let protocol = unsafe { (*ipv4hdr).proto };

    let (source_port, dest_port) = match protocol {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(0u32)?;
            (
                u16::from_be(unsafe { (*tcphdr).source }),
                u16::from_be(unsafe { (*tcphdr).dest }),
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(0u32)?;
            (
                u16::from_be(unsafe { (*udphdr).source }),
                u16::from_be(unsafe { (*udphdr).dest }),
            )
        }
        _ => return Err(0),
    };

    info!(
        &ctx,
        "memcached_ebpf_proxy_cache: SRC IP: {:i}, SRC PORT: {}, DST PORT: {}, PROTO: {}",
        source_addr,
        source_port,
        dest_port,
        protocol as u32
    );

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
