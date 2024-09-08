#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(core_intrinsics)]

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_OK},
    helpers::bpf_xdp_adjust_head,
    macros::{classifier, map, xdp},
    maps::{Array, PerCpuArray, ProgramArray},
    programs::{TcContext, XdpContext},
};
use aya_log_ebpf::{debug, error, info};
use core::{intrinsics::atomic_xchg_seqcst, mem, slice};

use memcached_ebpf_proxy_cache_common::{
    CacheEntry, CacheUsageStatistics, CallableProgTc, CallableProgXdp, Fnv1AHasher, Hasher,
    CACHE_ENTRY_COUNT, MAX_KEY_LENGTH, MAX_SPIN_LOCK_ITER_RETRY_LIMIT, MEMCACHED_PORT,
};
use memcached_ebpf_proxy_cache_common::{
    MEMCACHED_SET_PACKET_HEADER_EXTRAS_LENGTH, MEMCACHED_TCP_ADDITIONAL_PADDING,
};
use memcached_network_types::{
    binary::{Opcode, PacketHeader as MemcachedPacketHeader, ReqMagicByte, ResMagicByte},
    integer_enum_variant_constants,
    udp::MemcachedUdpHeader,
};
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
    BadResponsePacket,
    TailCallError,
    UnsupportedProtocol,
    UnexpectedKeyLen,
    UnexpectedValLen,
    LockRetryLimitHit,
    KeyNotFound,
}

impl AsRef<str> for CacheError {
    fn as_ref(&self) -> &str {
        match self {
            CacheError::PacketOffsetOutofBounds => "CacheError::PacketOffsetOutofBounds",
            CacheError::HeaderParseError => "CacheError::HeaderParseError",
            CacheError::PtrSliceCoercionError => "CacheError::PtrSliceCoercionError",
            CacheError::MapLookupError => "CacheError::MapLookupError",
            CacheError::BadRequestPacket => "CacheError::BadRequestPacket",
            CacheError::BadResponsePacket => "CacheError::BadResponsePacket",
            CacheError::TailCallError => "CacheError::TailCallError",
            CacheError::UnsupportedProtocol => "CacheError::UnsupportedProtocol",
            CacheError::UnexpectedKeyLen => "CacheError::UnexpectedKeyLen",
            CacheError::UnexpectedValLen => "CacheError::UnexpectedValLen",
            CacheError::LockRetryLimitHit => "CacheError::LockRetryLimitHit",
            CacheError::KeyNotFound => "CacheError::KeyNotFound",
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

pub trait PacketCtx {
    #[inline(always)]
    fn ptr_at<T>(&self, offset: usize) -> Option<*const T> {
        let start = self.data();
        let end = self.data_end();
        let item_len = mem::size_of::<T>();

        if start + offset + item_len > end {
            return None;
        }

        Some((start + offset) as *const T)
    }

    #[inline(always)]
    fn ptr_at_mut<T>(&self, offset: usize) -> Option<*mut T> {
        Some(self.ptr_at::<T>(offset)? as *mut T)
    }

    fn data_end(&self) -> usize;

    fn data(&self) -> usize;
}

impl PacketCtx for XdpContext {
    #[inline(always)]
    fn data_end(&self) -> usize {
        self.data_end()
    }

    #[inline(always)]
    fn data(&self) -> usize {
        self.data()
    }
}

impl PacketCtx for TcContext {
    #[inline(always)]
    fn data_end(&self) -> usize {
        self.data_end()
    }

    #[inline(always)]
    fn data(&self) -> usize {
        self.data()
    }
}

#[inline(always)]
fn try_spin_lock_acquire(lock: &mut u64, retry_limit: u32) -> Result<(), u32> {
    let mut retries = 0;

    while retries < retry_limit && unsafe { atomic_xchg_seqcst(lock as *mut u64, 1) } != 0 {
        retries += 1;
    }

    if retries < retry_limit {
        Ok(())
    } else {
        Err(retries)
    }
}

#[inline(always)]
fn spin_lock_release(lock: &mut u64) {
    unsafe { atomic_xchg_seqcst(lock as *mut u64, 0) };
}

#[inline(always)]
fn try_rx_filter(ctx: &XdpContext) -> Result<u32, CacheError> {
    let ethhdr: *const EthHdr = ctx.ptr_at(0).ok_or(CacheError::HeaderParseError)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Err(CacheError::HeaderParseError),
    }

    let ipv4hdr: *const Ipv4Hdr = ctx
        .ptr_at(EthHdr::LEN)
        .ok_or(CacheError::HeaderParseError)?;

    let protocol = unsafe { (*ipv4hdr).proto };

    debug!(
        ctx,
        "try_rx_filter: recv Ipv4 packet with protocol: {}", protocol as u32
    );

    let (dest_port, payload_offset) = match protocol {
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ctx
                .ptr_at(EthHdr::LEN + Ipv4Hdr::LEN)
                .ok_or(CacheError::HeaderParseError)?;
            (
                u16::from_be(unsafe { (*udphdr).dest }),
                EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + mem::size_of::<MemcachedUdpHeader>(),
            )
        }
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ctx
                .ptr_at(EthHdr::LEN + Ipv4Hdr::LEN)
                .ok_or(CacheError::HeaderParseError)?;
            (
                u16::from_be(unsafe { (*tcphdr).dest }),
                EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN + MEMCACHED_TCP_ADDITIONAL_PADDING,
            )
        }
        _ => return Err(CacheError::UnsupportedProtocol),
    };

    debug!(
        ctx,
        "try_rx_filter: dest_port={}, payload_offset={} protocol={}",
        dest_port,
        payload_offset,
        protocol as u32
    );

    let memcached_packet_header = unsafe {
        &mut *ctx
            .ptr_at_mut(payload_offset)
            .ok_or(CacheError::HeaderParseError)?
    } as &mut MemcachedPacketHeader;

    let magic_byte = memcached_packet_header.magic_byte;
    let opcode = memcached_packet_header.opcode;
    let key_length = memcached_packet_header.key_length.get();

    debug!(
        ctx,
        "try_rx_filter: dest_port={}, memcached_packet_header: magic_byte={}, opcode={}, key_length={}",
        dest_port,
        magic_byte,
        opcode,
        key_length
    );

    if key_length == 0 || key_length > MAX_KEY_LENGTH as u16 {
        return Err(CacheError::UnexpectedKeyLen);
    }

    const REQ_MAGIC_BYTE: u8 = ReqMagicByte::ReqPacket as u8;

    integer_enum_variant_constants!(
        Opcode,
        u8,
        (GET, Get),
        (GETK, GetK),
        (GETQ, GetQ),
        (GETKQ, GetKQ),
        (SET, Set),
        (SETQ, SetQ)
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
        (MEMCACHED_PORT, _, SET | SETQ) => Some(CallableProgXdp::InvalidateCache),
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

                if bpf_xdp_adjust_head(ctx.ctx, payload_offset as i32) != 0 {
                    return Err(CacheError::PacketOffsetOutofBounds);
                }

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

#[inline]
fn try_compute_key_hash<PCtx>(
    ctx: &PCtx,
    key_offset: usize,
    key_length: u16,
) -> Result<u32, CacheError>
where
    PCtx: PacketCtx,
{
    let mut hasher = Fnv1AHasher::new();

    let mut key_byte_idx: u16 = 0;
    let mut key_byte_offset = key_offset + key_byte_idx as usize;

    while key_byte_idx < MAX_KEY_LENGTH as u16
        && key_byte_idx < key_length
        && key_byte_offset < ctx.data_end()
    {
        let key_byte = ctx
            .ptr_at::<u8>(key_byte_offset)
            .ok_or(CacheError::BadRequestPacket)?;
        hasher.write_byte(unsafe { *key_byte });

        key_byte_idx += 1;
        key_byte_offset += mem::size_of::<u8>();
    }

    let key_hash = hasher.finish();

    Ok(key_hash)
}

#[inline(always)]
fn try_hash_key(ctx: &XdpContext) -> Result<u32, CacheError> {
    info!(ctx, "try_hash_key: received a packet");

    let _payload_ptr: *const u8 = ctx.ptr_at(0).ok_or(CacheError::BadRequestPacket)?;

    let parsing_context = PARSING_CONTEXT
        .get_ptr_mut(0)
        .ok_or(CacheError::MapLookupError)?;

    let parsing_context = unsafe { &*parsing_context };

    let key_offset = size_of::<MemcachedPacketHeader>();

    let key_length = parsing_context.memcached_packet_header.key_length.get();

    let key_first_byte = ctx
        .ptr_at::<u8>(key_offset)
        .ok_or(CacheError::BadRequestPacket)?;

    debug!(ctx, "try_hash_key: key first byte = {}", unsafe {
        *key_first_byte
    });

    let key_hash = try_compute_key_hash(ctx, key_offset, key_length)?;

    let cache_idx = key_hash % CACHE_ENTRY_COUNT;

    let cache_entry = MAP_KCACHE
        .get_ptr_mut(cache_idx)
        .ok_or(CacheError::MapLookupError)?;

    let cache_entry = unsafe { &mut *cache_entry };

    try_spin_lock_acquire(&mut cache_entry.lock, MAX_SPIN_LOCK_ITER_RETRY_LIMIT)
        .map_err(|_| CacheError::LockRetryLimitHit)?;

    let mut key_found = false;

    if cache_entry.valid && cache_entry.hash == key_hash {
        spin_lock_release(&mut cache_entry.lock);
        key_found = true;
    } else {
        spin_lock_release(&mut cache_entry.lock);

        let cache_usage_stats = CACHE_USAGE_STATS
            .get_ptr_mut(0)
            .ok_or(CacheError::MapLookupError)?;

        unsafe { (*cache_usage_stats).miss_count += 1 };
    }

    unsafe {
        let adjust_head_reset_delta = 0 - parsing_context.memcached_packet_offset as i32;

        if bpf_xdp_adjust_head(ctx.ctx, adjust_head_reset_delta) != 0 {
            return Err(CacheError::PacketOffsetOutofBounds);
        }

        if !key_found {
            return Err(CacheError::KeyNotFound);
        }

        MAP_CALLABLE_PROGS_XDP
            .tail_call(ctx, CallableProgXdp::PreparePacket as u32)
            .map_err(|_| CacheError::TailCallError)?;
    }
}

#[xdp]
pub fn hash_key(ctx: XdpContext) -> u32 {
    info!(&ctx, "hash_key: received a packet");

    match try_hash_key(&ctx) {
        Ok(ret) => {
            info!(&ctx, "hash_key: done processing packet, action: {}", ret);
            ret
        }
        Err(err) => {
            error!(&ctx, "hash_key: Err({})", err.as_ref());
            xdp_action::XDP_PASS
        }
    }
}

fn try_invalidate_cache(ctx: &XdpContext) -> Result<u32, CacheError> {
    info!(ctx, "try_invalidate_cache: received a packet");

    let _payload_ptr: *const u8 = ctx.ptr_at(0).ok_or(CacheError::BadRequestPacket)?;

    let cache_usage_stats = CACHE_USAGE_STATS
        .get_ptr_mut(0)
        .ok_or(CacheError::MapLookupError)?;

    unsafe { (*cache_usage_stats).set_recv_count += 1 };

    let parsing_context = PARSING_CONTEXT
        .get_ptr_mut(0)
        .ok_or(CacheError::MapLookupError)?;

    let parsing_context = unsafe { &*parsing_context };

    // TODO: use memcached_packet_header.extras_length for calculating key_offset
    // let extras_length = parsing_context.memcached_packet_header.extras_length;
    // let key_offset = size_of::<MemcachedPacketHeader>() + extras_length as usize
    let key_offset =
        size_of::<MemcachedPacketHeader>() + MEMCACHED_SET_PACKET_HEADER_EXTRAS_LENGTH as usize;

    let key_length = parsing_context.memcached_packet_header.key_length.get();

    let key_first_byte = ctx
        .ptr_at::<u8>(key_offset)
        .ok_or(CacheError::BadRequestPacket)?;

    debug!(ctx, "try_invalidate_cache: key first byte = {}", unsafe {
        *key_first_byte
    });

    let key_hash = try_compute_key_hash(ctx, key_offset, key_length)?;

    let cache_idx = key_hash % CACHE_ENTRY_COUNT;

    debug!(ctx, "try_invalidate_cache: cache_idx = {}", cache_idx);

    let cache_entry = MAP_KCACHE
        .get_ptr_mut(cache_idx)
        .ok_or(CacheError::MapLookupError)?;

    let cache_entry = unsafe { &mut *cache_entry };

    try_spin_lock_acquire(&mut cache_entry.lock, MAX_SPIN_LOCK_ITER_RETRY_LIMIT)
        .map_err(|_| CacheError::LockRetryLimitHit)?;

    if cache_entry.valid {
        cache_entry.valid = false;
        unsafe { (*cache_usage_stats).invalidation_count += 1 };
    }

    spin_lock_release(&mut cache_entry.lock);

    let _value_offset = key_offset + key_length as usize;

    let adjust_head_reset_delta = 0 - parsing_context.memcached_packet_offset as i32;

    if unsafe { bpf_xdp_adjust_head(ctx.ctx, adjust_head_reset_delta) } != 0 {
        return Err(CacheError::PacketOffsetOutofBounds);
    }

    Ok(xdp_action::XDP_PASS)
}

#[xdp]
pub fn invalidate_cache(ctx: XdpContext) -> u32 {
    info!(&ctx, "invalidate_cache: received a packet");

    match try_invalidate_cache(&ctx) {
        Ok(ret) => {
            info!(
                &ctx,
                "invalidate_cache: done processing packet, action: {}", ret
            );
            ret
        }
        Err(err) => {
            error!(&ctx, "invalidate_cache: Err({})", err.as_ref());
            xdp_action::XDP_PASS
        }
    }
}

pub fn try_tx_filter(ctx: &TcContext) -> Result<i32, CacheError> {
    let ethhdr = ctx
        .ptr_at::<EthHdr>(0)
        .ok_or(CacheError::HeaderParseError)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Err(CacheError::HeaderParseError),
    }

    let ipv4hdr = ctx
        .ptr_at::<Ipv4Hdr>(EthHdr::LEN)
        .ok_or(CacheError::HeaderParseError)?;

    if unsafe { (*ipv4hdr).proto } != IpProto::Udp {
        return Err(CacheError::UnsupportedProtocol);
    }

    let udphdr = ctx
        .ptr_at::<UdpHdr>(EthHdr::LEN + Ipv4Hdr::LEN)
        .ok_or(CacheError::HeaderParseError)?;

    let source_port = u16::from_be(unsafe { (*udphdr).source });

    if source_port != 11211 {
        return Err(CacheError::BadResponsePacket);
    }

    let payload_offset =
        EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + mem::size_of::<MemcachedUdpHeader>();

    let memcached_packet_header = unsafe {
        &*ctx
            .ptr_at(payload_offset)
            .ok_or(CacheError::HeaderParseError)?
    } as &MemcachedPacketHeader;

    let magic_byte = memcached_packet_header.magic_byte;
    let opcode = memcached_packet_header.opcode;
    let key_length = memcached_packet_header.key_length.get();

    debug!(
        ctx,
        "try_tx_filter: source_port={}, memcached_packet_header: magic_byte={}, opcode={}, key_length={}",
        source_port,
        magic_byte,
        opcode,
        key_length
    );

    if key_length == 0 || key_length > MAX_KEY_LENGTH as u16 {
        return Err(CacheError::UnexpectedKeyLen);
    }

    const RES_MAGIC_BYTE: u8 = ResMagicByte::ResPacket as u8;

    integer_enum_variant_constants!(
        Opcode,
        u8,
        (GET, Get),
        (GETK, GetK),
        (GETQ, GetQ),
        (GETKQ, GetKQ)
    );

    let callable_prog_tc = match (magic_byte, opcode) {
        (RES_MAGIC_BYTE, GET | GETQ | GETK | GETKQ) => Some(CallableProgTc::UpdateCache),
        _ => None,
    };

    if let Some(callable_prog_tc) = callable_prog_tc {
        debug!(
            ctx,
            "try_tx_filter: valid packet, attempt tail call to {}",
            callable_prog_tc.as_ref()
        );

        let cache_usage_stats = CACHE_USAGE_STATS
            .get_ptr_mut(0)
            .ok_or(CacheError::MapLookupError)?;

        unsafe { (*cache_usage_stats).get_recv_count += 1 };

        unsafe { MAP_CALLABLE_PROGS_TC.tail_call(ctx, callable_prog_tc as u32) }
            .map_err(|_| CacheError::TailCallError)?;
    } else {
        Err(CacheError::BadResponsePacket)
    }
}

#[classifier]
pub fn tx_filter(ctx: TcContext) -> i32 {
    info!(&ctx, "tx_filter: received a packet");

    match try_tx_filter(&ctx) {
        Ok(ret) => {
            info!(
                &ctx,
                "try_tx_filter: done processing packet, action: {}", ret
            );
            ret
        }
        Err(err) => {
            error!(&ctx, "try_tx_filter: Err({})", err.as_ref());
            TC_ACT_OK
        }
    }
}

pub fn try_update_cache(ctx: &TcContext) -> Result<i32, CacheError> {
    let payload_offset =
        EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + mem::size_of::<MemcachedUdpHeader>();

    let memcached_packet_header = unsafe {
        &*ctx
            .ptr_at(payload_offset)
            .ok_or(CacheError::HeaderParseError)?
    } as &MemcachedPacketHeader;

    let magic_byte = memcached_packet_header.magic_byte;
    let opcode = memcached_packet_header.opcode;
    let key_length = memcached_packet_header.key_length.get();

    debug!(
        ctx,
        "try_update_cache: memcached_packet_header: magic_byte={}, opcode={}, key_length={}",
        magic_byte,
        opcode,
        key_length
    );

    let key_offset = payload_offset + mem::size_of::<MemcachedPacketHeader>();

    let key_hash = try_compute_key_hash(ctx, key_offset, key_length)?;

    debug!(ctx, "try_update_cache: key_hash = {}", key_hash);

    Ok(TC_ACT_OK)
}

#[classifier]
pub fn update_cache(ctx: TcContext) -> i32 {
    info!(&ctx, "update_cache: received a packet");

    match try_update_cache(&ctx) {
        Ok(ret) => {
            info!(
                &ctx,
                "try_update_cache: done processing packet, action: {}", ret
            );
            ret
        }
        Err(err) => {
            error!(&ctx, "try_update_cache: Err({})", err.as_ref());
            TC_ACT_OK
        }
    }
}

pub enum ProxyError {
    UnsupportedProtocol,
    HeaderParseError,
}

impl AsRef<str> for ProxyError {
    fn as_ref(&self) -> &str {
        match self {
            ProxyError::UnsupportedProtocol => "ProxyError::UnsupportedProtocol",
            ProxyError::HeaderParseError => "ProxyError::HeaderParseError",
        }
    }
}

fn try_memcached_ebpf_proxy_cache(ctx: &XdpContext) -> Result<u32, ProxyError> {
    let ethhdr: *const EthHdr = ctx.ptr_at(0).ok_or(ProxyError::HeaderParseError)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ctx
        .ptr_at(EthHdr::LEN)
        .ok_or(ProxyError::HeaderParseError)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    let protocol = unsafe { (*ipv4hdr).proto };

    let (source_port, dest_port) = match protocol {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ctx
                .ptr_at(EthHdr::LEN + Ipv4Hdr::LEN)
                .ok_or(ProxyError::HeaderParseError)?;
            (
                u16::from_be(unsafe { (*tcphdr).source }),
                u16::from_be(unsafe { (*tcphdr).dest }),
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ctx
                .ptr_at(EthHdr::LEN + Ipv4Hdr::LEN)
                .ok_or(ProxyError::HeaderParseError)?;
            (
                u16::from_be(unsafe { (*udphdr).source }),
                u16::from_be(unsafe { (*udphdr).dest }),
            )
        }
        _ => return Err(ProxyError::UnsupportedProtocol),
    };

    info!(
        ctx,
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
    info!(&ctx, "memcached_ebpf_proxy_cache: received a packet");

    match try_memcached_ebpf_proxy_cache(&ctx) {
        Ok(ret) => {
            info!(
                &ctx,
                "memcached_ebpf_proxy_cache: done processing packet, action: {}", ret
            );
            ret
        }
        Err(err) => {
            error!(&ctx, "memcached_ebpf_proxy_cache: Err({})", err.as_ref());
            xdp_action::XDP_ABORTED
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
