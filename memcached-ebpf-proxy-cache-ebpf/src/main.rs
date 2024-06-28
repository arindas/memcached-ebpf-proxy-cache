#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, PerCpuArray, ProgramArray},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use memcached_ebpf_proxy_cache_common::{
    CacheEntry, CacheUsageStatistics, ProgTc, ProgXdp, CACHE_ENTRY_COUNT, MAX_KEYS_IN_PACKET,
    MAX_KEY_LENGTH,
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

fn compute_ip_checksum() {}

#[xdp]
pub fn memcached_ebpf_proxy_cache(ctx: XdpContext) -> u32 {
    match try_memcached_ebpf_proxy_cache(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_memcached_ebpf_proxy_cache(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
