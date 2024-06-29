#![no_std]

use aya_ebpf::bindings::bpf_spin_lock;

pub const MAX_KEY_LENGTH: usize = 250;
pub const MAX_VAL_LENGTH: usize = 1000;
pub const MAX_ADDITIONAL_PAYLOAD_BYTES: usize = 53;
pub const MAX_CACHE_DATA_SIZE: usize =
    MAX_KEY_LENGTH + MAX_VAL_LENGTH + MAX_ADDITIONAL_PAYLOAD_BYTES;

pub const MAX_KEY_IN_MULTIGET: u32 = 30;
pub const CACHE_ENTRY_COUNT: u32 = 3250000;

pub const MAX_PACKET_LENGTH: usize = 1500;
pub const MAX_KEYS_IN_PACKET: u32 = MAX_KEY_IN_MULTIGET;

pub const FNV_OFFSET_BASIS_32: u32 = 2166136261;
pub const FNV_PRIME_32: u32 = 16777619;

pub const MEMCACHED_PORT: u16 = 11211;

#[repr(C)]
pub struct CacheEntry {
    pub lock: bpf_spin_lock,
    pub len: u32,
    pub valid: u8,
    pub hash: u32,
    pub data: [u8; MAX_CACHE_DATA_SIZE],
}

pub enum CallableProgXdp {
    HashKeys,
    PreparePacket,
    WriteReply,
    InvalidateCache,

    Max,
}

pub enum CallableProgTc {
    UpdateCache,

    Max,
}

pub struct CacheUsageStatistics {
    pub get_recv_count: u32,
    pub set_recv_count: u32,

    pub hit_misprediction: u32,
    pub hit_count: u32,

    pub miss_count: u32,
    pub update_count: u32,
    pub invalidation_count: u32,
}
