#![no_std]

use core::iter;

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

pub const MAX_LOCK_RETRY_LIMIT: u32 = 3;

pub trait Hasher {
    fn write_byte(&mut self, byte: u8);

    fn finish(&self) -> u32;
}

pub struct Fnv1AHasher {
    state: u32,
}

impl Fnv1AHasher {
    pub fn with_state(state: u32) -> Self {
        Self { state }
    }

    pub fn new() -> Self {
        Self::with_state(FNV_OFFSET_BASIS_32)
    }
}

impl Default for Fnv1AHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Fnv1AHasher {
    fn write_byte(&mut self, byte: u8) {
        self.state ^= u32::from(byte);
        self.state = self.state.wrapping_mul(FNV_PRIME_32);
    }

    fn finish(&self) -> u32 {
        self.state
    }
}

#[repr(C)]
pub struct CacheEntry {
    pub lock: u32,
    pub len: u32,
    pub valid: bool,
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

impl AsRef<str> for CallableProgXdp {
    fn as_ref(&self) -> &str {
        match self {
            CallableProgXdp::HashKeys => "hash_keys",
            CallableProgXdp::PreparePacket => "prepare_packet",
            CallableProgXdp::WriteReply => "write_reply",
            CallableProgXdp::InvalidateCache => "invalidate_cache",
            CallableProgXdp::Max => "SENTINEL_MAX",
        }
    }
}

impl CallableProgXdp {
    pub fn variants() -> impl Iterator<Item = CallableProgXdp> {
        use CallableProgXdp::*;

        iter::empty()
            .chain(iter::once(HashKeys))
            .chain(iter::once(PreparePacket))
            .chain(iter::once(WriteReply))
            .chain(iter::once(InvalidateCache))
    }
}

pub enum CallableProgTc {
    UpdateCache,

    Max,
}

impl AsRef<str> for CallableProgTc {
    fn as_ref(&self) -> &str {
        match self {
            CallableProgTc::UpdateCache => "update_cache",
            CallableProgTc::Max => "SENTINEL_MAX",
        }
    }
}

impl CallableProgTc {
    pub fn variants() -> impl Iterator<Item = CallableProgTc> {
        iter::once(CallableProgTc::UpdateCache)
    }
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
