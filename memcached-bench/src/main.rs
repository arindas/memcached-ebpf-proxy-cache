use std::time::Instant;
use zzz::ProgressBarIterExt as _;

use itertools::Itertools;

pub const MEMCACHED_GET_PROTOCOL: &str = "udp";

pub const MEMCACHED_SET_PROTOCOL: &str = "tcp";

pub const MEMCACHED_HOST: &str = "127.0.0.1";

pub const MEMCACHED_PORT: u16 = 11211;

const SOURCE: &[u8] = b"memcached-ebpf";

fn main() {
    let memcached_get_endpoint = format!(
        "memcache+{}://{}:{}",
        MEMCACHED_GET_PROTOCOL, MEMCACHED_HOST, MEMCACHED_PORT
    );

    let memcached_set_endpoint = format!(
        "memcache+{}://{}:{}?tcp_nodelay=false",
        MEMCACHED_SET_PROTOCOL, MEMCACHED_HOST, MEMCACHED_PORT
    );

    let get_client = memcache::connect(memcached_get_endpoint).unwrap();

    let set_client = memcache::connect(memcached_set_endpoint).unwrap();

    let keys = SOURCE.iter().cloned().combinations(12);

    let start = Instant::now();

    for key in keys.progress() {
        let key = String::from_utf8(key).unwrap();

        set_client.set(&key, &key, 3600).unwrap();
    }

    let end = Instant::now();

    println!("Time spent in SET loop: {:?}", end.duration_since(start));

    let keys = SOURCE.iter().cloned().combinations(12);
    let start = Instant::now();

    for key in keys.cycle().take(10000).progress() {
        let key = String::from_utf8(key).unwrap();

        get_client.get::<String>(&key).unwrap().unwrap();
    }

    let end = Instant::now();

    println!("Time spent in GET loop: {:?}", end.duration_since(start));
}
