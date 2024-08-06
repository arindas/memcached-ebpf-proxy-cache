pub const MEMCACHED_GET_PROTOCOL: &str = "udp";

pub const MEMCACHED_SET_PROTOCOL: &str = "tcp";

pub const MEMCACHED_HOST: &str = "127.0.0.1";

pub const MEMCACHED_PORT: u16 = 11211;

#[test]
fn memcache_get_set_consistency() {
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

    const KEY: &str = "8Cjiq8WNYGO4GPJY36wgBSQ4I19jyGerNLCaCDqTax1GNMw4GI";
    const VAL: &str = "5kfd1EvCWvXtlKWNr9RFTtdKNVmcauRL6Mr0rnjMTKV1qp4f3U";

    set_client.set(KEY, VAL, 10).unwrap();

    assert_eq!(get_client.get::<String>(KEY).unwrap().unwrap(), VAL);
}
