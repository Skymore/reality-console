use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, MutexGuard};

const FIRST_TEST_PORT: u16 = 20_000;
const LAST_TEST_PORT: u16 = 45_000;
static NEXT_TEST_PORT: AtomicU16 = AtomicU16::new(FIRST_TEST_PORT);
static NETWORK_TEST_LOCK: Mutex<()> = Mutex::const_new(());

pub(crate) async fn lock_network_tests() -> MutexGuard<'static, ()> {
    NETWORK_TEST_LOCK.lock().await
}

pub(crate) async fn bind_unique_loopback() -> TcpListener {
    bind_unique(Ipv4Addr::LOCALHOST).await
}

pub(crate) async fn bind_unique_wildcard() -> TcpListener {
    bind_unique(Ipv4Addr::UNSPECIFIED).await
}

pub(crate) async fn unique_unused_port() -> u16 {
    bind_unique_wildcard().await.local_addr().unwrap().port()
}

async fn bind_unique(address: Ipv4Addr) -> TcpListener {
    loop {
        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        assert!(
            port <= LAST_TEST_PORT,
            "test process exhausted its reserved TCP port range"
        );
        if let Ok(listener) = TcpListener::bind((address, port)).await {
            return listener;
        }
    }
}
