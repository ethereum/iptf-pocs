//! TEE Swap server — enclave entry point (PID 1).
//!
//! Starts the RA-TLS HTTPS server on 127.0.0.1:8443 and a vsock→TCP proxy on
//! vsock port 5000, so external traffic forwarded by the host proxy reaches axum.
//!
//! Build with:
//!   cargo build --release --target x86_64-unknown-linux-musl --features nitro --bin server

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tee_swap::adapters::memory_store::InMemorySwapStore;
use tee_swap::adapters::mock_chain::MockChainPort;
use tee_swap::coordinator::SwapCoordinator;
use tee_swap::server;

#[cfg(feature = "nitro")]
use tee_swap::adapters::nitro_tee::NitroTeeRuntime;

#[cfg(not(feature = "nitro"))]
use tee_swap::adapters::mock_tee::MockTeeRuntime;

#[cfg(feature = "nitro")]
use tee_swap::server::vsock_proxy::run_vsock_proxy;

#[cfg(feature = "nitro")]
const VSOCK_PORT: u32 = 5000;
const AXUM_ADDR: &str = "127.0.0.1:8443";

#[tokio::main]
async fn main() {
    eprintln!("[server] TEE Swap server starting...");

    // ── TEE runtime ──────────────────────────────────────────────────────────
    #[cfg(feature = "nitro")]
    let tee = NitroTeeRuntime::new();

    #[cfg(not(feature = "nitro"))]
    let tee = {
        use alloy::primitives::Address;
        eprintln!("[server] WARNING: running with mock TEE (no real attestation)");
        MockTeeRuntime::new(Address::repeat_byte(0x42))
    };

    // ── Coordinator with mock chains (no live blockchain for PoC) ────────────
    // Chain IDs chosen to match the demo scenario.
    let chain_id_a = alloy::primitives::B256::left_padding_from(&[1]);
    let chain_id_b = alloy::primitives::B256::left_padding_from(&[2]);

    let mut chains = HashMap::new();
    chains.insert(chain_id_a, MockChainPort::new());
    chains.insert(chain_id_b, MockChainPort::new());

    let coordinator = Arc::new(SwapCoordinator::new(
        InMemorySwapStore::new(),
        chains,
        chain_id_a,
    ));

    // ── Start axum HTTPS server on loopback ──────────────────────────────────
    let addr: SocketAddr = AXUM_ADDR.parse().expect("valid socket address");
    let (_handle, bound_addr) = server::start_server(coordinator, &tee, addr)
        .await
        .expect("failed to start axum server");
    eprintln!("[server] axum HTTPS server listening on {bound_addr}");

    // ── Start vsock → TCP proxy ───────────────────────────────────────────────
    #[cfg(feature = "nitro")]
    {
        let tcp_target = Arc::new(AXUM_ADDR.to_string());
        tokio::spawn(run_vsock_proxy(VSOCK_PORT, tcp_target));
        eprintln!("[server] vsock proxy listening on port {VSOCK_PORT} → {AXUM_ADDR}");
    }

    eprintln!("[server] ready");

    // ── Block until shutdown ─────────────────────────────────────────────────
    tokio::signal::ctrl_c().await.ok();
    eprintln!("[server] shutting down");
}
