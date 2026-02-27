//! TEE Swap server — enclave entry point (PID 1).
//!
//! Reads `/etc/tee_swap/config.toml` (baked into the EIF at build time) — the same
//! config.toml used by the testnet binary. The server only consumes the [sepolia],
//! [layer2], and [tee] sections; all other sections (alice, bob, swap, coordinator)
//! are ignored.
//!
//! The server creates real Ethereum RPC adapters for each chain, starts the RA-TLS
//! HTTPS coordinator on loopback, and bridges it to external traffic via vsock.
//!
//! Build with:
//!   cargo build --release --target x86_64-unknown-linux-musl --features nitro --bin server

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use alloy::primitives::{Address, B256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use serde::Deserialize;
use tracing::{error, info, warn};

use tee_swap::adapters::ethereum::EthereumRpc;
use tee_swap::adapters::memory_store::InMemorySwapStore;
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
const CONFIG_PATH: &str = "/etc/tee_swap/config.toml";

// ── Config (subset of the shared config.toml format) ─────────────────────────

/// Chain section — mirrors [sepolia] / [layer2] in config.toml.
/// Extra fields present in the testnet config (deployer_private_key, deployment_block,
/// alice/bob/swap sections) are silently ignored by serde.
#[derive(Debug, Deserialize)]
struct ChainSection {
    rpc_url: String,
    /// Required for the server — contracts must already be deployed.
    private_utxo_address: Option<Address>,
    tee_lock_address: Option<Address>,
}

/// [tee] section — same as in the testnet config.
#[derive(Debug, Deserialize)]
struct TeeSection {
    private_key: String,
}

/// Minimal view of config.toml that the server binary needs.
#[derive(Debug, Deserialize)]
struct ServerConfig {
    sepolia: ChainSection,
    layer2: ChainSection,
    tee: TeeSection,
    /// Minimum seconds remaining before timeout for a swap to be accepted.
    /// Not present in testnet config.toml — defaults to 60 if absent.
    #[serde(default = "default_min_timeout")]
    min_timeout_secs: u64,
}

fn default_min_timeout() -> u64 {
    60
}

impl ServerConfig {
    fn load() -> Result<Self, String> {
        let content = std::fs::read_to_string(CONFIG_PATH)
            .map_err(|e| format!("cannot read {CONFIG_PATH}: {e}"))?;
        let config: Self =
            toml::from_str(&content).map_err(|e| format!("cannot parse {CONFIG_PATH}: {e}"))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        for (name, chain) in [("sepolia", &self.sepolia), ("layer2", &self.layer2)] {
            if chain.private_utxo_address.is_none() {
                return Err(format!(
                    "[{name}] missing private_utxo_address — contracts must be pre-deployed"
                ));
            }
            if chain.tee_lock_address.is_none() {
                return Err(format!(
                    "[{name}] missing tee_lock_address — contracts must be pre-deployed"
                ));
            }
        }
        Ok(())
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("TEE Swap server starting...");

    // ── Load config ───────────────────────────────────────────────────────────
    let config = ServerConfig::load().unwrap_or_else(|e| {
        error!("cannot load config: {e}");
        std::process::exit(1);
    });

    // ── Parse TEE signer ──────────────────────────────────────────────────────
    let tee_signer: PrivateKeySigner =
        config.tee.private_key.parse().unwrap_or_else(|e| {
            error!("invalid tee.private_key: {e}");
            std::process::exit(1);
        });
    let tee_address = tee_signer.address();
    info!(%tee_address, "TEE signer loaded");

    // ── TEE runtime ───────────────────────────────────────────────────────────
    #[cfg(feature = "nitro")]
    let tee = NitroTeeRuntime::new(tee_address);

    #[cfg(not(feature = "nitro"))]
    let tee = {
        warn!("running with mock TEE (no real attestation)");
        MockTeeRuntime::new(tee_address)
    };

    // ── Build chain adapters ──────────────────────────────────────────────────
    // Sepolia is the announcement chain (TeeLock lives there).
    // Layer 2 is the second chain (no announceSwap calls).
    let mut chains: HashMap<B256, EthereumRpc> = HashMap::new();

    let (sep_chain_id, layer2_chain_id) = build_chains(
        &config,
        &mut chains,
    )
    .await;

    info!(%sep_chain_id, %layer2_chain_id, "chain adapters ready");

    // ── Coordinator ───────────────────────────────────────────────────────────
    // Sepolia is the announcement chain — the coordinator posts announceSwap() there.
    let coordinator = Arc::new(
        SwapCoordinator::new(InMemorySwapStore::new(), chains, sep_chain_id)
            .with_min_timeout(config.min_timeout_secs),
    );

    // ── Start axum HTTPS server on loopback ───────────────────────────────────
    let addr: SocketAddr = AXUM_ADDR.parse().expect("valid socket address");
    let (_handle, bound_addr) = server::start_server(coordinator, &tee, addr)
        .await
        .unwrap_or_else(|e| {
            error!("cannot start server: {e}");
            std::process::exit(1);
        });
    info!(%bound_addr, "HTTPS server listening");

    // ── Start vsock → TCP proxy ───────────────────────────────────────────────
    #[cfg(feature = "nitro")]
    {
        let tcp_target = Arc::new(AXUM_ADDR.to_string());
        tokio::spawn(run_vsock_proxy(VSOCK_PORT, tcp_target));
        info!(vsock_port = VSOCK_PORT, target = AXUM_ADDR, "vsock proxy started");
    }

    info!("ready");

    tokio::signal::ctrl_c().await.ok();
    info!("shutting down");
}

/// Create `EthereumRpc` adapters for Sepolia and Layer 2, insert into `chains`,
/// and return their chain IDs as B256 values.
async fn build_chains(
    config: &ServerConfig,
    chains: &mut HashMap<B256, EthereumRpc>,
) -> (B256, B256) {
    let sep = &config.sepolia;
    let l2 = &config.layer2;

    let sep_id = query_chain_id(&sep.rpc_url, "sepolia").await;
    let layer2_id = query_chain_id(&l2.rpc_url, "layer2").await;

    let sep_id_b256 = B256::left_padding_from(&sep_id.to_be_bytes());
    let layer2_id_b256 = B256::left_padding_from(&layer2_id.to_be_bytes());

    let sep_rpc = EthereumRpc::new(
        &sep.rpc_url,
        &config.tee.private_key,
        sep.private_utxo_address.unwrap(),
        sep.tee_lock_address.unwrap(),
    )
    .await
    .unwrap_or_else(|e| {
        error!(chain = "sepolia", "cannot create RPC adapter: {e}");
        std::process::exit(1);
    });

    let layer2_rpc = EthereumRpc::new(
        &l2.rpc_url,
        &config.tee.private_key,
        l2.private_utxo_address.unwrap(),
        l2.tee_lock_address.unwrap(),
    )
    .await
    .unwrap_or_else(|e| {
        error!(chain = "layer2", "cannot create RPC adapter: {e}");
        std::process::exit(1);
    });

    info!(
        chain = "sepolia",
        private_utxo = %sep.private_utxo_address.unwrap(),
        tee_lock = %sep.tee_lock_address.unwrap(),
        "contracts loaded",
    );
    info!(
        chain = "layer2",
        private_utxo = %l2.private_utxo_address.unwrap(),
        tee_lock = %l2.tee_lock_address.unwrap(),
        "contracts loaded",
    );

    chains.insert(sep_id_b256, sep_rpc);
    chains.insert(layer2_id_b256, layer2_rpc);

    (sep_id_b256, layer2_id_b256)
}

async fn query_chain_id(rpc_url: &str, label: &str) -> u64 {
    let provider = DynProvider::new(
        ProviderBuilder::new()
            .connect_http(rpc_url.parse().unwrap_or_else(|e| {
                error!(chain = label, "invalid rpc_url: {e}");
                std::process::exit(1);
            })),
    );
    provider.get_chain_id().await.unwrap_or_else(|e| {
        error!(chain = label, "cannot query chain_id: {e}");
        std::process::exit(1);
    })
}
