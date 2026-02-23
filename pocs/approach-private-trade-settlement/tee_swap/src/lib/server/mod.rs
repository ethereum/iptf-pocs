pub mod cert;
pub mod routes;
pub mod verifier;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::adapters::memory_store::InMemorySwapStore;
use crate::adapters::mock_chain::MockChainPort;
use crate::adapters::mock_tee::MockTeeRuntime;
use crate::coordinator::SwapCoordinator;

use self::cert::generate_ra_tls_cert;
use self::routes::{announcement_handler, status_handler, submit_handler, AppState};

/// Start the RA-TLS HTTPS server.
///
/// 1. Generates a self-signed RA-TLS certificate (P-256 key + mock attestation)
/// 2. Configures rustls with the certificate
/// 3. Binds an HTTPS server with axum routes
///
/// Returns the `axum_server::Handle` for graceful shutdown and the bound address.
pub async fn start_server(
    coordinator: Arc<SwapCoordinator<MockChainPort, InMemorySwapStore>>,
    tee: &MockTeeRuntime,
    addr: SocketAddr,
) -> Result<(axum_server::Handle, SocketAddr), ServerError> {
    // 1. Generate RA-TLS certificate
    let ra_cert = generate_ra_tls_cert(tee)
        .await
        .map_err(|e| ServerError::Cert(e.to_string()))?;

    // 2. Build rustls ServerConfig
    let server_config = build_server_config(&ra_cert.cert_der, &ra_cert.key_der)?;

    // 3. Build axum Router
    let state = AppState { coordinator };
    let app = Router::new()
        .route("/submit", post(submit_handler))
        .route("/status/{swap_id}", get(status_handler))
        .route("/announcement/{swap_id}", get(announcement_handler))
        .with_state(state);

    // 4. Serve with axum-server + rustls
    let rustls_config =
        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config));

    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();

    tokio::spawn(async move {
        axum_server::bind_rustls(addr, rustls_config)
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
            .ok();
    });

    // Wait for the server to start listening and retrieve the bound address
    let bound_addr = loop {
        if let Some(addr) = handle.listening().await {
            break addr;
        }
    };

    Ok((handle, bound_addr))
}

fn build_server_config(
    cert_der: &[u8],
    key_der: &[u8],
) -> Result<rustls::ServerConfig, ServerError> {
    let certs = vec![CertificateDer::from(cert_der.to_vec())];
    let key = PrivateKeyDer::try_from(key_der.to_vec())
        .map_err(|e| ServerError::Tls(format!("invalid private key: {e}")))?;

    rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| ServerError::Tls(e.to_string()))?
    .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ServerError::Tls(e.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("certificate error: {0}")]
    Cert(String),

    #[error("TLS configuration error: {0}")]
    Tls(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::merkle_tree::LocalMerkleTree;
    use crate::domain::note::Note;
    use crate::domain::stealth::MetaKeyPair;
    use crate::domain::swap::{SwapAnnouncement, SwapTerms};
    use crate::party::prepare_lock;
    use crate::ports::SwapLockData;
    use crate::server::routes::SwapStatus;
    use crate::server::verifier::build_ra_tls_client;
    use alloy_primitives::{Address, B256};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_full_ra_tls_flow() {
        // ── Setup fixture ──
        let mut rng = ark_std::test_rng();
        let meta_a = MetaKeyPair::generate(&mut rng);
        let meta_b = MetaKeyPair::generate(&mut rng);

        let terms = SwapTerms::new(
            B256::left_padding_from(&[1]),
            B256::left_padding_from(&[2]),
            1000,
            50,
            B256::repeat_byte(0x01),
            B256::repeat_byte(0x02),
            B256::left_padding_from(&[0x00, 0x01, 0x51, 0x80]),
            meta_a.pk_x(),
            meta_b.pk_x(),
            B256::repeat_byte(0xFF),
        );

        let mut tree_a = LocalMerkleTree::new();
        let note_a = Note::new(
            terms.chain_id_a,
            terms.value_a,
            terms.asset_id_a,
            meta_a.pk_x(),
            B256::ZERO,
            B256::ZERO,
        );
        tree_a.insert_commitment(&note_a.commitment());
        let proof_a = tree_a.generate_proof(0).unwrap();
        let root_a = tree_a.current_root().unwrap();
        let lock_a =
            prepare_lock(&terms, &meta_a, &meta_b.pk.into(), &note_a, &proof_a, root_a);

        let mut tree_b = LocalMerkleTree::new();
        let note_b = Note::new(
            terms.chain_id_b,
            terms.value_b,
            terms.asset_id_b,
            meta_b.pk_x(),
            B256::ZERO,
            B256::ZERO,
        );
        tree_b.insert_commitment(&note_b.commitment());
        let proof_b = tree_b.generate_proof(0).unwrap();
        let root_b = tree_b.current_root().unwrap();
        let lock_b =
            prepare_lock(&terms, &meta_b, &meta_a.pk.into(), &note_b, &proof_b, root_b);

        let lock_data_a = SwapLockData {
            commitment: lock_a.locked_note.commitment().0,
            timeout: lock_a.witness.timeout,
            pk_stealth: lock_a.witness.pk_stealth,
            h_swap: lock_a.witness.h_swap,
            h_r: lock_a.witness.h_r,
            h_meta: lock_a.witness.h_meta,
            h_enc: lock_a.witness.h_enc,
        };

        let lock_data_b = SwapLockData {
            commitment: lock_b.locked_note.commitment().0,
            timeout: lock_b.witness.timeout,
            pk_stealth: lock_b.witness.pk_stealth,
            h_swap: lock_b.witness.h_swap,
            h_r: lock_b.witness.h_r,
            h_meta: lock_b.witness.h_meta,
            h_enc: lock_b.witness.h_enc,
        };

        // ── Build coordinator with pre-populated mock chains ──
        let chain_a = MockChainPort::new();
        chain_a
            .insert_lock_data(lock_data_a.commitment, lock_data_a)
            .await;

        let chain_b = MockChainPort::new();
        chain_b
            .insert_lock_data(lock_data_b.commitment, lock_data_b)
            .await;

        let mut chains = HashMap::new();
        chains.insert(terms.chain_id_a, chain_a);
        chains.insert(terms.chain_id_b, chain_b);

        let coordinator = Arc::new(SwapCoordinator::new(
            InMemorySwapStore::new(),
            chains,
            terms.chain_id_a,
        ));

        // ── Start RA-TLS server ──
        let tee = MockTeeRuntime::new(Address::repeat_byte(0x42));
        let addr = "127.0.0.1:0".parse().unwrap();

        let (handle, bound_addr) = start_server(coordinator, &tee, addr)
            .await
            .expect("server should start");

        let base_url = format!("https://127.0.0.1:{}", bound_addr.port());

        // ── Build RA-TLS client (validates mock attestation in TLS handshake) ──
        let client = build_ra_tls_client(true);

        // ── Test 1: POST Party A's submission → expect "pending" ──
        let resp = client
            .post(format!("{base_url}/submit"))
            .json(&lock_a.submission)
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "pending");

        // ── Test 2: GET /status → expect matched=true, announced=false ──
        let swap_id_hex = format!("0x{}", hex::encode(terms.swap_id));
        let resp = client
            .get(format!("{base_url}/status/{swap_id_hex}"))
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(resp.status(), 200);
        let status: SwapStatus = resp.json().await.unwrap();
        assert!(status.matched, "should have a pending submission");
        assert!(!status.announced, "should not be announced yet");

        // ── Test 3: POST Party B's submission → expect "verified" with announcement ──
        let resp = client
            .post(format!("{base_url}/submit"))
            .json(&lock_b.submission)
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "verified");
        assert!(body.get("announcement").is_some());

        let announcement: SwapAnnouncement =
            serde_json::from_value(body["announcement"].clone()).unwrap();
        assert_eq!(announcement.swap_id, terms.swap_id);

        // ── Test 4: GET /announcement → expect the announcement ──
        let resp = client
            .get(format!("{base_url}/announcement/{swap_id_hex}"))
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(resp.status(), 200);
        let fetched: SwapAnnouncement = resp.json().await.unwrap();
        assert_eq!(fetched.swap_id, terms.swap_id);
        assert_eq!(fetched.ephemeral_key_a, announcement.ephemeral_key_a);
        assert_eq!(fetched.ephemeral_key_b, announcement.ephemeral_key_b);

        // ── Test 5: GET /status → expect matched=false, announced=true ──
        let resp = client
            .get(format!("{base_url}/status/{swap_id_hex}"))
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(resp.status(), 200);
        let status: SwapStatus = resp.json().await.unwrap();
        assert!(!status.matched, "pending submission should be consumed");
        assert!(status.announced, "announcement should exist now");

        // ── Shutdown ──
        handle.shutdown();
    }
}
