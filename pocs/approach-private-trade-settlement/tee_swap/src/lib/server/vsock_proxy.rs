//! vsock-to-TCP proxy for the Nitro Enclave.
//!
//! The enclave has no external network. External HTTPS traffic reaches the enclave
//! via vsock (from the host proxy). This module listens on a vsock port and
//! transparently forwards each connection to the local axum HTTPS server.
//!
//! TLS is NOT terminated here — the bytes are forwarded as-is, so the axum server's
//! RA-TLS certificate (with the embedded NSM attestation) is visible end-to-end.

use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

/// Run the vsock → TCP proxy.
///
/// Binds on `vsock_port` (any CID) and forwards each accepted connection to
/// `tcp_target` (e.g. `"127.0.0.1:8443"`).
///
/// Runs indefinitely; call from `tokio::spawn`.
pub async fn run_vsock_proxy(vsock_port: u32, tcp_target: Arc<String>) {
    let mut listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port))
        .expect("failed to bind vsock listener");

    eprintln!("[vsock_proxy] listening on vsock port {vsock_port}");

    loop {
        match listener.accept().await {
            Ok((vsock_stream, addr)) => {
                eprintln!("[vsock_proxy] accepted connection from {addr:?}");
                let target = Arc::clone(&tcp_target);
                tokio::spawn(async move {
                    if let Err(e) = forward(vsock_stream, &target).await {
                        eprintln!("[vsock_proxy] forward error: {e}");
                    }
                });
            }
            Err(e) => {
                eprintln!("[vsock_proxy] accept error: {e}");
            }
        }
    }
}

async fn forward(
    mut vsock_stream: tokio_vsock::VsockStream,
    tcp_target: &str,
) -> std::io::Result<()> {
    let mut tcp_stream = TcpStream::connect(tcp_target).await?;
    tokio::io::copy_bidirectional(&mut vsock_stream, &mut tcp_stream).await?;
    Ok(())
}
