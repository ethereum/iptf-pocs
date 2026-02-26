//! Host-side vsock proxy for the Nitro Enclave.
//!
//! Listens on a TCP port and transparently forwards each connection to the enclave
//! via vsock. TLS is NOT terminated here — bytes pass through as-is, so the
//! enclave's RA-TLS certificate is visible end-to-end to the external client.
//!
//! Usage:
//!   ./host_proxy [--cid <CID>] [--vsock-port <PORT>] [--tcp-port <PORT>]
//!
//! Defaults: --cid 18 --vsock-port 5000 --tcp-port 8443
//!
//! The CID is printed by `nitro-cli run-enclave` as "EnclaveCID".

use std::env;

use tokio::net::{TcpListener, TcpStream};
use tokio_vsock::{VsockAddr, VsockStream};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let cid = parse_arg(&args, "--cid", 18u32);
    let vsock_port = parse_arg(&args, "--vsock-port", 5000u32);
    let tcp_port = parse_arg(&args, "--tcp-port", 8443u16);

    let bind_addr = format!("0.0.0.0:{tcp_port}");
    let listener = TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind TCP {bind_addr}: {e}"));

    eprintln!("[host_proxy] TCP:{tcp_port} → vsock CID:{cid} port:{vsock_port}");

    loop {
        match listener.accept().await {
            Ok((tcp_stream, peer)) => {
                eprintln!("[host_proxy] connection from {peer}");
                tokio::spawn(async move {
                    if let Err(e) = forward(tcp_stream, cid, vsock_port).await {
                        eprintln!("[host_proxy] forward error: {e}");
                    }
                });
            }
            Err(e) => {
                eprintln!("[host_proxy] accept error: {e}");
            }
        }
    }
}

async fn forward(mut tcp_stream: TcpStream, cid: u32, vsock_port: u32) -> std::io::Result<()> {
    let mut vsock_stream = VsockStream::connect(VsockAddr::new(cid, vsock_port))
        .await
        .map_err(|e| std::io::Error::other(format!("vsock connect failed: {e}")))?;

    tokio::io::copy_bidirectional(&mut tcp_stream, &mut vsock_stream).await?;
    Ok(())
}

fn parse_arg<T: std::str::FromStr + Copy>(args: &[String], flag: &str, default: T) -> T {
    args.windows(2)
        .find(|w| w[0] == flag)
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(default)
}
