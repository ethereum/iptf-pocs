#!/bin/sh
# Bring up loopback interface — not configured by default in Nitro Enclaves
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
ip link set lo up 2>/dev/null || true

# Nitro Enclaves have no direct network access — all outbound traffic must go
# through vsock to the host, where vsock-proxy forwards it to the internet.
# socat bridges local TCP ports to vsock CID:3 (the parent/host).
# Port mapping must match the vsock-proxy instances started on the host:
#   vsock-proxy 21001 1rpc.io 443
#   vsock-proxy 21002 sepolia-rpc.scroll.io 443
socat TCP-LISTEN:21001,fork,reuseaddr VSOCK-CONNECT:3:21001 &
socat TCP-LISTEN:21002,fork,reuseaddr VSOCK-CONNECT:3:21002 &

# Map RPC hostnames to loopback so the server connects via socat above.
# TLS verification still works because the hostname in the URL matches the cert.
echo "127.0.0.1 1rpc.io" >> /etc/hosts
echo "127.0.0.1 sepolia-rpc.scroll.io" >> /etc/hosts

# Give socat a moment to start listening before the server tries to connect
sleep 1

exec /app
