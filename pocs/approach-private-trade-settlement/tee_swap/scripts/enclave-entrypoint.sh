#!/bin/sh
# Bring up loopback interface — not configured by default in Nitro Enclaves
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
ip link set lo up 2>/dev/null || true
exec /app
