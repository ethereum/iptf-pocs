#!/bin/bash
set -e

# ==============================================================================
# PRIVATE BONDS ON AZTEC - GATE COUNT PROFILING
# ==============================================================================
#
# Profiles every transaction in the full bond lifecycle to measure circuit
# complexity (gate counts) using `aztec-wallet profile`.
#
# Gate counts are a more meaningful metric than wall-clock timing because they
# measure the actual circuit complexity independent of hardware.
#
# IMPORTANT: `profile` only simulates — it does NOT mutate on-chain state.
# After each profile we `send` the same operation to advance state for
# subsequent operations.
#
# Reference: https://docs.aztec.network/developers/docs/aztec-nr/framework-description/advanced/how_to_profile_transactions
#
# PREREQUISITES:
#   1. Aztec sandbox running:  aztec start --local-network
#   2. Test accounts imported: aztec-wallet import-test-accounts
#   3. Contracts compiled:     cd contracts && aztec compile
#
# ACTORS:
#   test0 - Bond issuer & stablecoin admin
#   test1 - Investor A (seller in DvP)
#   test2 - Investor B (buyer in DvP)
#
# USAGE:
#   ./bench.sh              Run profiling (human-readable output)
#
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="$SCRIPT_DIR/contracts"
TARGET_DIR="$CONTRACTS_DIR/target"

BOND_ARTIFACT="$TARGET_DIR/private_bonds-PrivateBonds.json"
STABLE_ARTIFACT="$TARGET_DIR/stablecoin-Stablecoin.json"
DVP_ARTIFACT="$TARGET_DIR/dvp-DvP.json"

# Ensure contracts are compiled
for artifact in "$BOND_ARTIFACT" "$STABLE_ARTIFACT" "$DVP_ARTIFACT"; do
    if [ ! -f "$artifact" ]; then
        echo "Contracts not compiled. Compiling..."
        (cd "$CONTRACTS_DIR" && aztec compile)
        echo ""
        break
    fi
done

echo "=============================================================="
echo "  PRIVATE BONDS - GATE COUNT PROFILING"
echo "=============================================================="
echo ""
echo "This script profiles every operation in the bond lifecycle"
echo "to measure circuit complexity (gate counts)."
echo ""
echo "Gate count reference:"
echo "  < 50,000      Excellent"
echo "  50,000-200,000  Acceptable"
echo "  200,000-500,000 Needs optimization"
echo "  > 500,000      Requires optimization"
echo ""

# ==============================================================================
# SETUP: Deploy contracts
# ==============================================================================

echo "=============================================================="
echo "SETUP: Deploying contracts"
echo "=============================================================="
echo ""

echo "[1/3] Deploying PrivateBonds (issuer=test0, supply=1M, maturity=0)..."
aztec-wallet deploy "$BOND_ARTIFACT" \
    --from accounts:test0 -a bench-bonds \
    --init constructor --args 1000000 0
echo ""

echo "[2/3] Deploying Stablecoin (admin=test0, supply=10M)..."
aztec-wallet deploy "$STABLE_ARTIFACT" \
    --from accounts:test0 -a bench-stable \
    --init constructor --args 10000000
echo ""

echo "[3/3] Deploying DvP coordinator (stateless, no init)..."
aztec-wallet deploy "$DVP_ARTIFACT" \
    --from accounts:test0 -a bench-dvp \
    --no-init
echo ""

# ==============================================================================
# PROFILE: PrivateBonds operations
# ==============================================================================
# State: test0 = 1M bonds, test1 = 0, test2 = 0

echo "=============================================================="
echo "PROFILING: PrivateBonds"
echo "=============================================================="
echo ""

# --- add_to_whitelist (public) ---
echo "--------------------------------------------------------------"
echo "Operation: add_to_whitelist (public)"
echo "--------------------------------------------------------------"
aztec-wallet profile add_to_whitelist \
    --contract-address contracts:bench-bonds \
    --args accounts:test1 \
    -f accounts:test0
echo ""

# Advance state: whitelist both investors
aztec-wallet send add_to_whitelist --contract-address contracts:bench-bonds --args accounts:test1 --from accounts:test0
aztec-wallet send add_to_whitelist --contract-address contracts:bench-bonds --args accounts:test2 --from accounts:test0
echo ""

# --- distribute_private (private) ---
# State: test0 = 1M bonds (nothing spent yet)
echo "--------------------------------------------------------------"
echo "Operation: distribute_private (private)"
echo "--------------------------------------------------------------"
aztec-wallet profile distribute_private \
    --contract-address contracts:bench-bonds \
    --args accounts:test1 500000 \
    -f accounts:test0
echo ""

# Advance state: distribute to both investors
aztec-wallet send distribute_private --contract-address contracts:bench-bonds --args accounts:test1 500000 --from accounts:test0
aztec-wallet send distribute_private --contract-address contracts:bench-bonds --args accounts:test2 300000 --from accounts:test0
echo ""

# --- transfer_private (private) ---
# State: test1 = 500k bonds
echo "--------------------------------------------------------------"
echo "Operation: transfer_private (private)"
echo "--------------------------------------------------------------"
aztec-wallet profile transfer_private \
    --contract-address contracts:bench-bonds \
    --args accounts:test2 100000 \
    -f accounts:test1
echo ""

# --- redeem (private) ---
# State: test2 = 300k bonds (profile above didn't mutate)
echo "--------------------------------------------------------------"
echo "Operation: redeem (private)"
echo "--------------------------------------------------------------"
aztec-wallet profile redeem \
    --contract-address contracts:bench-bonds \
    --args 100000 \
    -f accounts:test2
echo ""

# ==============================================================================
# PROFILE: Stablecoin operations
# ==============================================================================
# State: test0 = 10M stablecoins

echo "=============================================================="
echo "PROFILING: Stablecoin"
echo "=============================================================="
echo ""

echo "--------------------------------------------------------------"
echo "Operation: transfer_private (private)"
echo "--------------------------------------------------------------"
aztec-wallet profile transfer_private \
    --contract-address contracts:bench-stable \
    --args accounts:test2 1000000 \
    -f accounts:test0
echo ""

# Advance state: give test2 stablecoins for DvP
aztec-wallet send transfer_private --contract-address contracts:bench-stable --args accounts:test2 500000 --from accounts:test0
echo ""

# ==============================================================================
# PROFILE: DvP atomic swap
# ==============================================================================
#
# The DvP swap is the most complex operation — it involves:
#   1. DvP.execute_swap (entry point)
#   2. PrivateBonds.transfer_from (cross-contract call)
#   3. Stablecoin.transfer_from (cross-contract call)
#
# State: test1 = 500k bonds, test2 = 300k bonds + 500k stablecoins
# ==============================================================================

echo "=============================================================="
echo "PROFILING: DvP Atomic Swap"
echo "=============================================================="
echo ""

# Seller (test1) authorizes DvP to move 50k bonds to test2
echo "  Creating authwit: seller authorizes DvP to transfer bonds..."
aztec-wallet create-authwit transfer_from contracts:bench-dvp \
    --contract-address contracts:bench-bonds \
    --args accounts:test1 accounts:test2 50000 0 \
    -f accounts:test1 \
    -a bond-aw
echo ""

# Buyer (test2) authorizes DvP to move 250k stablecoins to test1
echo "  Creating authwit: buyer authorizes DvP to transfer stablecoins..."
aztec-wallet create-authwit transfer_from contracts:bench-dvp \
    --contract-address contracts:bench-stable \
    --args accounts:test2 accounts:test1 250000 0 \
    -f accounts:test2 \
    -a stable-aw
echo ""

echo "--------------------------------------------------------------"
echo "Operation: execute_swap (private, cross-contract)"
echo "--------------------------------------------------------------"
aztec-wallet profile execute_swap \
    --contract-address contracts:bench-dvp \
    --args contracts:bench-bonds contracts:bench-stable accounts:test1 accounts:test2 50000 250000 0 0 \
    -f accounts:test1 \
    -aw authwits:bond-aw,authwits:stable-aw
echo ""

# ==============================================================================
# SUMMARY
# ==============================================================================

echo "=============================================================="
echo "PROFILING COMPLETE"
echo "=============================================================="
echo ""
echo "Operations profiled:"
echo "  PrivateBonds:"
echo "    - add_to_whitelist    (public)"
echo "    - distribute_private  (private)"
echo "    - transfer_private    (private)"
echo "    - redeem              (private)"
echo "  Stablecoin:"
echo "    - transfer_private    (private)"
echo "  DvP:"
echo "    - execute_swap        (private, cross-contract)"
echo ""
