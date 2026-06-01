#!/bin/bash
# Generate Solidity verifiers from the EVM-targeted Noir circuits.
#
# Four circuits are verified on-chain: deposit, the two spend circuits (transfer,
# withdraw), and the relayer insertion proof. The chain-update circuit is consumed
# recursively off-chain (no Solidity verifier).
#
# VK generation needs only the compiled circuit, not a witness, so there is no
# Prover.toml / `nargo execute` step. Each verifier is emitted as bb's default
# `HonkVerifier`; forge disambiguates the same-named contracts by file path, and
# `ShieldedPoolExt` takes verifier *addresses*, so the contract names need not be
# unique.
#
# Requires nargo 1.0.0-beta.21 + bb 5.0.0-nightly on PATH (see README).
#
# NOTE: withdraw's k=1 insertion proof needs a single-insertion instantiation of
# the insertion circuit, which is not yet built; only the k=2 `insertion` verifier
# is generated here (see README "Implementation shortcuts").
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="$PROJECT_ROOT/target"
VERIFIERS_DIR="$PROJECT_ROOT/contracts/src/verifiers"

mkdir -p "$VERIFIERS_DIR"

CIRCUITS=("deposit" "transfer" "withdraw" "insertion")

echo "=== Generating Solidity Verifiers ==="
echo "Output directory: $VERIFIERS_DIR"
echo ""

echo "Compiling circuits..."
(cd "$PROJECT_ROOT" && nargo compile --workspace)
echo ""

for circuit in "${CIRCUITS[@]}"; do
    echo "Processing $circuit circuit..."

    VK_DIR="$TARGET_DIR/vk_${circuit}"
    rm -rf "$VK_DIR"

    echo "  [1/2] Generating verification key (keccak oracle)..."
    bb write_vk -b "$TARGET_DIR/${circuit}.json" -o "$VK_DIR" --oracle_hash keccak

    CONTRACT_NAME="$(echo ${circuit:0:1} | tr '[:lower:]' '[:upper:]')${circuit:1}Verifier"
    OUTPUT_FILE="$VERIFIERS_DIR/${CONTRACT_NAME}.sol"

    echo "  [2/2] Generating Solidity verifier: $OUTPUT_FILE"
    bb write_solidity_verifier -k "$VK_DIR/vk" -o "$OUTPUT_FILE"

    echo "  Done: $OUTPUT_FILE"
    echo ""
done

echo "=== All verifiers generated successfully ==="
