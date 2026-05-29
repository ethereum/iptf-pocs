#!/bin/bash
# Generate Solidity verifiers from Noir circuits.
# Only the EVM-targeted circuits (deposit, transfer, withdraw) get Solidity
# verifiers — the chain-update circuit is consumed recursively off-chain.
# Requires: nargo, bb (barretenberg CLI).
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CIRCUITS_DIR="$PROJECT_ROOT/circuits"
VERIFIERS_DIR="$PROJECT_ROOT/contracts/src/verifiers"

mkdir -p "$VERIFIERS_DIR"

CIRCUITS=("deposit" "transfer" "withdraw")

echo "=== Generating Solidity Verifiers ==="
echo "Circuits directory: $CIRCUITS_DIR"
echo "Output directory: $VERIFIERS_DIR"
echo ""

for circuit in "${CIRCUITS[@]}"; do
    CIRCUIT_DIR="$CIRCUITS_DIR/$circuit"

    if [ ! -d "$CIRCUIT_DIR" ]; then
        echo "ERROR: Circuit directory not found: $CIRCUIT_DIR"
        exit 1
    fi

    echo "Processing $circuit circuit..."
    cd "$CIRCUIT_DIR"

    echo "  [1/4] Compiling circuit..."
    nargo check

    echo "  [2/4] Executing circuit..."
    nargo execute witness

    echo "  [3/4] Generating verification key..."
    bb write_vk -b "../../target/${circuit}.json" -o ./target --oracle_hash keccak

    CONTRACT_NAME="$(echo ${circuit:0:1} | tr '[:lower:]' '[:upper:]')${circuit:1}Verifier"
    OUTPUT_FILE="$VERIFIERS_DIR/${CONTRACT_NAME}.sol"

    echo "  [4/4] Generating Solidity verifier: $CONTRACT_NAME"
    bb write_solidity_verifier -k ./target/vk -o "$OUTPUT_FILE"

    echo "  Done: $OUTPUT_FILE"
    echo ""
done

echo "=== All verifiers generated successfully ==="
