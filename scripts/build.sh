#!/usr/bin/env bash
#
# build.sh — Compile the Shade Protocol circuits and run the Groth16
#             trusted setup (single-participant dev ceremony).
#
# Usage:
#   ./scripts/build.sh              Full build (compile + setup + export)
#   ./scripts/build.sh --setup-only Skip compilation, run setup + export only
#
# Prerequisites:
#   - circom >= 2.0.6 installed and on PATH
#   - node_modules installed (npm install / yarn install)
#
# Outputs:
#   build/main.r1cs           R1CS constraint system
#   build/main_js/main.wasm   WASM witness generator
#   build/main.sym             Symbol table (debugging)
#   build/main.zkey            Groth16 proving key
#   build/verification_key.json  Verification key (JSON)
#   build/Verifier.sol         Solidity verifier contract

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"
SRC_DIR="${PROJECT_DIR}/src"

CIRCUIT_NAME="main"
PTAU_SIZE=20
PTAU_FILE="${BUILD_DIR}/powersOfTau28_hez_final_${PTAU_SIZE}.ptau"
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_${PTAU_SIZE}.ptau"

SETUP_ONLY=false
if [[ "${1:-}" == "--setup-only" ]]; then
    SETUP_ONLY=true
fi

echo "============================================"
echo " Shade Protocol — Circuit Build"
echo "============================================"
echo ""

# ------------------------------------------------------------------
# Step 0: Sanity checks
# ------------------------------------------------------------------
if ! command -v circom &>/dev/null; then
    echo "ERROR: circom not found on PATH."
    echo "Install it from https://docs.circom.io/getting-started/installation/"
    exit 1
fi

if ! command -v npx &>/dev/null; then
    echo "ERROR: npx not found. Install Node.js >= 16."
    exit 1
fi

if [[ ! -d "${PROJECT_DIR}/node_modules/circomlib" ]]; then
    echo "ERROR: circomlib not found in node_modules."
    echo "Run 'npm install' or 'yarn install' in ${PROJECT_DIR} first."
    exit 1
fi

mkdir -p "${BUILD_DIR}"

# ------------------------------------------------------------------
# Step 1: Compile the circuit
# ------------------------------------------------------------------
if [[ "${SETUP_ONLY}" == false ]]; then
    echo "[1/5] Compiling circuit..."
    circom "${SRC_DIR}/${CIRCUIT_NAME}.circom" \
        --r1cs \
        --wasm \
        --sym \
        -o "${BUILD_DIR}" \
        -l "${PROJECT_DIR}/node_modules"

    echo "      R1CS:  ${BUILD_DIR}/${CIRCUIT_NAME}.r1cs"
    echo "      WASM:  ${BUILD_DIR}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm"
    echo "      SYM:   ${BUILD_DIR}/${CIRCUIT_NAME}.sym"
    echo ""

    echo "      Constraint info:"
    npx snarkjs r1cs info "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs"
    echo ""
else
    echo "[1/5] Skipping compilation (--setup-only)."
    if [[ ! -f "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs" ]]; then
        echo "ERROR: ${BUILD_DIR}/${CIRCUIT_NAME}.r1cs not found. Run full build first."
        exit 1
    fi
    echo ""
fi

# ------------------------------------------------------------------
# Step 2: Download Hermez Powers of Tau (if not cached)
# ------------------------------------------------------------------
echo "[2/5] Checking Powers of Tau file..."
if [[ -f "${PTAU_FILE}" ]]; then
    echo "      Found cached PTAU: ${PTAU_FILE}"
else
    echo "      Downloading Hermez PTAU (2^${PTAU_SIZE})..."
    echo "      URL: ${PTAU_URL}"
    curl -L -o "${PTAU_FILE}" "${PTAU_URL}"
    echo "      Downloaded to ${PTAU_FILE}"
fi
echo ""

# ------------------------------------------------------------------
# Step 3: Phase 2 trusted setup (single-participant dev ceremony)
# ------------------------------------------------------------------
echo "[3/5] Running Phase 2 setup..."

# Generate initial zkey from R1CS + PTAU
npx snarkjs groth16 setup \
    "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs" \
    "${PTAU_FILE}" \
    "${BUILD_DIR}/${CIRCUIT_NAME}_0000.zkey"

# Contribute randomness (single participant — dev only, NOT production)
npx snarkjs zkey contribute \
    "${BUILD_DIR}/${CIRCUIT_NAME}_0000.zkey" \
    "${BUILD_DIR}/${CIRCUIT_NAME}_0001.zkey" \
    --name="shade-dev-contributor" \
    -v -e="shade-protocol-dev-entropy-$(date +%s)"

# Finalize (apply random beacon — using a fixed value for dev reproducibility)
npx snarkjs zkey beacon \
    "${BUILD_DIR}/${CIRCUIT_NAME}_0001.zkey" \
    "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
    0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 \
    10 \
    -n="shade-dev-beacon"

# Clean up intermediate zkey files
rm -f "${BUILD_DIR}/${CIRCUIT_NAME}_0000.zkey"
rm -f "${BUILD_DIR}/${CIRCUIT_NAME}_0001.zkey"

echo "      Final zkey: ${BUILD_DIR}/${CIRCUIT_NAME}.zkey"
echo ""

# ------------------------------------------------------------------
# Step 4: Export verification key
# ------------------------------------------------------------------
echo "[4/5] Exporting verification key..."
npx snarkjs zkey export verificationkey \
    "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
    "${BUILD_DIR}/verification_key.json"

echo "      Verification key: ${BUILD_DIR}/verification_key.json"
echo ""

# ------------------------------------------------------------------
# Step 5: Export Solidity verifier
# ------------------------------------------------------------------
echo "[5/5] Exporting Solidity verifier..."
npx snarkjs zkey export solidityverifier \
    "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
    "${BUILD_DIR}/Verifier.sol"

echo "      Solidity verifier: ${BUILD_DIR}/Verifier.sol"
echo ""

# ------------------------------------------------------------------
# Copy WASM to a convenient location
# ------------------------------------------------------------------
if [[ -f "${BUILD_DIR}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" ]]; then
    cp "${BUILD_DIR}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" \
       "${BUILD_DIR}/joinsplit.wasm"
    echo "      Copied WASM as: ${BUILD_DIR}/joinsplit.wasm"
fi

# Copy zkey with the joinsplit alias
cp "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" "${BUILD_DIR}/joinsplit.zkey"
echo "      Copied zkey as:  ${BUILD_DIR}/joinsplit.zkey"

echo ""
echo "============================================"
echo " Build complete!"
echo "============================================"
echo ""
echo " Artifacts:"
echo "   ${BUILD_DIR}/joinsplit.wasm"
echo "   ${BUILD_DIR}/joinsplit.zkey"
echo "   ${BUILD_DIR}/verification_key.json"
echo "   ${BUILD_DIR}/Verifier.sol"
echo ""
