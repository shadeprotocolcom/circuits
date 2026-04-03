# @shade-protocol/circuits

Zero-knowledge circuits for Shade Protocol, built with [Circom](https://docs.circom.io/).

## Overview

- **JoinSplit** — 2-input, 2-output private transaction circuit (depth-16 binary Poseidon Merkle tree)
- **MerkleProofVerifier** — Binary Poseidon Merkle inclusion proof
- **NullifierCheck** — Nullifier derivation verification

### Circuit Specs

| Parameter | Value |
|---|---|
| Inputs | 2 |
| Outputs | 2 |
| Merkle Depth | 16 |
| Constraints | 18,110 |
| Proof System | Groth16 (BN254) |
| Signature | EdDSA-Poseidon |

## Build

```bash
npm install
bash scripts/build.sh
```

This compiles the circuit, downloads the Hermez Powers of Tau, runs the trusted setup, and exports:
- `build/main_js/main.wasm` — Witness generator
- `build/joinsplit_final.zkey` — Proving key
- `build/Verifier.sol` — Solidity verifier contract
- `build/verification_key.json` — Verification key

Requires: [circom](https://docs.circom.io/getting-started/installation/) ≥ 2.0.6

## Test

```bash
node test/test_joinsplit.js
```

Generates a valid witness, creates a Groth16 proof, and verifies it.

## Related Repos

- [contracts](https://github.com/shadeprotocolcom/contracts) — Smart contracts
- [sdk](https://github.com/shadeprotocolcom/sdk) — TypeScript SDK
- [frontend](https://github.com/shadeprotocolcom/frontend) — Web app

## License

MIT
