/**
 * JoinSplit Circuit Witness Test
 *
 * Generates a valid witness for the 2-in/2-out JoinSplit circuit,
 * creates a Groth16 proof, and verifies it.
 *
 * Usage: node test/test_joinsplit.js
 * Requires: circomlibjs, snarkjs, @noble/hashes
 * Artifacts must be pre-built at ../build/
 */

const snarkjs = require("snarkjs");
const { buildPoseidon, buildBabyjub, buildEddsa } = require("circomlibjs");
const crypto = require("crypto");
const { createHash } = require("crypto");
const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SNARK_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const BABYJUBJUB_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

const TREE_DEPTH = 16;

// Artifact paths (relative to where this script runs)
const WASM_PATH = path.resolve(__dirname, "../build/main_js/main.wasm");
const ZKEY_PATH = path.resolve(__dirname, "../build/joinsplit_final.zkey");
const VK_PATH = path.resolve(__dirname, "../build/verification_key.json");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Compute ZERO_VALUE = keccak256("Shade") % SNARK_FIELD.
 * Matches the on-chain Commitments.sol and indexer initialisation.
 */
function computeZeroValue() {
  // Use keccak256 via createHash — Node.js doesn't have native keccak, use a manual approach
  // keccak256("Shade") = 0x... — we can compute this with the keccak function from circomlibjs's dependency
  // Simpler: hardcode the known value or use ethers
  // keccak256("Shade") as BigInt:
  const { keccak256, toUtf8Bytes } = require("ethers");
  const hashHex = keccak256(toUtf8Bytes("Shade"));
  const hash = Buffer.from(hashHex.slice(2), "hex");
  let value = 0n;
  for (const b of hash) {
    value = (value << 8n) + BigInt(b);
  }
  return value % SNARK_FIELD;
}

/**
 * Generate a random field element in [1, SNARK_FIELD).
 */
function randomFieldElement() {
  const bytes = crypto.randomBytes(32);
  let value = 0n;
  for (const b of bytes) {
    value = (value << 8n) + BigInt(b);
  }
  return (value % (SNARK_FIELD - 1n)) + 1n;
}

/**
 * Convert circomlibjs Poseidon output to BigInt.
 */
function fieldToBigInt(poseidon, element) {
  return BigInt(poseidon.F.toString(element));
}

/**
 * Poseidon hash wrapper that returns BigInt.
 */
function poseidonHash(poseidon, inputs) {
  const raw = poseidon(inputs);
  return fieldToBigInt(poseidon, raw);
}

/**
 * Convert BigInt to little-endian byte buffer of given length.
 */
function bigIntToLeBytes(value, length) {
  const buf = Buffer.alloc(length);
  let v = value;
  for (let i = 0; i < length; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

// ---------------------------------------------------------------------------
// Merkle Tree (binary Poseidon, matching on-chain)
// ---------------------------------------------------------------------------

class MerkleTree {
  constructor(depth, zeroValue, poseidon) {
    this.depth = depth;
    this.capacity = 2 ** depth;
    this.zeroValue = zeroValue;
    this.poseidon = poseidon;
    this.leafCount = 0;
    this.leaves = [];

    // Precompute zero hashes for each level
    this.zeroHashes = new Array(depth + 1);
    this.zeroHashes[0] = zeroValue;
    for (let i = 1; i <= depth; i++) {
      this.zeroHashes[i] = this._hash(this.zeroHashes[i - 1], this.zeroHashes[i - 1]);
    }

    // Filled subtrees for incremental insertion
    this.filledSubtrees = new Array(depth);
    for (let i = 0; i < depth; i++) {
      this.filledSubtrees[i] = this.zeroHashes[i];
    }

    this.root = this.zeroHashes[depth];
  }

  _hash(left, right) {
    return poseidonHash(this.poseidon, [left, right]);
  }

  insert(leaf) {
    if (this.leafCount >= this.capacity) {
      throw new Error("Merkle tree full");
    }

    const index = this.leafCount;
    this.leaves.push(leaf);

    let currentIndex = index;
    let currentHash = leaf;

    for (let level = 0; level < this.depth; level++) {
      if (currentIndex % 2 === 0) {
        this.filledSubtrees[level] = currentHash;
        currentHash = this._hash(currentHash, this.zeroHashes[level]);
      } else {
        currentHash = this._hash(this.filledSubtrees[level], currentHash);
      }
      currentIndex = Math.floor(currentIndex / 2);
    }

    this.root = currentHash;
    this.leafCount++;
    return index;
  }

  getPath(leafIndex) {
    if (leafIndex < 0 || leafIndex >= this.leafCount) {
      throw new Error(`Leaf index ${leafIndex} out of range`);
    }

    const pathElements = [];

    // Build level 0: all leaves, padded with zeroValue
    let currentLevel = new Array(this.capacity);
    for (let i = 0; i < this.capacity; i++) {
      currentLevel[i] = i < this.leafCount ? this.leaves[i] : this.zeroValue;
    }

    let idx = leafIndex;
    for (let level = 0; level < this.depth; level++) {
      const siblingIdx = idx % 2 === 1 ? idx - 1 : idx + 1;
      pathElements.push(currentLevel[siblingIdx]);

      // Compute next level
      const nextLevelSize = currentLevel.length / 2;
      const nextLevel = new Array(nextLevelSize);
      for (let i = 0; i < nextLevelSize; i++) {
        nextLevel[i] = this._hash(currentLevel[2 * i], currentLevel[2 * i + 1]);
      }
      currentLevel = nextLevel;
      idx = Math.floor(idx / 2);
    }

    return { pathElements };
  }
}

// ---------------------------------------------------------------------------
// Main Test
// ---------------------------------------------------------------------------

async function main() {
  console.log("=== JoinSplit Circuit Witness Test ===\n");

  // Check that artifacts exist
  for (const [name, p] of [["WASM", WASM_PATH], ["ZKEY", ZKEY_PATH], ["VK", VK_PATH]]) {
    if (!fs.existsSync(p)) {
      console.error(`ERROR: ${name} artifact not found at ${p}`);
      process.exit(1);
    }
  }

  // -------------------------------------------------------------------------
  // Step 1: Initialize circomlibjs
  // -------------------------------------------------------------------------
  console.log("[1/11] Initializing circomlibjs...");
  const poseidon = await buildPoseidon();
  const babyjub = await buildBabyjub();
  const eddsa = await buildEddsa();

  // -------------------------------------------------------------------------
  // Step 2: Generate test keys
  // -------------------------------------------------------------------------
  console.log("[2/11] Generating test keys...");

  // Spending key: random 32-byte seed (raw privKey for circomlibjs EdDSA).
  // circomlibjs internally derives the actual signing scalar via
  // Blake-512 hash + pruning + right-shift by 3.
  const spendingKeySeed = crypto.randomBytes(32);
  console.log(`  spendingKeySeed: ${spendingKeySeed.toString("hex")}`);

  // Spending public key: use circomlibjs EdDSA native derivation so that
  // the public key matches what signPoseidon() uses internally.
  const spendingPubRaw = eddsa.prv2pub(spendingKeySeed);
  const spendingPublicKey = [
    BigInt(eddsa.F.toString(spendingPubRaw[0])),
    BigInt(eddsa.F.toString(spendingPubRaw[1])),
  ];
  console.log(`  spendingPublicKey.x: ${spendingPublicKey[0]}`);
  console.log(`  spendingPublicKey.y: ${spendingPublicKey[1]}`);

  // Nullifying key: Poseidon of the seed interpreted as a big-endian bigint.
  let spendingKeySeedInt = 0n;
  for (const b of spendingKeySeed) {
    spendingKeySeedInt = (spendingKeySeedInt << 8n) + BigInt(b);
  }
  const nullifyingKey = poseidonHash(poseidon, [spendingKeySeedInt]);
  console.log(`  nullifyingKey: ${nullifyingKey}`);

  // Master public key: Poseidon(spendPubKey.x, spendPubKey.y, nullifyingKey)
  const masterPublicKey = poseidonHash(poseidon, [
    spendingPublicKey[0],
    spendingPublicKey[1],
    nullifyingKey,
  ]);
  console.log(`  masterPublicKey: ${masterPublicKey}`);

  // -------------------------------------------------------------------------
  // Step 3: Create input note 0 (the real note, value = 1000000)
  // -------------------------------------------------------------------------
  console.log("[3/11] Creating input note 0 (shield scenario)...");

  // Token ID: Poseidon of a fake address (just a test value)
  const fakeTokenAddress = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefn;
  const token = poseidonHash(poseidon, [fakeTokenAddress]);
  console.log(`  token: ${token}`);

  const value0 = 1000000n;
  const random0 = randomFieldElement();
  const npk0 = poseidonHash(poseidon, [masterPublicKey, random0]);
  const commitment0 = poseidonHash(poseidon, [npk0, token, value0]);
  console.log(`  random0: ${random0}`);
  console.log(`  npk0: ${npk0}`);
  console.log(`  commitment0: ${commitment0}`);

  // -------------------------------------------------------------------------
  // Step 4: Build Merkle tree and insert commitment at index 0
  // -------------------------------------------------------------------------
  console.log("[4/11] Building Merkle tree (depth 16)...");

  const ZERO_VALUE = computeZeroValue();
  console.log(`  ZERO_VALUE: ${ZERO_VALUE}`);

  const tree = new MerkleTree(TREE_DEPTH, ZERO_VALUE, poseidon);
  tree.insert(commitment0);

  const merkleRoot = tree.root;
  console.log(`  merkleRoot: ${merkleRoot}`);

  const proof0 = tree.getPath(0);
  console.log(`  pathElements[0] length: ${proof0.pathElements.length}`);

  // -------------------------------------------------------------------------
  // Step 5: Create input note 1 (dummy, value = 0)
  // -------------------------------------------------------------------------
  console.log("[5/11] Creating dummy input note 1 (value = 0)...");

  const random1 = randomFieldElement();
  const npk1 = poseidonHash(poseidon, [masterPublicKey, random1]);
  const commitment1_dummy = poseidonHash(poseidon, [npk1, token, 0n]);
  console.log(`  random1: ${random1}`);
  console.log(`  npk1: ${npk1}`);
  console.log(`  commitment1 (dummy): ${commitment1_dummy}`);

  // Dummy note: pathElements all zeros, leafIndex 0
  // The circuit skips Merkle check when valueIn == 0:
  //   valueIn[i] * (merkleRoot - computedRoot) === 0
  const dummyPathElements = new Array(TREE_DEPTH).fill(0n);

  // -------------------------------------------------------------------------
  // Step 6: Create output notes
  // -------------------------------------------------------------------------
  console.log("[6/11] Creating output notes...");

  // Output 0: self-transfer, value = 1000000
  const randomOut0 = randomFieldElement();
  const npkOut0 = poseidonHash(poseidon, [masterPublicKey, randomOut0]);
  const commitmentOut0 = poseidonHash(poseidon, [npkOut0, token, value0]);
  console.log(`  output 0: value=${value0}, npkOut0=${npkOut0}`);
  console.log(`  commitmentOut0: ${commitmentOut0}`);

  // Output 1: dummy, value = 0
  const randomOut1 = randomFieldElement();
  const npkOut1 = poseidonHash(poseidon, [masterPublicKey, randomOut1]);
  const commitmentOut1 = poseidonHash(poseidon, [npkOut1, token, 0n]);
  console.log(`  output 1: value=0, npkOut1=${npkOut1}`);
  console.log(`  commitmentOut1: ${commitmentOut1}`);

  // -------------------------------------------------------------------------
  // Step 7: Compute nullifiers
  // -------------------------------------------------------------------------
  console.log("[7/11] Computing nullifiers...");

  // nullifier = Poseidon(nullifyingKey, leafIndex)
  const nullifier0 = poseidonHash(poseidon, [nullifyingKey, 0n]); // leafIndex 0
  const nullifier1 = poseidonHash(poseidon, [nullifyingKey, 0n]); // dummy leafIndex 0
  console.log(`  nullifier0: ${nullifier0}`);
  console.log(`  nullifier1: ${nullifier1}`);

  // -------------------------------------------------------------------------
  // Step 8: Compute boundParamsHash and message hash
  // -------------------------------------------------------------------------
  console.log("[8/11] Computing bound params hash and message hash...");

  // boundParamsHash: Poseidon of chainId (test value)
  const chainId = 4114n; // Citrea mainnet
  const boundParamsHash = poseidonHash(poseidon, [chainId]);
  console.log(`  boundParamsHash: ${boundParamsHash}`);

  // Message hash = Poseidon(merkleRoot, boundParamsHash, null0, null1, commOut0, commOut1)
  const messageHash = poseidonHash(poseidon, [
    merkleRoot,
    boundParamsHash,
    nullifier0,
    nullifier1,
    commitmentOut0,
    commitmentOut1,
  ]);
  console.log(`  messageHash: ${messageHash}`);

  // -------------------------------------------------------------------------
  // Step 9: Sign with EdDSA-Poseidon
  // -------------------------------------------------------------------------
  console.log("[9/11] Signing message with EdDSA-Poseidon...");

  // CRITICAL: signPoseidon expects msg as a field element in Montgomery form
  // (Uint8Array). When poseidon() internally calls F.e(msg) on a Uint8Array,
  // it returns it as-is (assumes already in Montgomery form). So we must
  // convert messageHash to Montgomery form via F.e() before passing it.
  const msgF = eddsa.babyJub.F.e(messageHash);
  const signatureRaw = eddsa.signPoseidon(spendingKeySeed, msgF);

  const sigR8x = BigInt(eddsa.F.toString(signatureRaw.R8[0]));
  const sigR8y = BigInt(eddsa.F.toString(signatureRaw.R8[1]));
  const sigS = signatureRaw.S;
  console.log(`  R8x: ${sigR8x}`);
  console.log(`  R8y: ${sigR8y}`);
  console.log(`  S: ${sigS}`);

  // Verify signature locally before sending to circuit
  const verifyResult = eddsa.verifyPoseidon(msgF, signatureRaw, [
    spendingPubRaw[0],
    spendingPubRaw[1],
  ]);
  console.log(`  EdDSA local verification: ${verifyResult}`);
  if (!verifyResult) {
    console.error("ERROR: EdDSA signature failed local verification!");
    process.exit(1);
  }

  // -------------------------------------------------------------------------
  // Step 10: Build witness JSON
  // -------------------------------------------------------------------------
  console.log("[10/11] Building witness JSON...");

  const witnessInput = {
    // Public signals
    merkleRoot: merkleRoot.toString(),
    boundParamsHash: boundParamsHash.toString(),
    nullifiers: [nullifier0.toString(), nullifier1.toString()],
    commitmentsOut: [commitmentOut0.toString(), commitmentOut1.toString()],

    // Private signals
    token: token.toString(),
    publicKey: [spendingPublicKey[0].toString(), spendingPublicKey[1].toString()],
    signature: [sigR8x.toString(), sigR8y.toString(), sigS.toString()],
    randomIn: [random0.toString(), random1.toString()],
    valueIn: [value0.toString(), "0"],
    pathElements: [
      proof0.pathElements.map((e) => e.toString()),
      dummyPathElements.map((e) => e.toString()),
    ],
    leavesIndices: ["0", "0"],
    nullifyingKey: nullifyingKey.toString(),
    npkOut: [npkOut0.toString(), npkOut1.toString()],
    valueOut: [value0.toString(), "0"],
  };

  // Write input.json
  const inputPath = path.resolve(__dirname, "input.json");
  fs.writeFileSync(inputPath, JSON.stringify(witnessInput, null, 2));
  console.log(`  Written to ${inputPath}`);

  // -------------------------------------------------------------------------
  // Step 11: Generate and verify Groth16 proof
  // -------------------------------------------------------------------------
  console.log("[11/11] Generating and verifying Groth16 proof...\n");

  // Calculate witness
  console.log("  Calculating witness...");
  const wtnsPath = path.resolve(__dirname, "witness.wtns");
  await snarkjs.wtns.calculate(witnessInput, WASM_PATH, wtnsPath);
  console.log("  Witness calculated successfully.");

  // Generate proof
  console.log("  Generating Groth16 proof...");
  const { proof, publicSignals } = await snarkjs.groth16.prove(ZKEY_PATH, wtnsPath);
  console.log("  Proof generated successfully.");
  console.log(`  Public signals (${publicSignals.length}):`);
  const publicSignalNames = [
    "merkleRoot",
    "boundParamsHash",
    "nullifiers[0]",
    "nullifiers[1]",
    "commitmentsOut[0]",
    "commitmentsOut[1]",
  ];
  for (let i = 0; i < publicSignals.length; i++) {
    const name = i < publicSignalNames.length ? publicSignalNames[i] : `signal[${i}]`;
    console.log(`    ${name}: ${publicSignals[i]}`);
  }

  // Verify proof
  console.log("\n  Verifying proof...");
  const vk = JSON.parse(fs.readFileSync(VK_PATH, "utf8"));
  const isValid = await snarkjs.groth16.verify(vk, publicSignals, proof);

  console.log(`\n${"=".repeat(50)}`);
  if (isValid) {
    console.log("  PROOF VERIFIED SUCCESSFULLY");
  } else {
    console.log("  PROOF VERIFICATION FAILED");
  }
  console.log(`${"=".repeat(50)}\n`);

  // Clean up witness file
  if (fs.existsSync(wtnsPath)) {
    fs.unlinkSync(wtnsPath);
  }

  process.exit(isValid ? 0 : 1);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
