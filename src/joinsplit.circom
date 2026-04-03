pragma circom 2.0.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

include "./merkle.circom";
include "./nullifier.circom";

/**
 * JoinSplit(nInputs, nOutputs, TreeDepth)
 *
 * Core privacy circuit for the Shade Protocol. Proves that a user can
 * consume nInputs existing notes and produce nOutputs new notes while
 * preserving the balance invariant, all without revealing amounts,
 * recipients, or the specific notes being spent.
 *
 * Architecture:
 *   1. All public signals are hashed together into a single message
 *      digest, which is then verified under an EdDSA-Poseidon signature.
 *   2. Each input note's nullifier is verified against the nullifying key
 *      and its leaf index.
 *   3. A Master Public Key (MPK) is derived from the spending public key
 *      and the nullifying key. Per-note public keys (NPK) are derived as
 *      Poseidon(MPK, random), allowing stealth addresses.
 *   4. Each input commitment = Poseidon(NPK, token, value) is verified
 *      to exist in the Merkle tree at the claimed position.
 *   5. Each output commitment is recomputed and constrained.
 *   6. Output values are range-checked to 120 bits to prevent overflow
 *      attacks.
 *   7. Sum of input values must equal sum of output values.
 *
 * @param nInputs    Number of input notes to consume
 * @param nOutputs   Number of output notes to produce
 * @param TreeDepth  Depth of the Poseidon Merkle commitment tree
 *
 * @requires all input notes exist in the tree rooted at merkleRoot
 * @requires the spender knows the nullifying key and spending private key
 * @requires each valueOut fits in 120 bits
 * @ensures  nullifiers are correctly derived and unique per note
 * @ensures  sum(valueIn) == sum(valueOut) (balance preservation)
 * @ensures  commitmentsOut are correctly computed from npkOut, token, valueOut
 * @ensures  the EdDSA signature covers all public signals, binding the
 *           transaction to the stated parameters
 * @satisfies privacy: token, values, keys, and Merkle paths remain hidden
 * @satisfies soundness: no value is created or destroyed
 * @satisfies double-spend prevention: nullifiers are deterministic
 */
template JoinSplit(nInputs, nOutputs, TreeDepth) {

    // ---------------------------------------------------------------
    // Public signals
    // ---------------------------------------------------------------
    signal input merkleRoot;
    signal input boundParamsHash;
    signal input nullifiers[nInputs];
    signal input commitmentsOut[nOutputs];

    // ---------------------------------------------------------------
    // Private signals
    // ---------------------------------------------------------------
    signal input token;
    signal input publicKey[2];
    signal input signature[3]; // R8x, R8y, S
    signal input randomIn[nInputs];
    signal input valueIn[nInputs];
    signal input pathElements[nInputs][TreeDepth];
    signal input leavesIndices[nInputs];
    signal input nullifyingKey;
    signal input npkOut[nOutputs];
    signal input valueOut[nOutputs];

    // ---------------------------------------------------------------
    // Step 1: Hash all public signals to form the signed message
    //
    // We hash: merkleRoot, boundParamsHash, nullifiers[0..nInputs-1],
    //          commitmentsOut[0..nOutputs-1]
    // Total elements = 2 + nInputs + nOutputs
    // ---------------------------------------------------------------
    var msgLen = 2 + nInputs + nOutputs;
    component messageHasher = Poseidon(msgLen);
    messageHasher.inputs[0] <== merkleRoot;
    messageHasher.inputs[1] <== boundParamsHash;
    for (var i = 0; i < nInputs; i++) {
        messageHasher.inputs[2 + i] <== nullifiers[i];
    }
    for (var i = 0; i < nOutputs; i++) {
        messageHasher.inputs[2 + nInputs + i] <== commitmentsOut[i];
    }

    // ---------------------------------------------------------------
    // Step 2: Verify EdDSA-Poseidon signature over the message
    // ---------------------------------------------------------------
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== publicKey[0];
    sigVerifier.Ay <== publicKey[1];
    sigVerifier.R8x <== signature[0];
    sigVerifier.R8y <== signature[1];
    sigVerifier.S <== signature[2];
    sigVerifier.M <== messageHasher.out;

    // ---------------------------------------------------------------
    // Step 3: Derive Master Public Key
    //   MPK = Poseidon(publicKey[0], publicKey[1], nullifyingKey)
    // ---------------------------------------------------------------
    component mpkHasher = Poseidon(3);
    mpkHasher.inputs[0] <== publicKey[0];
    mpkHasher.inputs[1] <== publicKey[1];
    mpkHasher.inputs[2] <== nullifyingKey;

    signal masterPublicKey;
    masterPublicKey <== mpkHasher.out;

    // ---------------------------------------------------------------
    // Step 4: Process each input note
    //   For each input i:
    //   a) Verify nullifier derivation
    //   b) Compute NPK = Poseidon(MPK, randomIn[i])
    //   c) Compute commitment = Poseidon(NPK, token, valueIn[i])
    //   d) Verify Merkle inclusion of commitment at leavesIndices[i]
    // ---------------------------------------------------------------
    component nullifierChecks[nInputs];
    component npkInHashers[nInputs];
    component commitmentInHashers[nInputs];
    component merkleVerifiers[nInputs];

    for (var i = 0; i < nInputs; i++) {
        // 4a: Nullifier check
        nullifierChecks[i] = NullifierCheck();
        nullifierChecks[i].nullifier <== nullifiers[i];
        nullifierChecks[i].nullifyingKey <== nullifyingKey;
        nullifierChecks[i].leafIndex <== leavesIndices[i];

        // 4b: Note Public Key for input
        npkInHashers[i] = Poseidon(2);
        npkInHashers[i].inputs[0] <== masterPublicKey;
        npkInHashers[i].inputs[1] <== randomIn[i];

        // 4c: Input commitment
        commitmentInHashers[i] = Poseidon(3);
        commitmentInHashers[i].inputs[0] <== npkInHashers[i].out;
        commitmentInHashers[i].inputs[1] <== token;
        commitmentInHashers[i].inputs[2] <== valueIn[i];

        // 4d: Merkle proof verification
        // Compute the Merkle root from the proof regardless of value.
        merkleVerifiers[i] = MerkleProofVerifier(TreeDepth);
        merkleVerifiers[i].leaf <== commitmentInHashers[i].out;
        merkleVerifiers[i].leafIndex <== leavesIndices[i];
        for (var j = 0; j < TreeDepth; j++) {
            merkleVerifiers[i].pathElements[j] <== pathElements[i][j];
        }

        // Skip the Merkle root check when valueIn[i] == 0 (dummy/padding note).
        // A zero-value note cannot create or destroy value, so it is safe to
        // bypass the inclusion proof. This follows the Nocturne pattern:
        //   valueIn[i] * (merkleRoot - computedRoot) === 0
        // If valueIn[i] != 0, the Merkle root must match.
        // If valueIn[i] == 0, the constraint is trivially satisfied.
        valueIn[i] * (merkleRoot - merkleVerifiers[i].computedRoot) === 0;
    }

    // ---------------------------------------------------------------
    // Step 5: Process each output note
    //   For each output j:
    //   a) Range-check valueOut[j] to 120 bits
    //   b) Compute commitment = Poseidon(npkOut[j], token, valueOut[j])
    //   c) Constrain commitment to match the public commitmentsOut[j]
    // ---------------------------------------------------------------
    component valueRangeChecks[nOutputs];
    component commitmentOutHashers[nOutputs];

    for (var i = 0; i < nOutputs; i++) {
        // 5a: Range check — value must fit in 120 bits.
        // Num2Bits constrains the input to be representable in exactly
        // 120 bits, which implies 0 <= valueOut[i] < 2^120.
        valueRangeChecks[i] = Num2Bits(120);
        valueRangeChecks[i].in <== valueOut[i];

        // 5b: Output commitment
        commitmentOutHashers[i] = Poseidon(3);
        commitmentOutHashers[i].inputs[0] <== npkOut[i];
        commitmentOutHashers[i].inputs[1] <== token;
        commitmentOutHashers[i].inputs[2] <== valueOut[i];

        // 5c: Must match public output commitment
        commitmentsOut[i] === commitmentOutHashers[i].out;
    }

    // ---------------------------------------------------------------
    // Step 6: Balance check — sum of inputs must equal sum of outputs
    //
    // We accumulate sums using intermediate signals to keep constraints
    // rank-1 (R1CS compatible).
    // ---------------------------------------------------------------
    signal sumIn[nInputs + 1];
    sumIn[0] <== 0;
    for (var i = 0; i < nInputs; i++) {
        sumIn[i + 1] <== sumIn[i] + valueIn[i];
    }

    signal sumOut[nOutputs + 1];
    sumOut[0] <== 0;
    for (var i = 0; i < nOutputs; i++) {
        sumOut[i + 1] <== sumOut[i] + valueOut[i];
    }

    sumIn[nInputs] === sumOut[nOutputs];
}
