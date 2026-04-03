pragma circom 2.0.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/switcher.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * MerkleProofVerifier
 *
 * Binary Poseidon Merkle tree inclusion proof verifier. Given a leaf,
 * the leaf's index in the tree, and a path of sibling hashes, this
 * template recomputes the root and constrains it to equal the expected
 * merkleRoot.
 *
 * The leafIndex is decomposed into bits; bit i tells whether the
 * current node sits on the left (0) or right (1) at level i of the
 * tree. A Switcher gates the two Poseidon inputs accordingly.
 *
 * @param depth  The depth of the Merkle tree (number of levels)
 *
 * @requires leaf is a valid Poseidon commitment in the field
 * @requires pathElements[i] are the sibling hashes along the path
 * @requires leafIndex < 2^depth
 * @ensures  the recomputed root equals merkleRoot
 * @satisfies membership proof: leaf is at position leafIndex in the
 *            tree whose root is merkleRoot
 */
template MerkleProofVerifier(depth) {
    signal input leaf;
    signal input leafIndex;
    signal input pathElements[depth];
    // The recomputed root is exposed as an output so the caller can
    // conditionally enforce the equality (e.g. skip for zero-value dummy notes).
    signal output computedRoot;

    // Decompose leafIndex into bits to determine left/right placement
    // at each tree level.
    component indexBits = Num2Bits(depth);
    indexBits.in <== leafIndex;

    // At each level, use a Switcher to order (current, sibling) based
    // on the index bit, then hash with Poseidon(2).
    component switchers[depth];
    component hashers[depth];

    signal levelHashes[depth + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        switchers[i] = Switcher();
        switchers[i].sel <== indexBits.out[i];
        switchers[i].L <== levelHashes[i];
        switchers[i].R <== pathElements[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        levelHashes[i + 1] <== hashers[i].out;
    }

    computedRoot <== levelHashes[depth];
}
