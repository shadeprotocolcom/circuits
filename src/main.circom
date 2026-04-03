pragma circom 2.0.6;

include "./joinsplit.circom";

/**
 * Main component for the Shade Protocol MVP.
 *
 * Instantiates a JoinSplit circuit with:
 *   nInputs   = 2   (consume up to 2 notes per transaction)
 *   nOutputs  = 2   (produce up to 2 notes: recipient + change)
 *   TreeDepth = 16  (supports up to 2^16 = 65536 leaves)
 *
 * Public signals (declared explicitly):
 *   - merkleRoot         : current root of the commitment Merkle tree
 *   - boundParamsHash    : hash binding ciphertext + adapter params
 *   - nullifiers[2]      : nullifiers for the two consumed notes
 *   - commitmentsOut[2]  : commitments for the two new notes
 */
component main {public [merkleRoot, boundParamsHash, nullifiers, commitmentsOut]} = JoinSplit(2, 2, 16);
