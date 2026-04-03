pragma circom 2.0.6;

include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * NullifierCheck
 *
 * Verifies that a nullifier was correctly derived from the nullifying key
 * and the leaf index. This binds each UTXO to a unique, deterministic
 * nullifier that can be published on-chain to prevent double-spending
 * without revealing which note was consumed.
 *
 * @requires nullifyingKey is a valid field element known only to the spender
 * @requires leafIndex corresponds to the note's position in the commitment tree
 * @ensures  nullifier === Poseidon(nullifyingKey, leafIndex)
 * @satisfies double-spend prevention: each (nullifyingKey, leafIndex) pair
 *            produces exactly one nullifier
 */
template NullifierCheck() {
    signal input nullifier;
    signal input nullifyingKey;
    signal input leafIndex;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== nullifyingKey;
    hasher.inputs[1] <== leafIndex;

    nullifier === hasher.out;
}
