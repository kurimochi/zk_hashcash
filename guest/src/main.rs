#![no_main]
sp1_zkvm::entrypoint!(main);

use hashcash_lib::{HashAlgorithm, calc_hash, check_hash, public_values::HashCashPublicValues};

fn main() {
    // inputs
    let message = sp1_zkvm::io::read::<Vec<u8>>();
    let nonce = sp1_zkvm::io::read::<u128>();
    let difficulty = sp1_zkvm::io::read::<u32>();
    let hash_algorithm = sp1_zkvm::io::read::<HashAlgorithm>();

    let hash = calc_hash(&message, nonce, hash_algorithm);

    let is_valid = check_hash(&hash, difficulty);
    assert!(is_valid, "This nonce is invalid");

    // commit
    let public_values = HashCashPublicValues {
        message,
        difficulty,
        hash_algorithm,
        is_valid,
    };
    sp1_zkvm::io::commit(&public_values);
}
