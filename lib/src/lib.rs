use sha2::{Digest, Sha256};

pub mod public_values;

pub fn check_hash(hash: &[u8], difficulty: u32) -> bool {
    // difficulty check
    assert!(
        difficulty <= (hash.len() * 8) as u32,
        "Difficulty is too big"
    );

    let diff_bytes = (difficulty / 8) as usize;
    let remaining_bits = difficulty % 8;

    // check each byte
    if !hash[..diff_bytes].iter().all(|&b| b == 0) {
        return false;
    }

    // Check the last byte
    if remaining_bits > 0 {
        let target_byte = hash[diff_bytes];
        let mask = 0xFFu8 << (8 - remaining_bits);
        if target_byte & mask != 0 {
            return false;
        }
    }

    true
}

pub fn calc_hash(message: &[u8], nonce: u128) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&message);
    hasher.update(&nonce.to_be_bytes());
    hasher.finalize().to_vec()
}
