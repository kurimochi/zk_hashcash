use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use sha3::{Keccak256, Keccak512};

pub mod public_values;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Keccak256,
    Keccak512,
}

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

pub fn calc_hash(message: &[u8], nonce: u128, algorithm: HashAlgorithm) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(message);
            hasher.update(&nonce.to_be_bytes());
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(message);
            hasher.update(&nonce.to_be_bytes());
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Keccak256 => {
            let mut hasher = Keccak256::new();
            hasher.update(message);
            hasher.update(&nonce.to_be_bytes());
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Keccak512 => {
            let mut hasher = Keccak512::new();
            hasher.update(message);
            hasher.update(&nonce.to_be_bytes());
            hasher.finalize().to_vec()
        }
    }
}
