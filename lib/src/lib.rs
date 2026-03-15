use serde::{Deserialize, Serialize};
use sha2::Digest;

pub mod public_values;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Keccak256,
    Keccak512,
}

#[macro_export]
macro_rules! dispatch_hash_algorithm {
    ($algorithm:expr, $f:ident $(, $args:expr)* $(,)?) => {
        match $algorithm {
            $crate::HashAlgorithm::Sha256 => $f::<sha2::Sha256>($($args),*),
            $crate::HashAlgorithm::Sha512 => $f::<sha2::Sha512>($($args),*),
            $crate::HashAlgorithm::Keccak256 => $f::<sha3::Keccak256>($($args),*),
            $crate::HashAlgorithm::Keccak512 => $f::<sha3::Keccak512>($($args),*),
        }
    };
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
    algorithm.hash(message, nonce)
}

fn hash_with<H: Digest>(message: &[u8], nonce: u128) -> Vec<u8> {
    let mut hasher = H::new();
    hasher.update(message);
    hasher.update(&nonce.to_be_bytes());
    hasher.finalize().to_vec()
}

impl HashAlgorithm {
    pub fn hash(self, message: &[u8], nonce: u128) -> Vec<u8> {
        dispatch_hash_algorithm!(self, hash_with, message, nonce)
    }

    pub fn max_difficulty(self) -> u32 {
        match self {
            HashAlgorithm::Sha256 | HashAlgorithm::Keccak256 => 256,
            HashAlgorithm::Sha512 | HashAlgorithm::Keccak512 => 512,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
            HashAlgorithm::Keccak256 => "keccak256",
            HashAlgorithm::Keccak512 => "keccak512",
        }
    }
}
