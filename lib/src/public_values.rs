use serde::{Deserialize, Serialize};

use crate::HashAlgorithm;

#[derive(Deserialize, Serialize)]
pub struct HashCashPublicValues {
    pub message: Vec<u8>,
    pub difficulty: u32,
    pub hash_algorithm: HashAlgorithm,
    pub is_valid: bool,
}
