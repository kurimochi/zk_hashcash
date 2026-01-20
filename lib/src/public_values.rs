use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct HashCashPublicValues {
    pub message: Vec<u8>,
    pub difficulty: u32,
    pub is_valid: bool,
}
