use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VerifyProofRequest {
    pub timestamp: u64,
    pub root_hash: String,
    pub banned_list_hash: String,
    pub compliant: bool,
    pub image_id: Vec<String>,
    pub proof: String,
    pub generation_duration_ms: Option<u64>,
}

impl VerifyProofRequest {
    /// Validate the request structure
    pub fn validate(&self) -> Result<(), String> {
        if self.proof.is_empty() {
            return Err("Proof cannot be empty".to_string());
        }
        if self.image_id.is_empty() {
            return Err("Image ID cannot be empty".to_string());
        }
        if self.image_id.len() != 8 {
            return Err(format!(
                "Image ID must have 8 values, got {}",
                self.image_id.len()
            ));
        }
        if self.root_hash.is_empty() {
            return Err("Root hash cannot be empty".to_string());
        }
        if self.banned_list_hash.is_empty() {
            return Err("Banned list hash cannot be empty".to_string());
        }
        if self.timestamp == 0 {
            return Err("Timestamp cannot be zero".to_string());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MerklePublicOutputs {
    pub timestamp: u64,
    pub root_hash: [u8; 32],
    pub banned_list_hash: [u8; 32],
    pub compliant: bool,
}

#[derive(Serialize, Debug)]
pub struct VerifyProofResponse {
    pub proof_verified: bool,
    #[serde(rename = "timestamp_proof_created_at")]
    pub timestamp: u64,
    pub root_hash: String,
    pub banned_list_hash: String,
    pub compliant: bool,
    pub image_id: Vec<String>,
    pub generation_duration_ms: Option<u64>,
}
