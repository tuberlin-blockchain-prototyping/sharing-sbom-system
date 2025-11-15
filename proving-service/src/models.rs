use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct BannedListInfo {
    pub source: String,
    pub entry_count: usize,
    pub hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct PublicInputs {
    pub sbom_hash: [u8; 32],
    pub banned_list: Vec<String>,
    pub banned_list_info: BannedListInfo,
}

#[derive(Serialize, Deserialize)]
pub struct PublicOutputs {
    pub sbom_hash: [u8; 32],
    pub is_valid: bool,
    pub banned_list_info: BannedListInfo,
}

#[derive(Deserialize)]
pub struct ProveRequest {
    pub sbom: serde_json::Value,
    pub banned_list: Vec<String>,
}

#[derive(Serialize)]
pub struct ProveResponse {
    pub proof: String,
    pub sbom_hash: String,
    pub image_id: Vec<String>,
    pub proof_info: serde_json::Value,
}

