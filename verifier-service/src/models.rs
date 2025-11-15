use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct BannedListInfo {
    pub source: String,
    pub entry_count: usize,
    pub hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct PublicOutputs {
    pub sbom_hash: [u8; 32],
    pub is_valid: bool,
    pub banned_list_info: BannedListInfo,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub proof: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub sbom_hash: String,
    pub is_valid: bool,
    pub banned_list_info: Option<BannedListInfo>,
}

