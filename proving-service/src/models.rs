use serde::{Deserialize, Serialize};

// ============================================================================
// Legacy SBOM validation models (for /prove endpoint)
// ============================================================================

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
    pub components_hash: [u8; 32],
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

// Merkle Tree validation models (for /prove-merkle endpoint)
#[derive(Serialize, Deserialize, Clone)]
pub struct MerkleProof {
    pub purl: String,
    pub value: String,
    pub siblings: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct MerklePublicInputs {
    pub root_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct MerklePublicOutputs {
    pub root_hash: [u8; 32],
    pub is_valid: bool,
    pub verified_count: usize,
}

#[derive(Deserialize)]
pub struct ProveMerkleRequest {
    pub root: String,
    pub merkle_proofs: Vec<MerkleProof>,
}

#[derive(Serialize)]
pub struct ProveMerkleResponse {
    pub proof: String,
    pub root_hash: String,
    pub image_id: Vec<String>,
    pub proof_info: serde_json::Value,
}

// ============================================================================
// Compact Merkle Tree validation models (for /prove-merkle-compact endpoint)
// ============================================================================

#[derive(Serialize, Deserialize, Clone)]
pub struct CompactMerkleProof {
    pub purl: String,
    pub value: String,
    pub leaf_index: String,  // Hex-encoded 32 bytes (SHA-256 of purl)
    pub siblings: Vec<String>,  // Condensed array, only non-default siblings
    pub bitmap: String,  // Hex-encoded 32 bytes (256 bits packed), bit d=1 means sibling provided
}

#[derive(Deserialize)]
pub struct ProveCompactMerkleRequest {
    pub depth: usize,
    pub root: String,
    pub merkle_proofs: Vec<CompactMerkleProof>,
}

#[derive(Serialize)]
pub struct ProveCompactMerkleResponse {
    pub proof: String,
    pub root_hash: String,
    pub image_id: Vec<String>,
    pub proof_info: serde_json::Value,
}

