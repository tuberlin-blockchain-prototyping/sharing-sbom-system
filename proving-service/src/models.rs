use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct CompactMerkleProof {
    pub purl: String,
    pub value: String,
    pub leaf_index: String,
    pub siblings: Vec<String>,
    pub bitmap: String,
}

#[derive(Deserialize)]
pub struct ProveCompactMerkleRequest {
    pub depth: usize,
    pub root: String,
    pub merkle_proofs: Vec<CompactMerkleProof>,
}

#[derive(Serialize, Deserialize)]
pub struct MerklePublicInputs {
    pub root_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct MerklePublicOutputs {
    pub root_hash: [u8; 32],
    pub banned_list_hash: [u8; 32],
    pub compliant: bool,
}
