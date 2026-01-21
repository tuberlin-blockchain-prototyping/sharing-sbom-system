use risc0_zkvm::guest::env;
use risc0_zkvm::guest::sha::Impl as Sha256Impl;
use risc0_zkvm::guest::sha::rust_crypto::Sha256;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use sbom_common::{DEFAULTS, bitmap_bit, compute_purl_hash, hash_pair, hash_value, hex_to_bytes32, path_bit};

#[derive(Serialize, Deserialize, Clone)]
struct CompactMerkleProof {
    purl: String,
    value: String,
    leaf_index: String,
    siblings: Vec<String>,
    bitmap: String,
}

#[derive(Serialize, Deserialize)]
struct MerklePublicInputs {
    root_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct MerklePublicOutputs {
    timestamp: u64,
    root_hash: [u8; 32],
    banned_list_hash: [u8; 32],
    compliant: bool,
}

fn main() {
    let proofs_json: String = env::read();
    let public_inputs: MerklePublicInputs = env::read();
    let timestamp: u64 = env::read();

    let proofs: Vec<CompactMerkleProof> = match serde_json::from_str(&proofs_json) {
        Ok(p) => p,
        Err(_) => {
            // Empty banned list for invalid JSON
            let banned_list_hash = compute_banned_list_hash(&[]);
            commit_result(
                &public_inputs.root_hash,
                &banned_list_hash,
                false,
                timestamp,
            );
            return;
        }
    };

    // Collect purls as string slices to avoid cloning
    let banned_list: Vec<&str> = proofs.iter().map(|p| p.purl.as_str()).collect();
    let banned_list_hash = compute_banned_list_hash(&banned_list);

    let compliant = validate_proofs(&proofs, &public_inputs.root_hash);
    commit_result(
        &public_inputs.root_hash,
        &banned_list_hash,
        compliant,
        timestamp,
    );
}

fn compute_banned_list_hash(banned_list: &[&str]) -> [u8; 32] {
    let json = serde_json::to_string(&banned_list).unwrap_or_else(|_| "[]".to_string());
    let mut hasher = Sha256::<Sha256Impl>::new();
    hasher.update(json.as_bytes());
    hasher.finalize().into()
}

fn validate_proofs(proofs: &[CompactMerkleProof], root_hash: &[u8; 32]) -> bool {
    for proof in proofs {
        // Early exit: check value is "0" (non-membership proof)
        if proof.value != "0" {
            return false;
        }

        // Parse bitmap and leaf_index once, outside the hot loop
        let bitmap = match hex_to_bytes32(&proof.bitmap) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let leaf_index = match hex_to_bytes32(&proof.leaf_index) {
            Ok(li) => li,
            Err(_) => return false,
        };

        // This binds the proof to the claimed purl, preventing attacks where
        // an attacker provides a valid proof for a different position
        let expected_leaf_index = compute_purl_hash(&proof.purl);
        if leaf_index != expected_leaf_index {
            return false;
        }

        // Pre-parse all sibling hashes to avoid repeated hex parsing in the loop
        let mut siblings_parsed: Vec<[u8; 32]> = Vec::with_capacity(proof.siblings.len());
        for hex in &proof.siblings {
            match hex_to_bytes32(hex) {
                Ok(h) => siblings_parsed.push(h),
                Err(_) => return false,
            }
        }

        // Start with leaf hash (hash of value "0")
        let mut current = hash_value(&proof.value);
        let mut sibling_idx = 0;

        // Traverse tree from leaf to root (256 levels for depth-256 tree)
        for d in 0..256 {
            // Get sibling: either from provided siblings or from DEFAULTS
            let sibling = if bitmap_bit(&bitmap, d) == 1 {
                if sibling_idx >= siblings_parsed.len() {
                    return false;
                }
                let s = siblings_parsed[sibling_idx];
                sibling_idx += 1;
                s
            } else {
                DEFAULTS[d]
            };

            // Determine if current node is left (0) or right (1) child
            let direction = path_bit(&leaf_index, d);
            current = if direction == 0 {
                hash_pair(&current, &sibling)
            } else {
                hash_pair(&sibling, &current)
            };
        }

        // Final hash must match root
        if current != *root_hash {
            return false;
        }
    }

    true
}

fn commit_result(
    root_hash: &[u8; 32],
    banned_list_hash: &[u8; 32],
    compliant: bool,
    timestamp: u64,
) {
    env::commit(&MerklePublicOutputs {
        root_hash: *root_hash,
        banned_list_hash: *banned_list_hash,
        compliant,
        timestamp,
    });
}
