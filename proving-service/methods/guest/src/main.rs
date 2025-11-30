use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use sbom_common::{DEFAULTS, bitmap_bit, hash_pair, hash_value, hex_to_bytes32, path_bit};

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
            let banned_list: Vec<String> = vec![];
            let banned_list_hash = compute_banned_list_hash(&banned_list);
            commit_result(
                &public_inputs.root_hash,
                &banned_list_hash,
                false,
                timestamp,
            );
            return;
        }
    };

    let banned_list: Vec<String> = proofs.iter().map(|p| p.purl.clone()).collect();
    let banned_list_hash = compute_banned_list_hash(&banned_list);

    let compliant = validate_proofs(&proofs, &public_inputs.root_hash);
    commit_result(
        &public_inputs.root_hash,
        &banned_list_hash,
        compliant,
        timestamp,
    );
}

fn compute_banned_list_hash(banned_list: &[String]) -> [u8; 32] {
    let json = serde_json::to_string(banned_list).unwrap_or_else(|_| "[]".to_string());
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hasher.finalize().into()
}

fn validate_proofs(proofs: &[CompactMerkleProof], root_hash: &[u8; 32]) -> bool {
    for proof in proofs {
        if proof.value != "0" {
            return false;
        }

        let bitmap = match hex_to_bytes32(&proof.bitmap) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let leaf_index = match hex_to_bytes32(&proof.leaf_index) {
            Ok(li) => li,
            Err(_) => return false,
        };

        let mut current = hash_value(&proof.value);
        let mut siblings_iter = proof.siblings.iter();

        for d in 0..256 {
            let sibling = if bitmap_bit(&bitmap, d) == 1 {
                match siblings_iter.next() {
                    Some(hex) => match hex_to_bytes32(hex) {
                        Ok(h) => h,
                        Err(_) => return false,
                    },
                    None => return false,
                }
            } else {
                DEFAULTS[d]
            };

            let direction = path_bit(&leaf_index, d);
            current = if direction == 0 {
                hash_pair(&current, &sibling)
            } else {
                hash_pair(&sibling, &current)
            };
        }

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
