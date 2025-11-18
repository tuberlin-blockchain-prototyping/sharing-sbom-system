use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

// Import shared merkle utilities from common crate
use sbom_common::{hash_value, hash_pair, compute_purl_hash, hex_to_bytes32};

#[derive(Serialize, Deserialize, Clone)]
struct BannedListInfo {
    source: String,
    entry_count: usize,
    hash: String,
}

#[derive(Serialize, Deserialize)]
struct PublicInputs {
    sbom_hash: [u8; 32],
    banned_list: Vec<String>,
    banned_list_info: BannedListInfo,
}

#[derive(Serialize, Deserialize)]
struct PublicOutputs {
    sbom_hash: [u8; 32],
    components_hash: [u8; 32],
    is_valid: bool,
    banned_list_info: BannedListInfo,
}

#[derive(Deserialize)]
struct CycloneDXComponent {
    name: Option<String>,
    version: Option<String>,
    purl: Option<String>,
}

#[derive(Deserialize)]
struct CycloneDXSBOM {
    components: Option<Vec<CycloneDXComponent>>,
}

// ============================================================================
// New Merkle Tree validation structures
// ============================================================================

#[derive(Serialize, Deserialize, Clone)]
struct MerkleProof {
    purl: String,
    value: String,
    siblings: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct MerklePublicInputs {
    root_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct MerklePublicOutputs {
    root_hash: [u8; 32],
    is_valid: bool,
    verified_count: usize,
}

fn main() {
    // Try to determine which validation path to take by reading the first input
    let first_input: String = env::read();

    if first_input.contains("\"purl\"") && first_input.contains("\"siblings\"") {
        run_merkle_validation(first_input);
    } else {
        run_sbom_validation(first_input);
    }
}

fn run_sbom_validation(sbom_json: String) {
    let components_json: String = env::read();
    let public_inputs: PublicInputs = env::read();

    let computed_sbom_hash = compute_hash(&sbom_json);
    if computed_sbom_hash != public_inputs.sbom_hash {
        commit_result(&public_inputs.sbom_hash, &[0u8; 32], false, &public_inputs.banned_list_info);
        return;
    }

    let sbom: CycloneDXSBOM = match serde_json::from_str(&sbom_json) {
        Ok(s) => s,
        Err(_) => {
            commit_result(&public_inputs.sbom_hash, &[0u8; 32], false, &public_inputs.banned_list_info);
            return;
        }
    };

    let extracted_components = extract_components_from_sbom(&sbom);
    let extracted_components_json = serde_json::to_string(&extracted_components)
        .unwrap_or_else(|_| "{}".to_string());
    let computed_components_hash = compute_hash(&extracted_components_json);

    let pre_extracted_hash = compute_hash(&components_json);
    if computed_components_hash != pre_extracted_hash {
        commit_result(&public_inputs.sbom_hash, &computed_components_hash, false, &public_inputs.banned_list_info);
        return;
    }

    let is_valid = check_components(&sbom, &public_inputs.banned_list);
    commit_result(&public_inputs.sbom_hash, &computed_components_hash, is_valid, &public_inputs.banned_list_info);
}

// ============================================================================
// New Merkle Tree validation path
// ============================================================================

fn run_merkle_validation(proofs_json: String) {
    let public_inputs: MerklePublicInputs = env::read();

    // Parse the merkle proofs
    let proofs: Vec<MerkleProof> = match serde_json::from_str(&proofs_json) {
        Ok(p) => p,
        Err(_) => {
            commit_merkle_result(&public_inputs.root_hash, false, 0);
            return;
        }
    };

    // Validate all non-membership proofs
    let (is_valid, verified_count) = validate_non_membership_proofs(&proofs, &public_inputs.root_hash);

    commit_merkle_result(&public_inputs.root_hash, is_valid, verified_count);
}

fn compute_hash(data: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hasher.finalize().into()
}

fn check_components(sbom: &CycloneDXSBOM, banned_list: &[String]) -> bool {
    let components = sbom.components.as_deref().unwrap_or(&[]);
    let banned_set: HashSet<&str> = banned_list.iter().map(|s| s.as_str()).collect();

    for component in components {
        let identifiers = extract_identifiers(component);
        if identifiers.iter().any(|id| banned_set.contains(id.as_str())) {
            return false;
        }
    }

    true
}

fn extract_identifiers(component: &CycloneDXComponent) -> Vec<String> {
    let mut identifiers = Vec::new();

    if let Some(name) = &component.name {
        identifiers.push(name.clone());
    }

    if let (Some(name), Some(version)) = (&component.name, &component.version) {
        identifiers.push(format!("{}:{}", name, version));
    }

    if let Some(purl) = &component.purl {
        identifiers.push(purl.clone());
    }

    identifiers
}

fn extract_components_from_sbom(sbom: &CycloneDXSBOM) -> serde_json::Value {
    let components = sbom.components.as_deref().unwrap_or(&[]);
    let minimal_components: Vec<serde_json::Value> = components
        .iter()
        .map(|comp| {
            let mut minimal = serde_json::json!({});
            if let Some(name) = &comp.name {
                minimal["name"] = serde_json::Value::String(name.clone());
            }
            if let Some(version) = &comp.version {
                minimal["version"] = serde_json::Value::String(version.clone());
            }
            if let Some(purl) = &comp.purl {
                minimal["purl"] = serde_json::Value::String(purl.clone());
            }
            minimal
        })
        .collect();
    serde_json::json!({ "components": minimal_components })
}

fn commit_result(sbom_hash: &[u8; 32], components_hash: &[u8; 32], is_valid: bool, banned_list_info: &BannedListInfo) {
    let output = PublicOutputs {
        sbom_hash: *sbom_hash,
        components_hash: *components_hash,
        is_valid,
        banned_list_info: banned_list_info.clone(),
    };
    env::commit(&output);
}


/// Validate non-membership proofs against the sparse merkle tree
/// Each proof must have value=0 and verify against the root hash
fn validate_non_membership_proofs(
    proofs: &[MerkleProof],
    root_hash: &[u8; 32],
) -> (bool, usize) {
    let mut verified_count = 0;

    for proof in proofs {
        // Assert non-membership - value must be 0
        if proof.value != "0" {
            return (false, verified_count);
        }

        // Siblings must be exactly 256 for a depth-256 SMT
        if proof.siblings.len() != 256 {
            return (false, verified_count);
        }

        // Calculate leaf hash by hashing the value
        let mut current_hash = hash_value(&proof.value);

        // Compute the purl_hash to determine the path
        let purl_hash = compute_purl_hash(&proof.purl);

        // Climb the tree for 256 levels
        for i in 0..256 {
            let sibling_hash = match hex_to_bytes32(&proof.siblings[i]) {
                Ok(h) => h,
                Err(_) => return (false, verified_count),
            };

            // Determine the path bit for this level.
            // Interpret the 32-byte SHA-256 as a big-endian integer
            // (this is how we do it in the smt generation tool and it has to match)
            let byte_index = 31 - (i / 8);
            let bit_index = i % 8;
            let path_bit = (purl_hash[byte_index] >> bit_index) & 1;

            current_hash = if path_bit == 0 {
                // current_hash is left child
                hash_pair(&current_hash, &sibling_hash)
            } else {
                // current_hash is right child
                hash_pair(&sibling_hash, &current_hash)
            };
        }

        // computed root must match expected root
        if current_hash != *root_hash {
            return (false, verified_count);
        }

        verified_count += 1;
    }

    (true, verified_count)
}


fn commit_merkle_result(
    root_hash: &[u8; 32],
    is_valid: bool,
    verified_count: usize,
) {
    let output = MerklePublicOutputs {
        root_hash: *root_hash,
        is_valid,
        verified_count,
    };
    env::commit(&output);
}
