use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

fn main() {
    let sbom_json: String = env::read();
    let public_inputs: PublicInputs = env::read();

    let computed_hash = compute_hash(&sbom_json);
    if computed_hash != public_inputs.sbom_hash {
        commit_result(&public_inputs.sbom_hash, false, &public_inputs.banned_list_info);
        return;
    }

    let sbom: CycloneDXSBOM = match serde_json::from_str(&sbom_json) {
        Ok(s) => s,
        Err(_) => {
            commit_result(&public_inputs.sbom_hash, false, &public_inputs.banned_list_info);
            return;
        }
    };

    let is_valid = check_components(&sbom, &public_inputs.banned_list);
    commit_result(&public_inputs.sbom_hash, is_valid, &public_inputs.banned_list_info);
}

fn compute_hash(data: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hasher.finalize().into()
}

fn check_components(sbom: &CycloneDXSBOM, banned_list: &[String]) -> bool {
    let components = sbom.components.as_deref().unwrap_or(&[]);

    for component in components {
        let identifiers = extract_identifiers(component);
        if identifiers.iter().any(|id| banned_list.contains(id)) {
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

fn commit_result(sbom_hash: &[u8; 32], is_valid: bool, banned_list_info: &BannedListInfo) {
    let output = PublicOutputs {
        sbom_hash: *sbom_hash,
        is_valid,
        banned_list_info: banned_list_info.clone(),
    };
    env::commit(&output);
}
