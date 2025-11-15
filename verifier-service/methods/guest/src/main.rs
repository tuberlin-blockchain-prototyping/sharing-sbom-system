use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

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

fn main() {
    let sbom_json: String = env::read();
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
