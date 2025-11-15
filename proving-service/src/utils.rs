use sha2::{Digest, Sha256};
use serde_json::Value;

pub fn compute_hash(data: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hasher.finalize().into()
}

pub fn compute_banned_list_hash(banned_list: &[String]) -> String {
    let banned_list_str = banned_list.join("\n");
    let mut hasher = Sha256::new();
    hasher.update(banned_list_str.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn extract_components_json(sbom: &Value) -> Result<String, String> {
    let components = sbom
        .get("components")
        .and_then(|c| c.as_array())
        .ok_or_else(|| "No components array found in SBOM".to_string())?;

    let minimal_components: Vec<Value> = components
        .iter()
        .map(|comp| {
            let mut minimal = serde_json::json!({});
            if let Some(name) = comp.get("name") {
                minimal["name"] = name.clone();
            }
            if let Some(version) = comp.get("version") {
                minimal["version"] = version.clone();
            }
            if let Some(purl) = comp.get("purl") {
                minimal["purl"] = purl.clone();
            }
            minimal
        })
        .collect();

    let components_json = serde_json::json!({
        "components": minimal_components
    });

    serde_json::to_string(&components_json)
        .map_err(|e| format!("Failed to serialize components: {}", e))
}

