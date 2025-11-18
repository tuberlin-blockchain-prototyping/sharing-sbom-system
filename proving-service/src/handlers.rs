use actix_web::{web, HttpResponse, Result as ActixResult};
use base64::{Engine as _, engine::general_purpose};
use methods::{SBOM_VALIDATOR_ELF, SBOM_VALIDATOR_ID};
use risc0_zkvm::{default_prover, serde::to_vec, ExecutorEnv};

use crate::models::{
    BannedListInfo, ProveRequest, ProveResponse, PublicInputs, PublicOutputs,
    ProveMerkleRequest, ProveMerkleResponse, MerklePublicInputs, MerklePublicOutputs,
};
use crate::utils::{
    compute_banned_list_hash, compute_hash, extract_components_json, hex_to_bytes32,
    merkle_compute_purl_hash, merkle_hash_pair, merkle_hash_value,
};

pub async fn health() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "healthy"})))
}

// SBOM validation endpoint
pub async fn prove(req: web::Json<ProveRequest>) -> ActixResult<HttpResponse> {
    tracing::info!("Received SBOM prove request");

    let sbom_json = serde_json::to_string(&req.sbom)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid SBOM JSON: {}", e)))?;

    let banned_list = &req.banned_list;
    let sbom_hash = compute_hash(&sbom_json);

    let components_json = extract_components_json(&req.sbom)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Failed to extract components: {}", e)))?;
    
    let components_size = components_json.len();
    let full_size = sbom_json.len();
    tracing::info!(
        "Pre-extracted components: {} bytes (reduced from {} bytes, {:.1}% reduction)",
        components_size,
        full_size,
        100.0 * (1.0 - components_size as f64 / full_size as f64)
    );

    let banned_list_info = BannedListInfo {
        source: "CVE Database".to_string(),
        entry_count: banned_list.len(),
        hash: compute_banned_list_hash(banned_list),
    };

    let public_inputs = PublicInputs {
        sbom_hash,
        banned_list: banned_list.clone(),
        banned_list_info: banned_list_info.clone(),
    };

    let env = ExecutorEnv::builder()
        .write(&sbom_json)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to write SBOM: {}", e)))?
        .write(&components_json)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to write components: {}", e)))?
        .write(&public_inputs)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to write inputs: {}", e)))?
        .build()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to build env: {}", e)))?;

    tracing::info!("Generating proof for SBOM hash: {}", hex::encode(sbom_hash));

    let prover = default_prover();
    let receipt = prover
        .prove(env, SBOM_VALIDATOR_ELF)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Proof generation failed: {}", e)))?
        .receipt;

    let output: PublicOutputs = receipt
        .journal
        .decode()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to decode output: {}", e)))?;

    tracing::info!("Proof generated successfully. Valid: {}", output.is_valid);

    receipt
        .verify(SBOM_VALIDATOR_ID)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Receipt verification failed: {}", e)))?;

    let receipt_bytes: Vec<u8> = to_vec(&receipt)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to serialize receipt: {}", e)))?
        .iter()
        .flat_map(|&x| x.to_le_bytes())
        .collect();

    let proof_base64 = general_purpose::STANDARD.encode(&receipt_bytes);
    let proof_info = serde_json::json!({
        "sbom_hash": hex::encode(output.sbom_hash),
        "is_valid": output.is_valid,
        "banned_list": banned_list,
        "banned_list_info": {
            "source": output.banned_list_info.source,
            "entry_count": output.banned_list_info.entry_count,
            "hash": output.banned_list_info.hash,
        },
        "image_id": SBOM_VALIDATOR_ID.iter().map(|&x| x.to_string()).collect::<Vec<_>>(),
    });

    let response = ProveResponse {
        proof: proof_base64,
        sbom_hash: hex::encode(sbom_hash),
        image_id: SBOM_VALIDATOR_ID.iter().map(|&x| x.to_string()).collect(),
        proof_info,
    };

    Ok(HttpResponse::Ok().json(response))
}

// New Merkle Tree validation endpoint
pub async fn prove_merkle(req: web::Json<ProveMerkleRequest>) -> ActixResult<HttpResponse> {
    tracing::info!("Received merkle prove request");

    if req.merkle_proofs.is_empty() {
        return Err(actix_web::error::ErrorBadRequest("At least one merkle proof is required"));
    }

    let root_hash = hex_to_bytes32(&req.root)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid root hash: {}", e)))?;

    // Validate that all proofs have exactly 256 siblings (depth 256 tree)
    for (i, proof) in req.merkle_proofs.iter().enumerate() {
        if proof.siblings.len() != 256 {
            return Err(actix_web::error::ErrorBadRequest(
                format!("Proof {} has {} siblings, expected 256", i, proof.siblings.len())
            ));
        }

        // Validate that all siblings are valid hex strings
        for (j, sibling) in proof.siblings.iter().enumerate() {
            hex_to_bytes32(sibling)
                .map_err(|e| actix_web::error::ErrorBadRequest(
                    format!("Invalid sibling at proof {} sibling {}: {}", i, j, e)
                ))?;
        }
    }

    let public_inputs = MerklePublicInputs {
        root_hash,
    };

    let proofs_json = serde_json::to_string(&req.merkle_proofs)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid proofs JSON: {}", e)))?;

    tracing::info!(
        "Processing {} non-membership proofs for root: {}",
        req.merkle_proofs.len(),
        req.root
    );

    let env = ExecutorEnv::builder()
        .write(&proofs_json)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to write proofs: {}", e)))?
        .write(&public_inputs)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to write inputs: {}", e)))?
        .build()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to build env: {}", e)))?;

    tracing::info!("Generating proof for merkle tree root: {}", req.root);

    let prover = default_prover();
    let receipt = prover
        .prove(env, SBOM_VALIDATOR_ELF)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Proof generation failed: {}", e)))?
        .receipt;

    let output: MerklePublicOutputs = receipt
        .journal
        .decode()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to decode output: {}", e)))?;

    tracing::info!("Proof generated successfully. Valid: {}, Verified: {}/{}",
        output.is_valid, output.verified_count, req.merkle_proofs.len());

    receipt
        .verify(SBOM_VALIDATOR_ID)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Receipt verification failed: {}", e)))?;

    let receipt_bytes: Vec<u8> = to_vec(&receipt)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to serialize receipt: {}", e)))?
        .iter()
        .flat_map(|&x| x.to_le_bytes())
        .collect();

    let proof_base64 = general_purpose::STANDARD.encode(&receipt_bytes);
    let proof_info = serde_json::json!({
        "root_hash": hex::encode(output.root_hash),
        "is_valid": output.is_valid,
        "verified_count": output.verified_count,
        "total_proofs": req.merkle_proofs.len(),
        "image_id": SBOM_VALIDATOR_ID.iter().map(|&x| x.to_string()).collect::<Vec<_>>(),
    });

    let response = ProveMerkleResponse {
        proof: proof_base64,
        root_hash: hex::encode(root_hash),
        image_id: SBOM_VALIDATOR_ID.iter().map(|&x| x.to_string()).collect(),
        proof_info,
    };

    Ok(HttpResponse::Ok().json(response))
}

// Debug endpoint: host-side merkle verification (no ZK, just for verifying correctness during development)
#[derive(serde::Deserialize)]
pub struct DebugVerifyMerkleRequest {
    pub root: String,
    pub purl: String,
    pub value: String,
    pub siblings: Vec<String>,
}

pub async fn debug_verify_merkle(body: web::Json<serde_json::Value>) -> ActixResult<HttpResponse> {
    let value = body.into_inner();

    // Try to parse as single-proof first
    if let Ok(req) = serde_json::from_value::<DebugVerifyMerkleRequest>(value.clone()) {
        let result = verify_one(&req.root, &req.purl, &req.value, &req.siblings)?;
        return Ok(HttpResponse::Ok().json(result));
    }

    // Try to parse as batch (same shape as /prove-merkle)
    let batch: ProveMerkleRequest = serde_json::from_value(value)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!(
            "Json deserialize error: {}. Expected either single-proof {{root,purl,value,siblings}} or batch {{root,merkle_proofs:[...]}}.",
            e
        )))?;

    let root = batch.root.clone();
    if batch.merkle_proofs.is_empty() {
        return Err(actix_web::error::ErrorBadRequest("merkle_proofs must not be empty"));
    }

    // Verify each proof and collect results
    let mut results = Vec::with_capacity(batch.merkle_proofs.len());
    for (idx, mp) in batch.merkle_proofs.iter().enumerate() {
        match verify_one(&root, &mp.purl, &mp.value, &mp.siblings) {
            Ok(mut r) => {
                r["index"] = serde_json::json!(idx);
                r["purl"] = serde_json::json!(&mp.purl);
                results.push(r);
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "index": idx,
                    "purl": mp.purl,
                    "error": e.to_string(),
                }));
            }
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "root": root,
        "count": results.len(),
        "results": results,
        "note": "This mirrors the guest hashing and path-bit order: SHA256 for values and purl; bits are consumed as if the hash is a big-endian integer: iterate bytes 31..0 and, within each byte, bits 0..7 (LSB-first). Value is decimal, encoded as 32-byte big-endian before hashing."
    })))
}

fn verify_one(root_hex: &str, purl: &str, value: &str, siblings: &[String]) -> Result<serde_json::Value, actix_web::Error> {
    let root = hex_to_bytes32(root_hex)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid root: {}", e)))?;

    if siblings.len() != 256 {
        return Err(actix_web::error::ErrorBadRequest(format!("Expected 256 siblings, got {}", siblings.len())));
    }

    let mut current = merkle_hash_value(value);
    let path = merkle_compute_purl_hash(purl);

    for i in 0..256 {
        let sib = hex_to_bytes32(&siblings[i])
            .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid sibling at {}: {}", i, e)))?;
        // Interpret the 32-byte SHA-256 as a big-endian integer
        let byte_index = 31 - (i / 8);
        let bit_index = i % 8;
        let bit = (path[byte_index] >> bit_index) & 1;
        current = if bit == 0 { merkle_hash_pair(&current, &sib) } else { merkle_hash_pair(&sib, &current) };
    }

    let computed_root_hex = hex::encode(current);
    let matches = current == root;

    Ok(serde_json::json!({
        "computed_root": computed_root_hex,
        "expected_root": root_hex,
        "matches": matches,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_verify_sample_small_smt() {
        // Load the sample request file embedded at compile time
        let data = include_str!("../small-smt-request.json");
        let v: serde_json::Value = serde_json::from_str(data).expect("valid JSON");
        let root = v.get("root").and_then(|x| x.as_str()).expect("root str");
        let proofs = v.get("merkle_proofs").and_then(|x| x.as_array()).expect("array");
        let first = &proofs[0];
        let purl = first.get("purl").and_then(|x| x.as_str()).unwrap();
        let value = first.get("value").and_then(|x| x.as_str()).unwrap();
        let siblings: Vec<String> = first
            .get("siblings").and_then(|x| x.as_array()).unwrap()
            .iter().map(|s| s.as_str().unwrap().to_string()).collect();

        let res = verify_one(root, purl, value, &siblings).expect("verify ok");
        let matches = res.get("matches").and_then(|x| x.as_bool()).unwrap();
        assert!(matches, "computed root should match expected root: {:?}", res);
    }
}
