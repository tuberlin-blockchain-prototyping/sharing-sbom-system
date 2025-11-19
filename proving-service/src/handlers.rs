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
    use std::time::Instant;

    let start_time = Instant::now();
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

    let prove_start = Instant::now();
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

    let generation_duration = prove_start.elapsed();
    let total_duration = start_time.elapsed();
    
    tracing::info!(
        "Proof generation took {:.2}s (total request: {:.2}s)",
        generation_duration.as_secs_f64(),
        total_duration.as_secs_f64()
    );

    let proof_base64 = general_purpose::STANDARD.encode(&receipt_bytes);
    let proof_info = serde_json::json!({
        "root_hash": hex::encode(output.root_hash),
        "is_valid": output.is_valid,
        "verified_count": output.verified_count,
        "total_proofs": req.merkle_proofs.len(),
        "image_id": SBOM_VALIDATOR_ID.iter().map(|&x| x.to_string()).collect::<Vec<_>>(),
    });

    // Create proof data with timestamp and duration
    let timestamp = chrono::Local::now();
    let proof_data = serde_json::json!({
        "timestamp": timestamp.to_rfc3339(),
        "generation_duration_ms": generation_duration.as_millis(),
        "total_duration_ms": total_duration.as_millis(),
        "proof": proof_base64,
        "root_hash": hex::encode(root_hash),
        "image_id": SBOM_VALIDATOR_ID.iter().map(|&x| x.to_string()).collect::<Vec<_>>(),
        "proof_info": proof_info,
    });

    // Create proofs directory if it doesn't exist
    let proofs_dir = std::path::Path::new("proofs");
    std::fs::create_dir_all(proofs_dir)
        .map_err(|e| actix_web::error::ErrorInternalServerError(
            format!("Failed to create proofs directory: {}", e)
        ))?;

    // Generate filename with timestamp
    let filename = format!(
        "proof_information_{}.json",
        timestamp.format("%Y%m%d_%H%M%S")
    );
    let filepath = proofs_dir.join(&filename);

    // Write proof to file
    std::fs::write(&filepath, serde_json::to_string_pretty(&proof_data).unwrap())
        .map_err(|e| actix_web::error::ErrorInternalServerError(
            format!("Failed to write proof file: {}", e)
        ))?;

    tracing::info!("Proof saved to: {}", filepath.display());

    // Return simple success message
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Proof generated and saved successfully",
        "filename": filename,
        "filepath": filepath.display().to_string(),
        "generation_duration_ms": generation_duration.as_millis(),
        "is_valid": output.is_valid,
        "verified_count": output.verified_count,
    })))
}

// ============================================================================
// Compact Merkle Tree validation endpoint (bitmap-compressed proofs)
// ============================================================================

pub async fn prove_merkle_compact(req: web::Json<crate::models::ProveCompactMerkleRequest>) -> ActixResult<HttpResponse> {
    use crate::utils::{bitmap_bit, count_bitmap_ones, DEFAULTS};
    use std::time::Instant;

    let start_time = Instant::now();
    tracing::info!("Received compact merkle prove request");

    // Validate depth is exactly 256
    if req.depth != 256 {
        return Err(actix_web::error::ErrorBadRequest(
            format!("Depth must be 256, got {}", req.depth)
        ));
    }

    if req.merkle_proofs.is_empty() {
        return Err(actix_web::error::ErrorBadRequest("At least one merkle proof is required"));
    }

    let root_hash = hex_to_bytes32(&req.root)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid root hash: {}", e)))?;

    // Validate each compact proof
    for (_i, proof) in req.merkle_proofs.iter().enumerate() {
        // Validate bitmap is exactly 64 hex chars (32 bytes)
        let bitmap_hex = proof.bitmap.strip_prefix("0x").unwrap_or(&proof.bitmap);
        if bitmap_hex.len() != 64 {
            return Err(actix_web::error::ErrorBadRequest(
                format!("Bitmap must be valid 64-character hex string (32 bytes) for purl '{}'", proof.purl)
            ));
        }

        // Decode bitmap
        let bitmap = hex_to_bytes32(&proof.bitmap)
            .map_err(|e| actix_web::error::ErrorBadRequest(
                format!("Invalid bitmap hex for purl '{}': {}", proof.purl, e)
            ))?;

        // Count expected siblings based on bitmap
        let expected_sibling_count = count_bitmap_ones(&bitmap);
        if proof.siblings.len() != expected_sibling_count {
            return Err(actix_web::error::ErrorBadRequest(
                format!("Expected {} siblings based on bitmap, got {} for purl '{}'",
                    expected_sibling_count, proof.siblings.len(), proof.purl)
            ));
        }

        // Validate leaf_index format (64 hex chars)
        let leaf_index_hex = proof.leaf_index.strip_prefix("0x").unwrap_or(&proof.leaf_index);
        if leaf_index_hex.len() != 64 {
            return Err(actix_web::error::ErrorBadRequest(
                format!("Leaf index must be valid 64-character hex string (32 bytes) for purl '{}'", proof.purl)
            ));
        }
        hex_to_bytes32(&proof.leaf_index)
            .map_err(|e| actix_web::error::ErrorBadRequest(
                format!("Invalid leaf_index hex for purl '{}': {}", proof.purl, e)
            ))?;

        // Validate all provided siblings are valid hex and don't match DEFAULTS
        let mut sibling_idx = 0;
        for d in 0..256 {
            if bitmap_bit(&bitmap, d) == 1 {
                if sibling_idx >= proof.siblings.len() {
                    return Err(actix_web::error::ErrorBadRequest(
                        format!("Not enough siblings for bitmap at depth {} for purl '{}'", d, proof.purl)
                    ));
                }

                let sibling_hash = hex_to_bytes32(&proof.siblings[sibling_idx])
                    .map_err(|e| actix_web::error::ErrorBadRequest(
                        format!("Invalid sibling at depth {} for purl '{}': {}", d, proof.purl, e)
                    ))?;

                // Strict validation: provided sibling must not match DEFAULTS[d]
                if sibling_hash == DEFAULTS[d] {
                    return Err(actix_web::error::ErrorBadRequest(
                        format!("Sibling at depth {} for purl '{}' matches DEFAULTS[{}] - must use bitmap bit 0 instead",
                            d, proof.purl, d)
                    ));
                }

                sibling_idx += 1;
            }
        }
    }

    let public_inputs = crate::models::MerklePublicInputs {
        root_hash,
    };

    let proofs_json = serde_json::to_string(&req.merkle_proofs)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid proofs JSON: {}", e)))?;

    tracing::info!(
        "Processing {} compact non-membership proofs for root: {}",
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

    tracing::info!("Generating proof for compact merkle tree root: {}", req.root);
    
    let prove_start = Instant::now();
    let prover = default_prover();
    let receipt = prover
        .prove(env, SBOM_VALIDATOR_ELF)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Proof generation failed: {}", e)))?
        .receipt;

    let output: crate::models::MerklePublicOutputs = receipt
        .journal
        .decode()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to decode output: {}", e)))?;

    tracing::info!("Compact proof generated successfully. Valid: {}, Verified: {}/{}",
        output.is_valid, output.verified_count, req.merkle_proofs.len());

    receipt
        .verify(SBOM_VALIDATOR_ID)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Receipt verification failed: {}", e)))?;

    let receipt_bytes: Vec<u8> = to_vec(&receipt)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to serialize receipt: {}", e)))?
        .iter()
        .flat_map(|&x| x.to_le_bytes())
        .collect();

    let generation_duration = prove_start.elapsed();
    let total_duration = start_time.elapsed();
    
    tracing::info!(
        "Proof generation took {:.2}s (total request: {:.2}s)",
        generation_duration.as_secs_f64(),
        total_duration.as_secs_f64()
    );

    let proof_base64 = general_purpose::STANDARD.encode(&receipt_bytes);
    let proof_info = serde_json::json!({
        "root_hash": hex::encode(output.root_hash),
        "is_valid": output.is_valid,
        "verified_count": output.verified_count,
        "total_proofs": req.merkle_proofs.len(),
        "proof_type": "compact",
        "image_id": SBOM_VALIDATOR_ID.iter().map(|&x| x.to_string()).collect::<Vec<_>>(),
    });

    // Create proof data with timestamp and duration
    let timestamp = chrono::Local::now();
    let proof_data = serde_json::json!({
        "timestamp": timestamp.to_rfc3339(),
        "generation_duration_ms": generation_duration.as_millis(),
        "total_duration_ms": total_duration.as_millis(),
        "proof": proof_base64,
        "root_hash": hex::encode(root_hash),
        "image_id": SBOM_VALIDATOR_ID.iter().map(|&x| x.to_string()).collect::<Vec<_>>(),
        "proof_info": proof_info,
    });

    // Create proofs directory if it doesn't exist
    let proofs_dir = std::path::Path::new("proofs");
    std::fs::create_dir_all(proofs_dir)
        .map_err(|e| actix_web::error::ErrorInternalServerError(
            format!("Failed to create proofs directory: {}", e)
        ))?;

    // Generate filename with timestamp
    let filename = format!(
        "proof_information_{}.json",
        timestamp.format("%Y%m%d_%H%M%S")
    );
    let filepath = proofs_dir.join(&filename);

    // Write proof to file
    std::fs::write(&filepath, serde_json::to_string_pretty(&proof_data).unwrap())
        .map_err(|e| actix_web::error::ErrorInternalServerError(
            format!("Failed to write proof file: {}", e)
        ))?;

    tracing::info!("Proof saved to: {}", filepath.display());

    // Return simple success message
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Proof generated and saved successfully",
        "filename": filename,
        "filepath": filepath.display().to_string(),
        "generation_duration_ms": generation_duration.as_millis(),
        "is_valid": output.is_valid,
        "verified_count": output.verified_count,
    })))
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

// ============================================================================
// Debug endpoint: host-side compact merkle verification (no ZK)
// ============================================================================

#[derive(serde::Deserialize)]
pub struct DebugVerifyCompactMerkleRequest {
    pub root: String,
    pub purl: String,
    pub value: String,
    pub leaf_index: String,
    pub siblings: Vec<String>,
    pub bitmap: String,
}

pub async fn debug_verify_merkle_compact(body: web::Json<serde_json::Value>) -> ActixResult<HttpResponse> {
    let value = body.into_inner();

    // Try to parse as single-proof first
    if let Ok(req) = serde_json::from_value::<DebugVerifyCompactMerkleRequest>(value.clone()) {
        let result = verify_one_compact(&req.root, &req.purl, &req.value, &req.leaf_index, &req.siblings, &req.bitmap)?;
        return Ok(HttpResponse::Ok().json(result));
    }

    // Try to parse as batch (same shape as /prove-merkle-compact)
    let batch: crate::models::ProveCompactMerkleRequest = serde_json::from_value(value)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!(
            "Json deserialize error: {}. Expected either single-proof {{root,purl,value,leaf_index,siblings,bitmap}} or batch {{depth,root,merkle_proofs:[...]}}.",
            e
        )))?;

    if batch.depth != 256 {
        return Err(actix_web::error::ErrorBadRequest(format!("Depth must be 256, got {}", batch.depth)));
    }

    let root = batch.root.clone();
    if batch.merkle_proofs.is_empty() {
        return Err(actix_web::error::ErrorBadRequest("merkle_proofs must not be empty"));
    }

    // Verify each proof and collect results
    let mut results = Vec::with_capacity(batch.merkle_proofs.len());
    for (idx, mp) in batch.merkle_proofs.iter().enumerate() {
        match verify_one_compact(&root, &mp.purl, &mp.value, &mp.leaf_index, &mp.siblings, &mp.bitmap) {
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
        "note": "Compact proof verification using bitmap-compressed siblings. Bitmap bit d=1 uses provided sibling, bit d=0 uses DEFAULTS[d]. Path determined by leaf_index (pre-computed SHA256 of PURL). Big-endian bit interpretation."
    })))
}

fn verify_one_compact(
    root_hex: &str,
    purl: &str,
    value: &str,
    leaf_index_hex: &str,
    siblings: &[String],
    bitmap_hex: &str,
) -> Result<serde_json::Value, actix_web::Error> {
    use crate::utils::{bitmap_bit, path_bit, count_bitmap_ones, DEFAULTS, merkle_hash_value, merkle_hash_pair};

    let root = hex_to_bytes32(root_hex)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid root: {}", e)))?;

    let bitmap = hex_to_bytes32(bitmap_hex)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid bitmap: {}", e)))?;

    let leaf_index = hex_to_bytes32(leaf_index_hex)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid leaf_index: {}", e)))?;

    // Validate sibling count matches bitmap
    let expected_sibling_count = count_bitmap_ones(&bitmap);
    if siblings.len() != expected_sibling_count {
        return Err(actix_web::error::ErrorBadRequest(
            format!("Expected {} siblings based on bitmap, got {}", expected_sibling_count, siblings.len())
        ));
    }

    // Start with leaf hash
    let mut current = merkle_hash_value(value);
    let mut siblings_iter = siblings.iter();
    let mut used_defaults_count = 0;
    let mut used_provided_count = 0;

    // Climb the tree for 256 levels
    for d in 0..256 {
        let sibling_hash = if bitmap_bit(&bitmap, d) == 1 {
            // Use provided sibling
            used_provided_count += 1;
            match siblings_iter.next() {
                Some(sib_hex) => hex_to_bytes32(sib_hex)
                    .map_err(|e| actix_web::error::ErrorBadRequest(
                        format!("Invalid sibling at depth {}: {}", d, e)
                    ))?,
                None => return Err(actix_web::error::ErrorBadRequest(
                    format!("Not enough siblings for bitmap at depth {}", d)
                )),
            }
        } else {
            // Use DEFAULTS[d]
            used_defaults_count += 1;
            DEFAULTS[d]
        };

        // Determine path direction from leaf_index
        let path_direction = path_bit(&leaf_index, d);

        current = if path_direction == 0 {
            merkle_hash_pair(&current, &sibling_hash)
        } else {
            merkle_hash_pair(&sibling_hash, &current)
        };
    }

    let computed_root_hex = hex::encode(current);
    let matches = current == root;

    Ok(serde_json::json!({
        "computed_root": computed_root_hex,
        "expected_root": root_hex,
        "matches": matches,
        "purl": purl,
        "value": value,
        "leaf_index": leaf_index_hex,
        "bitmap_ones": expected_sibling_count,
        "used_provided_siblings": used_provided_count,
        "used_defaults": used_defaults_count,
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
