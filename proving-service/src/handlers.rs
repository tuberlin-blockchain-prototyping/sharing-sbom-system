use actix_web::{HttpResponse, Result as ActixResult, web};
use base64::{Engine as _, engine::general_purpose};
use methods::{SBOM_VALIDATOR_ELF, SBOM_VALIDATOR_ID};
use risc0_zkvm::{ExecutorEnv, default_prover, serde::to_vec};
use std::time::Instant;

use crate::config::Config;
use crate::models::{MerklePublicInputs, MerklePublicOutputs, ProveCompactMerkleRequest};
use crate::utils::{DEFAULTS, bitmap_bit, count_bitmap_ones, hex_to_bytes32};

pub async fn health() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "healthy"})))
}

pub async fn prove_merkle_compact(
    req: web::Json<ProveCompactMerkleRequest>,
    config: web::Data<Config>,
) -> ActixResult<HttpResponse> {
    let start_time = Instant::now();
    tracing::info!(
        "Received compact merkle prove request with depth={}, root={}, proof_count={}",
        req.depth,
        req.root,
        req.merkle_proofs.len()
    );

    if req.depth != 256 {
        let err_msg = format!(
            "Invalid depth: expected 256, got {}. Depth must be exactly 256 for this merkle tree configuration",
            req.depth
        );
        tracing::error!("{}", err_msg);
        return Err(actix_web::error::ErrorBadRequest(err_msg));
    }

    if req.merkle_proofs.is_empty() {
        let err_msg = "Request validation failed: at least one merkle proof is required. Cannot generate proof without any proofs to verify";
        tracing::error!("{}", err_msg);
        return Err(actix_web::error::ErrorBadRequest(err_msg));
    }

    let root_hash = hex_to_bytes32(&req.root)
        .map_err(|e| {
            let err_msg = format!("Invalid root hash format: '{}'. Error details: {}. Root hash must be a valid 64-character hex string (optionally prefixed with '0x')", req.root, e);
            tracing::error!("{}", err_msg);
            actix_web::error::ErrorBadRequest(err_msg)
        })?;

    tracing::info!(
        "Validating {} compact merkle proof(s)",
        req.merkle_proofs.len()
    );
    for (idx, proof) in req.merkle_proofs.iter().enumerate() {
        validate_compact_proof(proof).map_err(|e| {
            tracing::error!(
                "Proof validation failed at index {} (purl: {}): {}",
                idx,
                proof.purl,
                e
            );
            e
        })?;
    }
    tracing::info!(
        "All {} proof(s) validated successfully",
        req.merkle_proofs.len()
    );

    let public_inputs = MerklePublicInputs { root_hash };

    let proofs_json = serde_json::to_string(&req.merkle_proofs)
        .map_err(|e| {
            let err_msg = format!("Failed to serialize merkle proofs to JSON: {}. This may indicate invalid proof structure or serialization issue", e);
            tracing::error!("{}", err_msg);
            actix_web::error::ErrorBadRequest(err_msg)
        })?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| {
            let err_msg = format!("System time error: failed to get current timestamp: {}. This indicates a system clock issue", e);
            tracing::error!("{}", err_msg);
            actix_web::error::ErrorInternalServerError(err_msg)
        })?
        .as_secs();

    tracing::info!(
        "Preparing executor environment: processing {} compact non-membership proofs for root: {} (timestamp: {})",
        req.merkle_proofs.len(),
        req.root,
        timestamp
    );

    let env = ExecutorEnv::builder()
        .write(&proofs_json)
        .map_err(|e| {
            let err_msg = format!("Failed to write proofs JSON to executor environment: {}. Proofs JSON length: {} bytes", e, proofs_json.len());
            tracing::error!("{}", err_msg);
            actix_web::error::ErrorInternalServerError(err_msg)
        })?
        .write(&public_inputs)
        .map_err(|e| {
            let err_msg = format!("Failed to write public inputs to executor environment: {}. Root hash: {}", e, hex::encode(root_hash));
            tracing::error!("{}", err_msg);
            actix_web::error::ErrorInternalServerError(err_msg)
        })?
        .write(&timestamp)
        .map_err(|e| {
            let err_msg = format!("Failed to write timestamp to executor environment: {}. Timestamp value: {}", e, timestamp);
            tracing::error!("{}", err_msg);
            actix_web::error::ErrorInternalServerError(err_msg)
        })?
        .build()
        .map_err(|e| {
            let err_msg = format!("Failed to build executor environment: {}. This may indicate memory or configuration issues", e);
            tracing::error!("{}", err_msg);
            actix_web::error::ErrorInternalServerError(err_msg)
        })?;

    tracing::info!(
        "Executor environment built successfully. Starting proof generation for compact merkle tree root: {}",
        req.root
    );

    let prove_start = Instant::now();
    let prover = default_prover();
    let receipt = prover
        .prove(env, SBOM_VALIDATOR_ELF)
        .map_err(|e| {
            let err_msg = format!("Proof generation failed during RISC0 execution: {}. This may indicate an issue with the proof computation or executor environment", e);
            tracing::error!("{}", err_msg);
            actix_web::error::ErrorInternalServerError(err_msg)
        })?
        .receipt;

    let output: MerklePublicOutputs = receipt
        .journal
        .decode()
        .map_err(|e| {
            let err_msg = format!("Failed to decode receipt journal output: {}. Journal size: {} bytes. This may indicate a serialization mismatch or corrupted receipt", e, receipt.journal.bytes.len());
            tracing::error!("{}", err_msg);
            actix_web::error::ErrorInternalServerError(err_msg)
        })?;

    tracing::info!(
        "Compact proof generated successfully. Compliant: {}, Root hash: {}, Banned list hash: {}",
        output.compliant,
        hex::encode(output.root_hash),
        hex::encode(output.banned_list_hash)
    );

    receipt
        .verify(SBOM_VALIDATOR_ID)
        .map_err(|e| {
            let err_msg = format!("Receipt verification failed: {}. This indicates the generated proof is invalid or corrupted. Image ID: {:?}", e, SBOM_VALIDATOR_ID);
            tracing::error!("{}", err_msg);
            actix_web::error::ErrorInternalServerError(err_msg)
        })?;

    tracing::info!("Receipt verification successful");

    let receipt_bytes: Vec<u8> = to_vec(&receipt)
        .map_err(|e| {
            let err_msg = format!("Failed to serialize receipt to bytes: {}. This may indicate a serialization format issue", e);
            tracing::error!("{}", err_msg);
            actix_web::error::ErrorInternalServerError(err_msg)
        })?
        .iter()
        .flat_map(|&x| x.to_le_bytes())
        .collect();

    let generation_duration = prove_start.elapsed();
    let total_duration = start_time.elapsed();

    tracing::info!(
        "Proof generation completed: generation_time={:.2}s, total_request_time={:.2}s, receipt_size={} bytes",
        generation_duration.as_secs_f64(),
        total_duration.as_secs_f64(),
        receipt_bytes.len()
    );

    let proof_base64 = general_purpose::STANDARD.encode(&receipt_bytes);

    let proof_data = serde_json::json!({
        "timestamp": output.timestamp,
        "root_hash": hex::encode(output.root_hash),
        "banned_list_hash": hex::encode(output.banned_list_hash),
        "compliant": output.compliant,
        "image_id": SBOM_VALIDATOR_ID.iter().map(|&x| x.to_string()).collect::<Vec<_>>(),
        "proof": proof_base64,
        "generation_duration_ms": generation_duration.as_millis(),
    });

    tracing::info!(
        "Attempting to save proof to directory: {}",
        config.proofs_dir.display()
    );
    if let Err(e) = std::fs::create_dir_all(&config.proofs_dir) {
        let err_msg = format!(
            "Failed to create proofs directory '{}': {}. Proof will not be persisted to disk",
            config.proofs_dir.display(),
            e
        );
        tracing::warn!("{}", err_msg);
    }

    let filename = format!("proof_{}.json", output.timestamp);
    let filepath = config.proofs_dir.join(&filename);

    match serde_json::to_string_pretty(&proof_data) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&filepath, json) {
                let err_msg = format!(
                    "Failed to write proof file to '{}': {}. Proof data will still be returned in response",
                    filepath.display(),
                    e
                );
                tracing::warn!("{}", err_msg);
            } else {
                tracing::info!(
                    "Proof successfully saved to: {} (size: {} bytes)",
                    filepath.display(),
                    std::fs::metadata(&filepath).map(|m| m.len()).unwrap_or(0)
                );
            }
        }
        Err(e) => {
            let err_msg = format!(
                "Failed to serialize proof data to JSON for file storage: {}. Proof data will still be returned in response",
                e
            );
            tracing::warn!("{}", err_msg);
        }
    }

    let response = serde_json::json!({
        "timestamp": output.timestamp,
        "root_hash": hex::encode(output.root_hash),
        "banned_list_hash": hex::encode(output.banned_list_hash),
        "compliant": output.compliant,
        "image_id": SBOM_VALIDATOR_ID.iter().map(|&x| x.to_string()).collect::<Vec<_>>(),
        "proof": proof_base64,
        "generation_duration_ms": generation_duration.as_millis(),
    });

    tracing::info!("Request completed successfully. Returning proof response");
    Ok(HttpResponse::Ok().json(response))
}

fn validate_compact_proof(proof: &crate::models::CompactMerkleProof) -> actix_web::Result<()> {
    tracing::debug!("Validating compact proof for purl: {}", proof.purl);

    let bitmap_hex = proof.bitmap.strip_prefix("0x").unwrap_or(&proof.bitmap);
    if bitmap_hex.len() != 64 {
        let err_msg = format!(
            "Invalid bitmap length for purl '{}': expected 64-character hex string, got {} characters (value: '{}')",
            proof.purl,
            bitmap_hex.len(),
            proof.bitmap
        );
        tracing::error!("{}", err_msg);
        return Err(actix_web::error::ErrorBadRequest(err_msg));
    }

    let bitmap = hex_to_bytes32(&proof.bitmap)
        .map_err(|e| {
            let err_msg = format!(
                "Invalid bitmap hex format for purl '{}': {}. Bitmap value: '{}'. Bitmap must be a valid 64-character hex string",
                proof.purl, e, proof.bitmap
            );
            tracing::error!("{}", err_msg);
            actix_web::error::ErrorBadRequest(err_msg)
        })?;

    let expected_sibling_count = count_bitmap_ones(&bitmap);
    if proof.siblings.len() != expected_sibling_count {
        let err_msg = format!(
            "Sibling count mismatch for purl '{}': bitmap indicates {} sibling(s) should be present (bitmap: '{}'), but {} sibling(s) provided",
            proof.purl,
            expected_sibling_count,
            proof.bitmap,
            proof.siblings.len()
        );
        tracing::error!("{}", err_msg);
        return Err(actix_web::error::ErrorBadRequest(err_msg));
    }

    let leaf_index_hex = proof
        .leaf_index
        .strip_prefix("0x")
        .unwrap_or(&proof.leaf_index);
    if leaf_index_hex.len() != 64 {
        let err_msg = format!(
            "Invalid leaf_index length for purl '{}': expected 64-character hex string, got {} characters (value: '{}')",
            proof.purl,
            leaf_index_hex.len(),
            proof.leaf_index
        );
        tracing::error!("{}", err_msg);
        return Err(actix_web::error::ErrorBadRequest(err_msg));
    }

    hex_to_bytes32(&proof.leaf_index)
        .map_err(|e| {
            let err_msg = format!(
                "Invalid leaf_index hex format for purl '{}': {}. Leaf index value: '{}'. Leaf index must be a valid 64-character hex string",
                proof.purl, e, proof.leaf_index
            );
            tracing::error!("{}", err_msg);
            actix_web::error::ErrorBadRequest(err_msg)
        })?;

    tracing::debug!(
        "Validating {} sibling(s) for purl '{}'",
        proof.siblings.len(),
        proof.purl
    );
    let mut sibling_idx = 0;
    #[allow(clippy::needless_range_loop)]
    for d in 0..256 {
        if bitmap_bit(&bitmap, d) == 1 {
            if sibling_idx >= proof.siblings.len() {
                let err_msg = format!(
                    "Insufficient siblings for purl '{}': bitmap indicates sibling needed at depth {}, but only {} sibling(s) available (expected at least {})",
                    proof.purl,
                    d,
                    proof.siblings.len(),
                    sibling_idx + 1
                );
                tracing::error!("{}", err_msg);
                return Err(actix_web::error::ErrorBadRequest(err_msg));
            }

            let sibling_hash = hex_to_bytes32(&proof.siblings[sibling_idx])
                .map_err(|e| {
                    let err_msg = format!(
                        "Invalid sibling hex format for purl '{}' at depth {} (sibling index {}): {}. Sibling value: '{}'",
                        proof.purl, d, sibling_idx, e, proof.siblings[sibling_idx]
                    );
                    tracing::error!("{}", err_msg);
                    actix_web::error::ErrorBadRequest(err_msg)
                })?;

            if sibling_hash == DEFAULTS[d] {
                let err_msg = format!(
                    "Invalid sibling for purl '{}' at depth {}: sibling matches DEFAULTS[{}] (value: {}). When sibling equals default value, bitmap bit should be 0, not 1",
                    proof.purl,
                    d,
                    d,
                    hex::encode(DEFAULTS[d])
                );
                tracing::error!("{}", err_msg);
                return Err(actix_web::error::ErrorBadRequest(err_msg));
            }

            sibling_idx += 1;
        }
    }

    tracing::debug!(
        "Compact proof validation successful for purl: {}",
        proof.purl
    );
    Ok(())
}
