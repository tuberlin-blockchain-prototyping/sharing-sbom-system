use actix_web::{web, HttpResponse, Result as ActixResult};
use base64::{Engine as _, engine::general_purpose};
use methods::{SBOM_VALIDATOR_ELF, SBOM_VALIDATOR_ID};
use risc0_zkvm::{default_prover, serde::to_vec, ExecutorEnv};
use sha2::{Digest, Sha256};
use std::time::Instant;

use crate::config::Config;
use crate::models::{MerklePublicInputs, MerklePublicOutputs, ProveCompactMerkleRequest};
use crate::utils::{bitmap_bit, count_bitmap_ones, hex_to_bytes32, DEFAULTS};

pub async fn health() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "healthy"})))
}

pub async fn prove_merkle_compact(
    req: web::Json<ProveCompactMerkleRequest>,
    config: web::Data<Config>,
) -> ActixResult<HttpResponse> {
    let start_time = Instant::now();
    tracing::info!("Received compact merkle prove request");

    if req.depth != 256 {
        return Err(actix_web::error::ErrorBadRequest(
            format!("Depth must be 256, got {}", req.depth)
        ));
    }

    if req.merkle_proofs.is_empty() {
        return Err(actix_web::error::ErrorBadRequest("At least one merkle proof is required"));
    }

    let root_hash = hex_to_bytes32(&req.root)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid root hash: {e}")))?;

    // Validate compact proof format
    for proof in &req.merkle_proofs {
        validate_compact_proof(proof)?;
    }

    let banned_list: Vec<String> = req.merkle_proofs.iter().map(|p| p.purl.clone()).collect();
    let banned_list_hash = compute_banned_list_hash(&banned_list);

    let public_inputs = MerklePublicInputs {
        root_hash,
        banned_list_hash,
    };

    let proofs_json = serde_json::to_string(&req.merkle_proofs)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid proofs JSON: {e}")))?;

    tracing::info!(
        "Processing {} compact non-membership proofs for root: {} with banned list hash: {}",
        req.merkle_proofs.len(),
        req.root,
        hex::encode(banned_list_hash)
    );

    let env = ExecutorEnv::builder()
        .write(&proofs_json)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to write proofs: {e}")))?
        .write(&banned_list)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to write banned list: {e}")))?
        .write(&public_inputs)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to write inputs: {e}")))?
        .build()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to build env: {e}")))?;

    tracing::info!("Generating proof for compact merkle tree root: {}", req.root);
    
    let prove_start = Instant::now();
    let prover = default_prover();
    let receipt = prover
        .prove(env, SBOM_VALIDATOR_ELF)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Proof generation failed: {e}")))?
        .receipt;

    let output: MerklePublicOutputs = receipt
        .journal
        .decode()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to decode output: {e}")))?;

    tracing::info!("Compact proof generated successfully. Compliant: {}, Verified: {}/{}",
        output.compliant, output.verified_count, req.merkle_proofs.len());

    receipt
        .verify(SBOM_VALIDATOR_ID)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Receipt verification failed: {e}")))?;

    let receipt_bytes: Vec<u8> = to_vec(&receipt)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to serialize receipt: {e}")))?
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
    
    // Save proof to file
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let proof_data = serde_json::json!({
        "root_hash": hex::encode(output.root_hash),
        "banned_list_hash": hex::encode(output.banned_list_hash),
        "verified_count": output.verified_count,
        "compliant": output.compliant,
        "timestamp": timestamp,
        "generation_duration_ms": generation_duration.as_millis(),
        "image_id": SBOM_VALIDATOR_ID.iter().map(|&x| x.to_string()).collect::<Vec<_>>(),
        "proof": proof_base64,
    });

    std::fs::create_dir_all(&config.proofs_dir).ok();
    
    let filename = format!("proof_{timestamp}.json");
    let filepath = config.proofs_dir.join(&filename);
    
    match serde_json::to_string_pretty(&proof_data) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&filepath, json) {
                tracing::warn!("Failed to save proof to file: {}", e);
            } else {
                tracing::info!("Proof saved to: {}", filepath.display());
            }
        }
        Err(e) => tracing::warn!("Failed to serialize proof data: {}", e),
    }
    
    let response = serde_json::json!({
        "root_hash": hex::encode(output.root_hash),
        "banned_list_hash": hex::encode(output.banned_list_hash),
        "verified_count": output.verified_count,
        "compliant": output.compliant,
        "timestamp": timestamp,
        "generation_duration_ms": generation_duration.as_millis(),
        "image_id": SBOM_VALIDATOR_ID.iter().map(|&x| x.to_string()).collect::<Vec<_>>(),
        "proof": proof_base64,
    });

    Ok(HttpResponse::Ok().json(response))
}

fn validate_compact_proof(proof: &crate::models::CompactMerkleProof) -> actix_web::Result<()> {
    let bitmap_hex = proof.bitmap.strip_prefix("0x").unwrap_or(&proof.bitmap);
    if bitmap_hex.len() != 64 {
        return Err(actix_web::error::ErrorBadRequest(
            format!("Bitmap must be 64-character hex string for purl '{}'", proof.purl)
        ));
    }

    let bitmap = hex_to_bytes32(&proof.bitmap)
        .map_err(|e| actix_web::error::ErrorBadRequest(
            format!("Invalid bitmap hex for purl '{}': {}", proof.purl, e)
        ))?;

    let expected_sibling_count = count_bitmap_ones(&bitmap);
    if proof.siblings.len() != expected_sibling_count {
        return Err(actix_web::error::ErrorBadRequest(
            format!("Expected {} siblings based on bitmap, got {} for purl '{}'",
                expected_sibling_count, proof.siblings.len(), proof.purl)
        ));
    }

    let leaf_index_hex = proof.leaf_index.strip_prefix("0x").unwrap_or(&proof.leaf_index);
    if leaf_index_hex.len() != 64 {
        return Err(actix_web::error::ErrorBadRequest(
            format!("Leaf index must be 64-character hex string for purl '{}'", proof.purl)
        ));
    }
    
    hex_to_bytes32(&proof.leaf_index)
        .map_err(|e| actix_web::error::ErrorBadRequest(
            format!("Invalid leaf_index hex for purl '{}': {}", proof.purl, e)
        ))?;

    let mut sibling_idx = 0;
    #[allow(clippy::needless_range_loop)]
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

            if sibling_hash == DEFAULTS[d] {
                return Err(actix_web::error::ErrorBadRequest(
                    format!("Sibling at depth {} for purl '{}' matches DEFAULTS[{}] - must use bitmap bit 0 instead",
                        d, proof.purl, d)
                ));
            }

            sibling_idx += 1;
        }
    }

    Ok(())
}

fn compute_banned_list_hash(banned_list: &[String]) -> [u8; 32] {
    let json = serde_json::to_string(banned_list).unwrap_or_else(|_| "[]".to_string());
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hasher.finalize().into()
}
