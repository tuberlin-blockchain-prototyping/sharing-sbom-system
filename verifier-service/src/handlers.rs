use actix_web::{web, HttpResponse, Result as ActixResult};
use base64::{engine::general_purpose, Engine as _};
use risc0_zkvm::{serde::from_slice, Receipt};
use tracing;

use crate::error::{Error, Result};
use crate::models::{MerklePublicOutputs, VerifyProofRequest, VerifyProofResponse};

/// Health check endpoint
pub async fn health() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "healthy"})))
}

/// Verify a Risc0 zero-knowledge proof
pub async fn verify(req: web::Json<VerifyProofRequest>) -> ActixResult<HttpResponse> {
    tracing::debug!("Received verification request");

    req.validate().map_err(|e| Error::InvalidProof(e))?;

    let receipt = deserialize_receipt(&req.proof)?;
    let image_id = parse_image_id(&req.image_id)?;

    receipt
        .verify(image_id)
        .map_err(|e| Error::VerificationFailed(e.to_string()))?;

    let outputs: MerklePublicOutputs = receipt
        .journal
        .decode()
        .map_err(|e| Error::DeserializationFailed(e.to_string()))?;

    // Validate all fields match the proof's journal outputs
    let decoded_root_hash = hex::encode(outputs.root_hash);
    if req.root_hash != decoded_root_hash {
        return Err(Error::VerificationFailed(format!(
            "Root hash mismatch: request has {}, proof contains {}",
            req.root_hash, decoded_root_hash
        ))
        .into());
    }

    let decoded_banned_hash = hex::encode(outputs.banned_list_hash);
    if req.banned_list_hash != decoded_banned_hash {
        return Err(Error::VerificationFailed(format!(
            "Banned list hash mismatch: request has {}, proof contains {}",
            req.banned_list_hash, decoded_banned_hash
        ))
        .into());
    }

    if req.compliant != outputs.compliant {
        return Err(Error::VerificationFailed(format!(
            "Compliant flag mismatch: request has {}, proof contains {}",
            req.compliant, outputs.compliant
        ))
        .into());
    }

    if req.timestamp != outputs.timestamp {
        return Err(Error::VerificationFailed(format!(
            "Timestamp mismatch: request has {}, proof contains {}",
            req.timestamp, outputs.timestamp
        ))
        .into());
    }

    tracing::info!("Proof verified: compliant={}", outputs.compliant);

    let response = VerifyProofResponse {
        proof_verified: true,
        root_hash: decoded_root_hash,
        banned_list_hash: decoded_banned_hash,
        compliant: outputs.compliant,
        image_id: req.image_id.clone(),
        timestamp: outputs.timestamp,
        generation_duration_ms: req.generation_duration_ms,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Deserialize a Risc0 receipt from base64-encoded proof
fn deserialize_receipt(proof_base64: &str) -> Result<Receipt> {
    let proof_bytes = general_purpose::STANDARD
        .decode(proof_base64)
        .map_err(|e| Error::InvalidProof(format!("Invalid base64: {}", e)))?;

    if proof_bytes.len() % 4 != 0 {
        return Err(Error::InvalidProof(format!(
            "Proof length {} is not a multiple of 4",
            proof_bytes.len()
        )));
    }

    let proof_u32: Vec<u32> = proof_bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();

    from_slice(&proof_u32)
        .map_err(|e| Error::DeserializationFailed(format!("Invalid receipt: {}", e)))
}

/// Parse image ID from string array to u32 array
fn parse_image_id(image_id_vec: &[String]) -> Result<[u32; 8]> {
    if image_id_vec.len() != 8 {
        return Err(Error::InvalidImageId(format!(
            "Expected 8 values, got {}",
            image_id_vec.len()
        )));
    }

    let mut image_id = [0u32; 8];
    for (i, val_str) in image_id_vec.iter().enumerate() {
        image_id[i] = val_str
            .parse::<u32>()
            .map_err(|e| Error::InvalidImageId(format!("Invalid value at index {}: {}", i, e)))?;
    }

    Ok(image_id)
}
