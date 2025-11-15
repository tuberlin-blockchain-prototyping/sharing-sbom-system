use actix_web::{web, HttpResponse, Result as ActixResult};
use methods::SBOM_VALIDATOR_ID;
use risc0_zkvm::Receipt;

use crate::models::{PublicOutputs, VerifyRequest, VerifyResponse};
use crate::utils::load_receipt;

pub async fn health() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "healthy"})))
}

pub async fn verify(req: web::Json<VerifyRequest>) -> ActixResult<HttpResponse> {
    tracing::info!("Received verify request");

    let receipt = load_receipt(&req.proof)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Failed to load receipt: {}", e)))?;

    tracing::info!("Verifying receipt...");
    receipt
        .verify(SBOM_VALIDATOR_ID)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Receipt verification failed: {}", e)))?;

    tracing::info!("Receipt verified successfully");

    let output: PublicOutputs = receipt
        .journal
        .decode()
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Failed to decode output: {}", e)))?;

    let response = VerifyResponse {
        valid: true,
        sbom_hash: hex::encode(output.sbom_hash),
        is_valid: output.is_valid,
        banned_list_info: Some(output.banned_list_info),
    };

    Ok(HttpResponse::Ok().json(response))
}

