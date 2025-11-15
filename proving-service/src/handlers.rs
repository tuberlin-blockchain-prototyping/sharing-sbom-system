use actix_web::{web, HttpResponse, Result as ActixResult};
use base64::{Engine as _, engine::general_purpose};
use methods::{SBOM_VALIDATOR_ELF, SBOM_VALIDATOR_ID};
use risc0_zkvm::{default_prover, serde::to_vec, ExecutorEnv};

use crate::models::{BannedListInfo, ProveRequest, ProveResponse, PublicInputs, PublicOutputs};
use crate::utils::{compute_banned_list_hash, compute_hash};

pub async fn health() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "healthy"})))
}

pub async fn prove(req: web::Json<ProveRequest>) -> ActixResult<HttpResponse> {
    tracing::info!("Received prove request");

    let sbom_json = serde_json::to_string(&req.sbom)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid SBOM JSON: {}", e)))?;

    let banned_list = &req.banned_list;
    let sbom_hash = compute_hash(&sbom_json);

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

