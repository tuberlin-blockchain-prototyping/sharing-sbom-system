use risc0_zkvm::{serde::from_slice, Receipt};

pub fn load_receipt(proof_base64: &str) -> Result<Receipt, String> {
    use base64::{Engine as _, engine::general_purpose};
    let bytes = general_purpose::STANDARD
        .decode(proof_base64)
        .map_err(|e| format!("Failed to decode base64: {}", e))?;

    if bytes.len() % 4 != 0 {
        return Err("Receipt file size is not a multiple of 4 bytes".to_string());
    }

    let u32s: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();

    from_slice(&u32s).map_err(|e| format!("Failed to decode receipt: {}", e))
}

