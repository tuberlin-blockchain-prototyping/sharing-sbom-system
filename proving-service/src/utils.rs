use sha2::{Digest, Sha256};

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

