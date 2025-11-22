use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub proofs_dir: PathBuf,
}

impl Config {
    pub fn from_env() -> Self {
        let port = env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);

        let proofs_dir = env::var("PROOFS_DIR")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/app/proofs"));

        Self { port, proofs_dir }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8080,
            proofs_dir: PathBuf::from("/app/proofs"),
        }
    }
}

