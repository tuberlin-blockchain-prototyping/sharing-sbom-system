use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
}

impl Config {
    pub fn from_env() -> Self {
        let port = env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8082);

        Self { port }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 8082,
        }
    }
}

