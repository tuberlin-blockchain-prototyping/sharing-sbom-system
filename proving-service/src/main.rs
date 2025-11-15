mod config;
mod handlers;
mod models;
mod utils;

use actix_web::{web, App, HttpServer};
use tracing_subscriber::filter::EnvFilter;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = config::Config::from_env();

    tracing::info!("Starting proving-service on port {}", config.port);

    HttpServer::new(|| {
        App::new()
            .route("/health", web::get().to(handlers::health))
            .route("/prove", web::post().to(handlers::prove))
    })
    .bind(("0.0.0.0", config.port))?
    .keep_alive(std::time::Duration::from_secs(3600))
    .client_timeout(3600000)
    .run()
    .await
}
