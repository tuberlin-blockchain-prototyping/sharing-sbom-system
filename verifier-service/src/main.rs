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

    tracing::info!("Starting verifier-service on port {}", config.port);

    HttpServer::new(|| {
        App::new()
            .route("/health", web::get().to(handlers::health))
            .route("/verify", web::post().to(handlers::verify))
    })
    .bind(("0.0.0.0", config.port))?
    .run()
    .await
}
