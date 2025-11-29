use actix_web::{App, HttpServer, middleware, web};
use proving_service::{config::Config, handlers};
use tracing_subscriber::filter::EnvFilter;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env();

    tracing::info!("Starting proving-service on port {}", config.port);
    tracing::info!("Proofs directory: {}", config.proofs_dir.display());

    let port = config.port;

    HttpServer::new(move || {
        let config = config.clone();
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(config))
            .route("/health", web::get().to(handlers::health))
            .route(
                "/prove-merkle-compact",
                web::post().to(handlers::prove_merkle_compact),
            )
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
