use actix_web::{middleware, web, App, HttpServer};
use tracing_subscriber::filter::EnvFilter;
use verifier_service::{config::Config, handlers};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Config::from_env();
    
    tracing::info!("Starting verifier-service on port {}", config.port);
    
    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            .route("/health", web::get().to(handlers::health))
            .route("/verify", web::post().to(handlers::verify))
    })
    .bind(("0.0.0.0", config.port))?
    .run()
    .await
}
