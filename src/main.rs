use std::net::SocketAddr;

use axum::{extract::DefaultBodyLimit, routing::get, Json, Router};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

mod auth;
mod errors;
mod handlers;
mod models;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "umamoe_ingest=debug,tower_http=info".into()),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let db = PgPoolOptions::new()
        .max_connections(8)
        .min_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");

    info!("Connected to database");

    sqlx::migrate!("./migrations")
        .set_ignore_missing(true)
        .run(&db)
        .await
        .expect("Failed to run migrations");

    info!("Migrations applied");

    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    auth::init(jwt_secret);
    info!("JWT authentication configured");

    let state = AppState { db };

    // 128 MB cap — generous headroom for large veteran lists
    const BODY_LIMIT: usize = 128 * 1024 * 1024;

    let app = Router::new()
        .route("/health", get(health))
        .route("/ingest/veteran", axum::routing::post(handlers::ingest::veteran_list))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3003".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid u16");

    let addr: SocketAddr = format!("{}:{}", host, port).parse().expect("Invalid address");

    info!("🚀 Ingest server starting on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}
