use std::error::Error;

use axum::{
    http::{Method, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    serve::Serve,
    Router,
    Json,
};
use domain::AuthAPIError;
use redis::RedisResult;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, services::{ServeDir, ServeFile}, trace::TraceLayer};
use utils::tracing::{make_span_with_request_id, on_request, on_response};

pub mod app_state;
pub mod domain;
pub mod routes;
pub mod services;
pub mod utils;

pub use app_state::*;
pub use domain::*;
pub use routes::*;
pub use services::*;
pub use utils::*;

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<TcpListener, Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
         let asset_dir = ServeDir::new("assets")
            .not_found_service(ServeFile::new("assets/index.html"));
        let allowed_origins = [
            "http://localhost:8000".parse()?,
            "http://157.245.80.215:8000".parse()?,
        ];

        let cors = CorsLayer::new()
            // Allow GET and POST requests
            .allow_methods([Method::GET, Method::POST])
            // Allow cookies to be included in requests
            .allow_credentials(true)
            .allow_origin(allowed_origins);

        let router = Router::new()
            .fallback_service(asset_dir)
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/verify-2fa", post(verify_2fa))
            .route("/logout", post(logout))
            .route("/verify-token", post(verify_token))
            .with_state(app_state)
            .layer(cors)
            .layer(
                // Add a TraceLayer for HTTP requests to enable detailed tracing
                // This layer will create spans for each request using the make_span_with_request_id function,
                // and log events at the start and end of each request using on_request and on_response functions.
                TraceLayer::new_for_http()
                    .make_span_with(make_span_with_request_id)
                    .on_request(on_request)
                    .on_response(on_response),
            );

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(Self { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        ::tracing::info!("listening on {}", &self.address);
        self.server.await
    }
}

pub async fn get_postgres_pool(url: &SecretString) -> Result<PgPool, sqlx::Error> {
    // Create a new PostgreSQL connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(url.expose_secret())
        .await;
    pool
}

pub fn get_redis_client(redis_hostname: String) -> RedisResult<redis::Client> {
    let redis_url = format!("redis://{}/", redis_hostname);
    redis::Client::open(redis_url)
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        log_error_chain(&self);
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::IncorrectCredentials => (StatusCode::UNAUTHORIZED, "Incorrect credentials"),
            AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "Missing auth token"),
            AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthAPIError::UnexpectedError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}

fn log_error_chain(e: &(dyn Error + 'static)) {
    let separator =
        "\n-----------------------------------------------------------------------------------\n";
    let mut report = format!("{}{:?}\n", separator, e);
    let mut current = e.source();
    while let Some(cause) = current {
        let str = format!("Caused by:\n\n{:?}", cause);
        report = format!("{}\n{}", report, str);
        current = cause.source();
    }
    report = format!("{}\n{}", report, separator);
    ::tracing::error!("{}", report);
}