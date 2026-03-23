use std::sync::Arc;

use auth_service::Application;
use auth_service::Email;
use auth_service::HashmapTwoFACodeStore;
use auth_service::HashsetBannedTokenStore;
use auth_service::MockEmailClient;
use auth_service::PostgresUserStore;
use auth_service::PostmarkEmailClient;
use auth_service::RedisBannedTokenStore;
use auth_service::RedisTwoFACodeStore;
use auth_service::constants::DATABASE_URL;
use auth_service::constants::POSTMARK_AUTH_TOKEN;
use auth_service::constants::REDIS_HOST_NAME;
use auth_service::get_postgres_pool;
use auth_service::get_redis_client;
use auth_service::tracing::init_tracing;
use auth_service::utils::constants::prod;
use auth_service::AppState;
use reqwest::Client;
use sqlx::PgPool;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    color_eyre::install().expect("Failed to install color_eyre");
    init_tracing().expect("Failed to initialize tracing");
    // We will use this PostgreSQL pool in the next task! 
    let pg_pool = configure_postgresql().await;
    
    let user_store = PostgresUserStore::new(pg_pool);
    let banned_token_store = RedisBannedTokenStore::new(Arc::new(RwLock::new(configure_redis())));
    let two_fa_code_store = RedisTwoFACodeStore::new(Arc::new(RwLock::new(configure_redis())));
    let email_client = Arc::new(configure_postmark_email_client());
    let app_state: AppState = AppState::new(
                    Arc::new(RwLock::new(user_store)), 
                    Arc::new(RwLock::new(banned_token_store)),
                    Arc::new(RwLock::new(two_fa_code_store)),
                    email_client,
    );

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn configure_postgresql() -> PgPool {
    // Create a new database connection pool
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our test database! 
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}

fn configure_postmark_email_client() -> PostmarkEmailClient {
    let http_client = Client::builder()
        .timeout(prod::email_client::TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");

    PostmarkEmailClient::new(
        prod::email_client::BASE_URL.to_owned(),
        Email::parse(prod::email_client::SENDER.to_owned().into()).unwrap(),
        POSTMARK_AUTH_TOKEN.to_owned(),
        http_client,
    )
}