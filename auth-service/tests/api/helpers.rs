use std::sync::Arc;
use reqwest::{Client, cookie::Jar};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{Connection, Executor, PgConnection, PgPool, postgres::{PgConnectOptions, PgPoolOptions}};
use tokio::sync::RwLock;
use uuid::Uuid;
use auth_service::{
    Application, Email, MockEmailClient, PostgresUserStore, PostmarkEmailClient, RedisBannedTokenStore, RedisTwoFACodeStore, app_state::{AppState, BannedTokenStoreType, TwoFACodeStoreType}, constants::{DATABASE_URL, DEFAULT_REDIS_HOSTNAME}, get_postgres_pool, get_redis_client, utils::constants::test
};
use wiremock::MockServer;
use std::str::FromStr;

pub struct TestApp {
    db_name: String,
    clean_up_called: bool,

    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub http_client: reqwest::Client,
    pub two_fa_code_store: TwoFACodeStoreType,
    pub banned_token_store: BannedTokenStoreType,
    pub email_server: MockServer,
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if !self.clean_up_called {
            panic!("TestApp was not cleaned up. Please call the `clean_up` method to clean up resources.");
        }
    }
}

impl TestApp {
    pub async fn new() -> Self {
        // We are creating a new database for each test case, and we need to ensure each database has a unique name!
        let db_name = Uuid::new_v4().to_string();
        let pg_pool = configure_postgresql(&db_name).await;
        let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
        let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(Arc::new(RwLock::new(configure_redis())))));
        let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFACodeStore::new(Arc::new(RwLock::new(configure_redis())))));
        
        // Set up a mock email server
        let email_server = MockServer::start().await; // New!
        let base_url = email_server.uri(); // New!
        let email_client = Arc::new(configure_postmark_email_client(base_url)); // Updated!

        let app_state = AppState::new(
            user_store, 
            banned_token_store.clone(), 
            two_fa_code_store.clone(),
            email_client,
        );
        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread. 
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let cookie_jar = Arc::new(Jar::default());
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        Self {
            db_name: db_name.to_owned(),
            clean_up_called: false,
            address,
            cookie_jar,
            http_client,
            two_fa_code_store,
            banned_token_store,
            email_server
        }
    }

    pub async fn clean_up(&mut self) {
        delete_database(&self.db_name).await;
        self.clean_up_called = true;
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

async fn configure_postgresql(db_name: &str) -> PgPool {
    let postgresql_conn_url = DATABASE_URL.to_owned();

    configure_database(&postgresql_conn_url, &db_name).await;

    let postgresql_conn_url_with_db = SecretString::new(
        format!("{}/{}", postgresql_conn_url.expose_secret(), db_name).into()
    );

    // Create a new connection pool and return it
    get_postgres_pool(&postgresql_conn_url_with_db)
        .await
        .expect("Failed to create Postgres connection pool!")
}

async fn configure_database(db_conn_string: &SecretString, db_name: &str) {
    // Create database connection
    let connection: sqlx::Pool<sqlx::Postgres> = PgPoolOptions::new()
        .connect(db_conn_string.expose_secret())
        .await
        .expect("Failed to create Postgres connection pool.");

    // Create a new database
    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to create database.");


    // Connect to new database
    let db_conn_string = format!("{}/{}", db_conn_string.expose_secret(), db_name);

    let connection = PgPoolOptions::new()
        .connect(&db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Run migrations against new database
    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");
}

async fn delete_database(db_name: &str) {
    let postgresql_conn_url = DATABASE_URL.to_owned();

    let connection_options = PgConnectOptions::from_str(&postgresql_conn_url.expose_secret())
        .expect("Failed to parse PostgreSQL connection string");

    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    // Kill any active connections to the database
    connection
        .execute(
            format!(
                r#"
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{}'
                  AND pid <> pg_backend_pid();
                "#,
                db_name
            )
            .as_str(),
        )
        .await
        .expect("Failed to drop the database.");

    // Drop the database
    connection
        .execute(format!(r#"DROP DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to drop the database.");
}

fn configure_redis() -> redis::Connection {
    let redis_hostname = DEFAULT_REDIS_HOSTNAME.to_owned();

    get_redis_client(redis_hostname)
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}

fn configure_postmark_email_client(base_url: String) -> PostmarkEmailClient {
    let postmark_auth_token = SecretString::new("auth_token".to_owned().into_boxed_str());

    let sender = Email::parse(SecretString::new(test::email_client::SENDER.to_owned().into_boxed_str())).unwrap();

    let http_client = Client::builder()
        .timeout(test::email_client::TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");

    PostmarkEmailClient::new(base_url, sender, postmark_auth_token, http_client)
}