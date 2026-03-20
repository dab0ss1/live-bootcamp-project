use std::sync::Arc;

use redis::{Commands, Connection, TypedCommands};
use tokio::sync::RwLock;

use crate::{
    domain::data_stores::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn banish_token(&mut self, token: &str) -> Result<(), BannedTokenStoreError> {

        let key = get_key(token);
        let ttl = TOKEN_TTL_SECONDS as u64;

        Commands::set_ex::<String, bool, u64>(&mut *self.conn.write().await, key, true, ttl)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;
        Ok(())
    }

    async fn is_token_banished(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        // Check if the token exists by calling the exists method on the Redis connection
        let key = get_key(&token);

        match Commands::exists(&mut *self.conn.write().await, key) {
            Ok(res) => Ok(res),
            Err(_) => Err(BannedTokenStoreError::UnexpectedError),
        }
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}
