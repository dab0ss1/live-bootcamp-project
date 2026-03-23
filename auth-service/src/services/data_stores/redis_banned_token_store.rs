use std::sync::Arc;

use redis::{Commands, Connection};
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::RwLock;
use color_eyre::eyre::{eyre, Context, Result};

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
    #[tracing::instrument(name = "Banish Token", skip_all)]
    async fn banish_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError> {

        let key = get_key(token.expose_secret());
        let ttl: u64 = TOKEN_TTL_SECONDS
            .try_into()
            .wrap_err("failed to cast TOKEN_TTL_SECONDS to u64")
            .map_err(BannedTokenStoreError::UnexpectedError)?;

        let _: () = self
            .conn
            .write()
            .await
            .set_ex(&key, true, ttl)
            .wrap_err("failed to set banned token in Redis")
            .map_err(BannedTokenStoreError::UnexpectedError)?;

        Ok(())
    }

    #[tracing::instrument(name = "Is Token Banned", skip_all)]
    async fn is_token_banished(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError> {
        // Check if the token exists by calling the exists method on the Redis connection
        let key = get_key(token.expose_secret());

        match Commands::exists(&mut *self.conn.write().await, key) {
            Ok(res) => Ok(res),
            Err(_) => Err(BannedTokenStoreError::UnexpectedError(
                eyre!("failed to check if token exists in Redis")
            )),
        }
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}
