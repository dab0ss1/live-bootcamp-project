use std::sync::Arc;

use redis::{Commands, Connection};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use color_eyre::eyre::Context;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    Email,
};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    #[tracing::instrument(name = "Add 2FA Code", skip_all)]
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let tuple = TwoFATuple(login_attempt_id.as_ref().expose_secret().to_string(), code.as_ref().expose_secret().to_string());
        let string_value = serde_json::to_string(&tuple)
            .wrap_err("failed to serialize 2FA tuple")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        let ttl = TEN_MINUTES_IN_SECONDS as u64;

        let _: () = self.conn.write().await.set_ex(&key, string_value, ttl)
            .wrap_err("failed to set 2FA code in Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;

        Ok(())
    }

    #[tracing::instrument(name = "Remove 2FA Code", skip_all)]
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(email);

        let _: () = self.conn.write().await.del(&key)
            .wrap_err("failed to delete 2FA code from Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;

        Ok(())
    }

    #[tracing::instrument(name = "Get 2FA Code", skip_all)]
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(email);

        let string_value: String = self.conn.write().await.get::<_, String>(&key)
            .map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;

        let two_fa_tuple: TwoFATuple = serde_json::from_str(&string_value)
            .wrap_err("failed to deserialize 2FA tuple")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;

        let login_attempt_id: LoginAttemptId = LoginAttemptId::parse(SecretString::new(two_fa_tuple.0.into()))
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        let code: TwoFACode = TwoFACode::parse(SecretString::new(two_fa_tuple.1.into()))
            .map_err(TwoFACodeStoreError::UnexpectedError)?;

        Ok((login_attempt_id, code))
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref().expose_secret())
}
