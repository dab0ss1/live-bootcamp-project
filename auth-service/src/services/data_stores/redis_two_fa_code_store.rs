use std::sync::Arc;

use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

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
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let tuple = TwoFATuple(login_attempt_id.as_ref().to_string(), code.as_ref().to_string());
        let string_value = serde_json::to_string(&tuple)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let ttl = TEN_MINUTES_IN_SECONDS as u64;

        let _: () = self.conn.write().await.set_ex(&key, string_value, ttl)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(email);

        let _: () = self.conn.write().await.del(&key)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(email);

        let string_value: String = self.conn.write().await.get::<_, String>(&key)
            .map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;

        let two_fa_tuple: TwoFATuple = serde_json::from_str(&string_value)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        let login_attempt_id: LoginAttemptId = LoginAttemptId::parse(two_fa_tuple.0)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let code: TwoFACode = TwoFACode::parse(two_fa_tuple.1)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok((login_attempt_id, code))
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}
