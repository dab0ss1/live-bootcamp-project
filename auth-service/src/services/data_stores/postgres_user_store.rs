use sqlx::PgPool;

use crate::{HashedPassword, domain::{
    Email, User, data_stores::{UserStore, UserStoreError}
}, password};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let result = sqlx::query!(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
            user.email.as_ref(),
            user.password.as_ref(),
            user.requires_2fa,
        )
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.code() == Some("23505".into()) => {
                Err(UserStoreError::UserAlreadyExists)
            }
            Err(_) => Err(UserStoreError::UnexpectedError),
        }
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let result = sqlx::query!(
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1",
            email.as_ref()
        )
        .fetch_one(&self.pool)
        .await;

        let record = match result {
            Ok(record) => record,
            Err(sqlx::Error::RowNotFound) => return Err(UserStoreError::UserNotFound),
            Err(_) => return Err(UserStoreError::UnexpectedError),
        };

        let password = match HashedPassword::parse_password_hash(record.password_hash) {
            Ok(p) => p,
            Err(_) => return Err(UserStoreError::UnexpectedError),
        };

        Ok(User {
            email: email.clone(),
            password,
            requires_2fa: record.requires_2fa,
        })
    }

    async fn validate_user(&self, email: &Email, raw_password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;

        user.password
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}
