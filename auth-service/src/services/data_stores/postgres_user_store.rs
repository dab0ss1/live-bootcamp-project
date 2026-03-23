use sqlx::PgPool;
use ::tracing;

use crate::{HashedPassword, domain::{
    Email, User, data_stores::{UserStore, UserStoreError}
}};
use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, SecretString};

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
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let result = sqlx::query!(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
            &user.email.as_ref().expose_secret(),
            &user.password.as_ref().expose_secret(),
            user.requires_2fa,
        )
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) if db_err.code() == Some("23505".into()) => {
                Err(UserStoreError::UserAlreadyExists)
            }
            Err(e) => Err(UserStoreError::UnexpectedError(e.into())),
        }
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let result = sqlx::query!(
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1",
            email.as_ref().expose_secret()
        )
        .fetch_one(&self.pool)
        .await;

        let record = match result {
            Ok(record) => record,
            Err(sqlx::Error::RowNotFound) => return Err(UserStoreError::UserNotFound),
            Err(e) => return Err(UserStoreError::UnexpectedError(e.into())),
        };

        let password = match HashedPassword::parse_password_hash(
            SecretString::new(record.password_hash.into())
        ) {
            Ok(p) => p,
            Err(e) => return Err(UserStoreError::UnexpectedError(eyre!(e))),
        };

        Ok(User {
            email: email.clone(),
            password,
            requires_2fa: record.requires_2fa,
        })
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
    async fn validate_user(&self, email: &Email, raw_password: &SecretString) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;

        user.password
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}
