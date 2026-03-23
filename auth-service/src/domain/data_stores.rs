use super::{User, Email, HashedPassword};
use color_eyre::eyre::{eyre, Report, Result};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}


#[async_trait::async_trait]
pub trait UserStore: Send + Sync {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, raw_password: &SecretString) -> Result<(), UserStoreError>;
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

#[async_trait::async_trait]
pub trait BannedTokenStore: Send + Sync {
    async fn banish_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError>;
    async fn is_token_banished(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError>;
} 

// This trait represents the interface all concrete 2FA code stores should implement
#[async_trait::async_trait]
pub trait TwoFACodeStore: Send + Sync {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login Attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

// New!
impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone)]
pub struct LoginAttemptId(SecretString);

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
        // We can use the expose_secret method to expose the SecretString           
        // in a controlled manner when needed!
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl LoginAttemptId {
    pub fn parse(id: SecretString) -> Result<Self> {
        match Uuid::parse_str(&id.expose_secret()) {
            Ok(_) => Ok(LoginAttemptId(id)),
            Err(_) => Err(eyre!("Invalid login attempt id"))
        }
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        LoginAttemptId(SecretString::new(Uuid::new_v4().to_string().into()))
    }
}

impl AsRef<SecretString> for LoginAttemptId {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct TwoFACode(SecretString);

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
        // We can use the expose_secret method to expose the SecretString           
        // in a controlled manner when needed!
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl TwoFACode {
    pub fn parse(code: SecretString) -> Result<Self> {
        if validate_two_fa_code(&code) {
            Ok(Self(code))
        } else {
            Err(eyre!("Failed to parse string to a TwoFACode type"))
        }
    }
}

fn validate_two_fa_code(s: &SecretString) -> bool {
    s.expose_secret().len() == 6 && s.expose_secret().chars().all(|c| c.is_ascii_digit())
}

impl Default for TwoFACode {
    fn default() -> Self {
        // Use the `rand` crate to generate a random 2FA code.
        // The code should be 6 digits (ex: 834629)
        TwoFACode(SecretString::new(rand::rng().random_range(100_000..=999_999).to_string().into()))

    }
}

impl AsRef<SecretString> for TwoFACode {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}