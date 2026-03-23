use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};
use color_eyre::eyre::{eyre, Context, ContextCompat, Result};
use secrecy::{ExposeSecret, SecretString};

use crate::{BannedTokenStoreType, domain::email::Email};

use super::constants::{JWT_COOKIE_NAME, JWT_SECRET};

// Create cookie with a new JWT auth token
#[tracing::instrument(name = "Generate Auth Cookie", skip_all)]
pub fn generate_auth_cookie(email: &Email) -> Result<Cookie<'static>> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

// Create cookie and set the value to the passed-in token string 
#[tracing::instrument(name = "Create Auth Cookie", skip_all)]
fn create_auth_cookie(token: SecretString) -> Cookie<'static> {
    let cookie = Cookie::build((JWT_COOKIE_NAME, token.expose_secret().to_owned()))
        .path("/") // apply cookie to all URLs on the server
        .http_only(true) // prevent JavaScript from accessing the cookie
        .same_site(SameSite::Lax) // send cookie with "same-site" requests, and with "cross-site" top-level navigations.
        .build();

    cookie
}

// This value determines how long the JWT auth token is valid for
pub const TOKEN_TTL_SECONDS: i64 = 600; // 10 minutes

// Create JWT auth token
#[tracing::instrument(name = "Generate Auth Token", skip_all)]
fn generate_auth_token(email: &Email) -> Result<SecretString> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
        .wrap_err("failed to create 10 minute time delta")?;

    // Create JWT expiration time
    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(eyre!("failed to add 10 minutes to current time"))?
        .timestamp();

    // Cast exp to a usize, which is what Claims expects
    let exp: usize = exp.try_into().wrap_err(format!(
        "failed to cast exp time to usize. exp time: {}",
        exp
    ))?;

    let sub = email.as_ref().expose_secret().to_owned();

    let claims = Claims { sub, exp };

    create_token(&claims)
}

// Check if JWT auth token is valid by decoding it using the JWT secret
#[tracing::instrument(name = "Validate Token", skip_all)]
pub async fn validate_token(banned_token_store: BannedTokenStoreType, token: &SecretString) -> Result<Claims> {
    let bts_read = banned_token_store.read().await;
    let is_banished = bts_read.is_token_banished(token).await;
    if is_banished.is_err() || is_banished.unwrap() {
        return Err(eyre!("token is banned"));
    } 
    decode::<Claims>(
        token.expose_secret(),
        &DecodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .wrap_err("failed to decode token")
}

// Create JWT auth token by encoding claims using the JWT secret
#[tracing::instrument(name = "Create Token", skip_all)]
fn create_token(claims: &Claims) -> Result<SecretString> {
    let token = encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
    )
    .wrap_err("failed to create token")?;
    Ok(SecretString::new(token.into()))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use secrecy::SecretString;
    use tokio::sync::RwLock;

    use crate::{HashsetBannedTokenStore};

    use super::*;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse(SecretString::new("test@example.com".to_owned().into())).unwrap();
        let cookie = generate_auth_cookie(&email).unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = SecretString::new("test_token".to_owned().into());
        let cookie = create_auth_cookie(token.clone());
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value(), token.expose_secret());
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse(SecretString::new("test@example.com".to_owned().into())).unwrap();
        let result = generate_auth_token(&email).unwrap();
        assert_eq!(result.expose_secret().split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let hashset_banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
        let email = Email::parse(SecretString::new("test@example.com".to_owned().into())).unwrap();
        let token = generate_auth_token(&email).unwrap();
        let result = validate_token(hashset_banned_token_store, &token).await.unwrap();
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let hashset_banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
        let token = SecretString::new("invalid_token".to_owned().into());
        let result = validate_token(hashset_banned_token_store, &token).await;
        assert!(result.is_err());
    }
}
