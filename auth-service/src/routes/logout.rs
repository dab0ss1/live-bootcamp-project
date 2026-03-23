use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie, CookieJar};
use secrecy::SecretString;
use tracing::instrument;

use crate::{
    AppState, domain::AuthAPIError, utils::{auth::validate_token, constants::JWT_COOKIE_NAME}
};

#[instrument(name = "Logout", skip_all)]
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let Some(cookie) = jar.get(JWT_COOKIE_NAME) else {
        return (jar, Err(AuthAPIError::MissingToken));
    };

    let token = SecretString::new(cookie.value().to_owned().into_boxed_str());

    if validate_token(state.banned_token_store.clone(), &token).await.is_err() {
        return (jar, Err(AuthAPIError::InvalidToken));
    }

    // Remove JWT cookie from the CookieJar
    let jar = jar.remove(cookie::Cookie::from(JWT_COOKIE_NAME));

    // Ban token from being used again
    if let Err(e) = state.banned_token_store.write().await.banish_token(token).await {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    (jar, Ok(StatusCode::OK))
}
