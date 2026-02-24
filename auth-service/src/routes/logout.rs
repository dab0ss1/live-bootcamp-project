use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie, CookieJar};

use crate::{
    AppState, domain::AuthAPIError, utils::{auth::validate_token, constants::JWT_COOKIE_NAME}
};

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let Some(cookie) = jar.get(JWT_COOKIE_NAME) else {
        return (jar, Err(AuthAPIError::MissingToken));
    };

    let token = cookie.value().to_owned();

    if validate_token(state.banned_token_store.clone(), &token).await.is_err() {
        return (jar, Err(AuthAPIError::InvalidToken));
    }

    // Remove JWT cookie from the CookieJar
    let jar = jar.remove(cookie::Cookie::from(JWT_COOKIE_NAME));

    // Ban token from being used again
    state.banned_token_store.write().await.banish_token(&token).await;

    (jar, Ok(StatusCode::OK))
}
