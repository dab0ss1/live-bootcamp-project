use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use secrecy::SecretString;
use serde::Deserialize;

use crate::{
    app_state::AppState, auth::validate_token, domain::AuthAPIError
};

#[tracing::instrument(name = "Verifying token", skip_all)]
pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {

    if validate_token(state.banned_token_store.clone(), &request.token).await.is_err() {
        return Err(AuthAPIError::InvalidToken);
    }

    Ok(StatusCode::OK.into_response())
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: SecretString,
}