use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{
    app_state::AppState, auth::generate_auth_cookie, domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode}
};

pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>
) -> (CookieJar, impl IntoResponse) {
    // Attempt to pase request fields
    let (email, login_attempt_id, two_fa_code) = match (
        Email::parse(request.email), LoginAttemptId::parse(request.login_attempt_id), TwoFACode::parse(request.two_fa_code)
    ) {
        (Ok(email), Ok(login_attempt_id), Ok(two_fa_code)) => (email, login_attempt_id, two_fa_code),
        // Invalid params 
        _ => return (jar, Err(AuthAPIError::InvalidCredentials))
    };

    // get store for reading
    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    // check if store contains email entry
    let code_tuple = match two_fa_code_store.get_code(&email).await {
        Ok((login_attempt_id, two_fa_code)) => (login_attempt_id, two_fa_code),
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials))
    };

    // validate login attempt id and two fa code entry vs what was provided in the request
    if code_tuple != (login_attempt_id, two_fa_code) {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    // remove two fa code from store (only allow single use)
    if two_fa_code_store.remove_code(&email).await.is_err() {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    // update jar cookie with auth
    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        _ => {
            return (jar, Err(AuthAPIError::UnexpectedError));
        }
    };
    let updated_jar = jar.add(auth_cookie);

    // return sucessful
    (updated_jar, Ok(StatusCode::OK.into_response()))
}

#[derive(Deserialize)]
pub struct Verify2FARequest {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}