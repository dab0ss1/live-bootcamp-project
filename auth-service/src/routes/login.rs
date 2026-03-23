use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use secrecy::{ExposeSecret, SecretString};


use crate::{
    LoginAttemptId, HashedPassword, TwoFACode, app_state::AppState, domain::{AuthAPIError, Email}, utils::auth::generate_auth_cookie
};

#[instrument(name = "Login", skip_all)]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Attempt to pase email and passowrd 
    let (email, _) = match (Email::parse(request.email), HashedPassword::parse(request.password.clone()).await) {
        (Ok(email), Ok(password)) => (email, password),
        // Invalid params 
        _ => return (jar, Err(AuthAPIError::InvalidCredentials))
    };

    let mut user_store = state.user_store.read().await;

    // Credentials failed to validate 
    if user_store.validate_user(&email, &request.password).await.is_err() {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    // User for email doesn't exist
    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    // Handle request based on user's 2FA configuration
    match user.requires_2fa {
        true => handle_2fa(&user.email, &state, jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
}

#[instrument(name = "Handle 2FA", skip_all)]
async fn handle_2fa(
    email: &Email,
    state: &AppState,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // First, we must generate a new random login attempt ID and 2FA code
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    if let Err(e) = state.two_fa_code_store.write().await.add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone()).await {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    if let Err(e) = state.email_client
        .send_email(email, "Auth key", two_fa_code.as_ref().expose_secret()).await {
            return (jar, Err(AuthAPIError::UnexpectedError(e)));
    }

    let response = Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: login_attempt_id.as_ref().expose_secret().to_owned(),
    }));

    (jar, Ok((StatusCode::PARTIAL_CONTENT, response)))
}

#[instrument(name = "Handle No 2FA", skip_all)]
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(e) => {
            return (jar, Err(AuthAPIError::UnexpectedError(e)));
        }
    };

    let updated_jar = jar.add(auth_cookie);

    (updated_jar, Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: SecretString,
    pub password: SecretString,
}

// The login route can return 2 possible success responses.
// This enum models each response!
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}