use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{
    Password, 
    app_state::AppState, 
    domain::{AuthAPIError, Email}, 
    utils::auth::generate_auth_cookie,
};

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Attempt to pase email and passowrd 
    let (email, password) = match (Email::parse(request.email), Password::parse(request.password)) {
        (Ok(email), Ok(password)) => (email, password),
        // Invalid params 
        _ => return (jar, Err(AuthAPIError::InvalidCredentials))
    };

    let mut user_store = state.user_store.read().await;

    // Credentials failed to validate 
    if user_store.validate_user(&email, &password).await.is_err() {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    // User for email doesn't exist
    if user_store.get_user(&email).await.is_err() {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        _ => {
            return (jar, Err(AuthAPIError::UnexpectedError));
        }
    };

    let updated_jar = jar.add(auth_cookie);

    (updated_jar, Ok(StatusCode::OK.into_response()))
}


#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}