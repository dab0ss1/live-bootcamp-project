use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    Password, app_state::AppState, domain::{AuthAPIError, Email, User}, password
};

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // Attempt to pase email and passowrd 
    let (email, password) = match (Email::parse(request.email), Password::parse(request.password)) {
        (Ok(email), Ok(password)) => (email, password),
        // Invalid params 
        _ => return Err(AuthAPIError::InvalidCredentials)
    };

    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    // User already exists 
    if user_store.get_user(&user.email).await.is_ok() {
        return Err(AuthAPIError::UserAlreadyExists);
    }

    // Unable to add user for an unexpected reason
    if user_store.add_user(user).await.is_err() {
        return Err(AuthAPIError::UnexpectedError);
    }

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SignupResponse {
    pub message: String,
}