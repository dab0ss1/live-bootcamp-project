use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    Password, app_state::AppState, domain::{AuthAPIError, Email, User}, password
};

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // Attempt to pase email and passowrd 
    let (email, password) = match (Email::parse(request.email), Password::parse(request.password)) {
        (Ok(email), Ok(password)) => (email, password),
        // Invalid params 
        _ => return Err(AuthAPIError::InvalidCredentials)
    };

    // let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.read().await;

    // Credentials failed to validate 
    if user_store.validate_user(&email, &password).await.is_err() {
        return Err(AuthAPIError::IncorrectCredentials);
    }

    // User for email doesn't exist
    let user = match user_store.get_user(&email).await {
        Ok(u) => u,
        _ => {
            return Err(AuthAPIError::IncorrectCredentials);
        }
    };

    // // Unable to add user for an unexpected reason
    // if user_store.add_user(user).await.is_err() {
    //     return Err(AuthAPIError::UnexpectedError);
    // }

    let response = Json(LoginResponse {
        message: "User logged-in successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}


#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct LoginResponse {
    pub message: String,
}