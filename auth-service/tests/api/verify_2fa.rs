use crate::helpers::{get_random_email, TestApp};
use secrecy::{ExposeSecret, SecretString, SerializableSecret};
use uuid::Uuid;
use auth_service::{
    ErrorResponse, constants::JWT_COOKIE_NAME, domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore}, routes::TwoFactorAuthResponse
};
use wiremock::{Mock, ResponseTemplate, matchers::{method, path}};

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();
    let password = "password123";

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": password,
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_body = serde_json::json!({
        "email": random_email,
        "password": password
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(response_body.message, "2FA required".to_owned());
    assert!(!response_body.login_attempt_id.is_empty());

    let (login_attempt_id, two_fa_code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(SecretString::new(random_email.clone().into())).unwrap())
        .await
        .unwrap();

    let request_body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
        "2FACode": two_fa_code.as_ref().expose_secret()
    });

    let response = app.post_verify_2fa(&request_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({
            "email": "dog@gmail.coom",
            "loginAttemptId": "random"
        }),
        serde_json::json!({
            "email": "dog@gmail.coom",
            "2FACode": "123456"
        }),
        serde_json::json!({
            "loginAttemptId": "random",
            "2FACode": "123456"
        }),
        serde_json::json!({
            "email": "dog@gmail.coom"
        }),
        serde_json::json!({
            "loginAttemptId": "random"
        }),
        serde_json::json!({
            "2FACode": "123456"
        }),
        serde_json::json!({}),
    ];

    for test_case in test_cases {
        let response = app.post_verify_2fa(&test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();
    let login_attempt_id = LoginAttemptId::default();
    let code = TwoFACode::default();

    let test_cases = [
        serde_json::json!({
            "email": random_email.clone(),
            "loginAttemptId": "bad_uuid",
            "2FACode": code.as_ref().expose_secret()
        }),
        serde_json::json!({
            "email": "bad_email.coom",
            "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
            "2FACode": code.as_ref().expose_secret()
        }),
        serde_json::json!({
            "email": random_email.clone(),
            "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
            "2FACode": "bad_code"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await;
        assert_eq!(response.status().as_u16(), 400, "Failed for input: {:?}", test_case);

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();
    let password = "password123";

    // sign up
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": password,
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    // login
    let login_body = serde_json::json!({
        "email": random_email,
        "password": password
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(response_body.message, "2FA required".to_owned());
    assert!(!response_body.login_attempt_id.is_empty());

    let (login_attempt_id, two_fa_code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(SecretString::new(random_email.clone().into())).unwrap())
        .await
        .unwrap();

    // verify 2fa
    let incorrect_email = get_random_email();
    let incorrect_login_attempt_id = LoginAttemptId::default().as_ref().to_owned();
    let incorrect_two_fa_code = TwoFACode::default();

    let test_cases = vec![
        (
            incorrect_email.as_str(),
            login_attempt_id.as_ref(),
            two_fa_code.clone(),
        ),
        (
            random_email.as_str(),
            &incorrect_login_attempt_id,
            two_fa_code,
        ),
        (
            random_email.as_str(),
            login_attempt_id.as_ref(),
            incorrect_two_fa_code,
        ),
    ];

    for (email, login_attempt_id, code) in test_cases {
        let request_body = serde_json::json!({
            "email": email,
            "loginAttemptId": login_attempt_id.expose_secret(),
            "2FACode": code.as_ref().expose_secret()    
        });

        let response = app.post_verify_2fa(&request_body).await;

        assert_eq!(
            response.status().as_u16(),
            401,
            "Failed for input: {:?}",
            request_body
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Incorrect credentials".to_owned()
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();
    let password = "password123";

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": password,
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&app.email_server)
        .await;

    // login
    let login_body = serde_json::json!({
        "email": random_email,
        "password": password
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(response_body.message, "2FA required".to_owned());
    assert!(!response_body.login_attempt_id.is_empty());

    let (login_attempt_id, two_fa_code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(SecretString::new(random_email.clone().into())).unwrap())
        .await
        .unwrap();

    // login again (throw away response)
    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    // verify 2fa with old id and code
    let request_body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
        "2FACode": two_fa_code.as_ref().expose_secret()
    });

    let response = app.post_verify_2fa(&request_body).await;

    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();
    let password = "password123";

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": password,
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_body = serde_json::json!({
        "email": random_email,
        "password": password
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(response_body.message, "2FA required".to_owned());
    assert!(!response_body.login_attempt_id.is_empty());

    let (login_attempt_id, two_fa_code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(SecretString::new(random_email.clone().into())).unwrap())
        .await
        .unwrap();

    let request_body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
        "2FACode": two_fa_code.as_ref().expose_secret()
    });

    let response = app.post_verify_2fa(&request_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    let response = app.post_verify_2fa(&request_body).await;

    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}