#[derive(Clone, PartialEq)]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Password, String> {
        if password.len() < 8 {
            Err(String::from("Password needed to be 8 characters or longer"))
        } else {
            Ok(Password(password))
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_password_ok() {
        let password = "12345678".to_string();

        let password_result = Password::parse(password);

        assert!(password_result.is_ok());
    }

    #[tokio::test]
    async fn test_password_is_too_short() {
        let password = "1234567".to_string();

        let password_result = Password::parse(password);

        assert!(password_result.is_err());
    }

    #[tokio::test]
    async fn test_password_empty() {
        let password = "".to_string();

        let password_result = Password::parse(password);

        assert!(password_result.is_err());
    }
}