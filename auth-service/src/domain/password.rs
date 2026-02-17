use validator::{Validate, ValidationErrors};

#[derive(Clone, PartialEq, Validate)]
pub struct Password {
    #[validate(length(min = 8))]
    password: String
}

impl Password {
    pub fn parse(password: String) -> Result<Password, ValidationErrors> {
        let password_struct = Password { password };
        match password_struct.validate() {
            Ok(_) => Ok(password_struct),
            Err(e) => Err(e)
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.password
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