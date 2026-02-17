use validator::{Validate, ValidationErrors};

#[derive(Clone, Eq, PartialEq, Hash, Validate)]
pub struct Email {
    #[validate(email)]
    #[validate(length(min = 1))]
    email: String
}

impl Email {
    pub fn parse(email: String) -> Result<Email, ValidationErrors> {
        let email_struct = Email { email };
        match email_struct.validate() {
            Ok(_) => Ok(email_struct),
            Err(e) => Err(e)
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.email
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_email_ok() {
        let email = "bob@gmail.com".to_string();

        let email_result = Email::parse(email);

        assert!(email_result.is_ok());
    }

    #[tokio::test]
    async fn test_email_missing_at_char() {
        let email = "bobgmail.com".to_string();

        let email_result = Email::parse(email);

        assert!(email_result.is_err());
    }

    #[tokio::test]
    async fn test_email_empty() {
        let email = "".to_string();

        let email_result = Email::parse(email);

        assert!(email_result.is_err());
    }
}