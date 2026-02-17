#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Email, String> {
        if email.is_empty() {
            Err(String::from("Email is empty"))
        } else if !email.contains("@") {
            Err(String::from("Email is missing '@'"))
        } else {
            Ok(Email(email))
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
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