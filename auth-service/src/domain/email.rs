use std::hash::Hash;

use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, SecretString};


#[derive(Clone, Debug)]
pub struct Email(SecretString);

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        // We can use the expose_secret method to expose the SecretString           
        // in a controlled manner when needed!
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl Eq for Email {}

impl Email {
    pub fn parse(email: SecretString) -> Result<Email> {
        if validate_email(&email) {
            Ok(Self(email))
        } else {
            Err(eyre!(format!(
                "{} is not a valid email.",
                email.expose_secret()
            )))
        }
    }
}

impl AsRef<SecretString> for Email {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

fn validate_email(s: &SecretString) -> bool {
    s.expose_secret().contains('@') && !s.expose_secret().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_email_ok() {
        let email = SecretString::new("bob@gmail.com".to_string().into());

        let email_result = Email::parse(email);

        assert!(email_result.is_ok());
    }

    #[tokio::test]
    async fn test_email_missing_at_char() {
        let email = SecretString::new("bobgmail.com".to_string().into());

        let email_result = Email::parse(email);

        assert!(email_result.is_err());
    }

    #[tokio::test]
    async fn test_email_empty() {
        let email = SecretString::new("".to_string().into());

        let email_result = Email::parse(email);

        assert!(email_result.is_err());
    }
}