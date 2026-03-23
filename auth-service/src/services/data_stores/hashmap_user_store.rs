use std::collections::HashMap;

use secrecy::SecretString;

use crate::Email;
use crate::HashedPassword;
use crate::UserStore;
use crate::domain::User;
use crate::domain::UserStoreError;

#[derive(Default)]
pub struct HashmapUserStore {
    map: HashMap<Email, User>
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.map.contains_key(&user.email) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.map.insert(user.email.clone(), user);
            Ok(())
        }
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        match self.map.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound)
        }
    }

    async fn validate_user(&self, email: &Email, raw_password: &SecretString) -> Result<(), UserStoreError> {
        let user: &User = self.map.get(email)
            .ok_or(UserStoreError::UserNotFound)?;
        
        user.password // updated password verification
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut hus = HashmapUserStore::default();
        let email = Email::parse(SecretString::new("email@gamil.com".to_string().into())).unwrap();
        let raw_password = SecretString::new("password".to_string().into());
        let password = HashedPassword::parse(raw_password.clone()).await.unwrap();

        let user = User::new(email, password, false);

        assert!(hus.add_user(user).await.is_ok());
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut hus = HashmapUserStore::default();
        let email = Email::parse(SecretString::new("email@gamil.com".to_string().into())).unwrap();
        let raw_password = SecretString::new("password".to_string().into());
        let password = HashedPassword::parse(raw_password.clone()).await.unwrap();

        let user = User::new(email.clone(), password, false);

        assert!(hus.add_user(user).await.is_ok());
        assert!(hus.get_user(&email).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut hus = HashmapUserStore::default();
        let email = Email::parse(SecretString::new("email@gamil.com".to_string().into())).unwrap();
        let raw_password = SecretString::new("password".to_string().into());
        let password = HashedPassword::parse(raw_password.clone()).await.unwrap();

        let user = User::new(email.clone(), password.clone(), false);

        assert!(hus.add_user(user).await.is_ok());
        assert!(hus.validate_user(&email, &raw_password).await.is_ok());
    }
}
