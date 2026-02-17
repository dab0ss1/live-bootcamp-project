use std::collections::HashMap;

use crate::Email;
use crate::Password;
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

    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        
        if &user.password == password {
            Ok(())
        } else {
            Err(UserStoreError::InvalidCredentials)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::password;

    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut hus = HashmapUserStore::default();
        let email = Email::parse("email@gamil.com".to_string()).unwrap();
        let password = Password::parse("password".to_string()).unwrap();

        let user = User::new(email, password, false);

        assert!(hus.add_user(user).await.is_ok());
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut hus = HashmapUserStore::default();
        let email = Email::parse("email@gamil.com".to_string()).unwrap();
        let password = Password::parse("password".to_string()).unwrap();

        let user = User::new(email.clone(), password, false);

        assert!(hus.add_user(user).await.is_ok());
        assert!(hus.get_user(&email).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut hus = HashmapUserStore::default();
        let email = Email::parse("email@gamil.com".to_string()).unwrap();
        let password = Password::parse("password".to_string()).unwrap();

        let user = User::new(email.clone(), password.clone(), false);

        assert!(hus.add_user(user).await.is_ok());
        assert!(hus.validate_user(&email, &password).await.is_ok());
    }
}
