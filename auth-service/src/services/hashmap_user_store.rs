use std::collections::HashMap;

use crate::UserStore;
use crate::domain::User;
use crate::domain::UserStoreError;

#[derive(Default)]
pub struct HashmapUserStore {
    map: HashMap<String, User>
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

    async fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        match self.map.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound)
        }
    }

    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        
        if user.password == password {
            Ok(())
        } else {
            Err(UserStoreError::InvalidCredentials)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut hus = HashmapUserStore::default();

        let user = User::new("email".to_string(), "password".to_string(), false);

        assert!(hus.add_user(user).await.is_ok());
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut hus = HashmapUserStore::default();

        let user = User::new("email".to_string(), "password".to_string(), false);

        assert!(hus.add_user(user).await.is_ok());
        assert!(hus.get_user("email").await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut hus = HashmapUserStore::default();

        let user = User::new("email".to_string(), "password".to_string(), false);

        assert!(hus.add_user(user).await.is_ok());
        assert!(hus.validate_user("email", "password").await.is_ok());
    }
}
