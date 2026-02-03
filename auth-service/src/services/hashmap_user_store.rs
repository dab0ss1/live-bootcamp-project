use std::collections::HashMap;

use crate::domain::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[derive(Default)]
pub struct HashmapUserStore {
    map: HashMap<String, User>
}

impl HashmapUserStore {
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.map.contains_key(&user.email) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.map.insert(user.email.clone(), user);
            Ok(())
        }
    }

    pub fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        match self.map.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound)
        }
    }

    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email)?;
        
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

        assert!(hus.add_user(user).is_ok());
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut hus = HashmapUserStore::default();

        let user = User::new("email".to_string(), "password".to_string(), false);

        assert!(hus.add_user(user).is_ok());
        assert!(hus.get_user("email").is_ok());
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut hus = HashmapUserStore::default();

        let user = User::new("email".to_string(), "password".to_string(), false);

        assert!(hus.add_user(user).is_ok());
        assert!(hus.validate_user("email", "password").is_ok());
    }
}
