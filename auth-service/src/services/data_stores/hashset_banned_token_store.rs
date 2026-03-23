use std::collections::HashSet;

use secrecy::{ExposeSecret, SecretString};

use crate::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    set: HashSet<String>
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn banish_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError>{
        self.set.insert(token.expose_secret().to_string());
        Ok(())
    }

    async fn is_token_banished(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError> {
        Ok(self.set.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_banish_token() {
        let mut store = HashsetBannedTokenStore::default();
        let token = SecretString::new("my_token".into());

        store.banish_token(token.clone()).await;

        let result = store.is_token_banished(&token).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_token_not_banished_by_default() {
        let store = HashsetBannedTokenStore::default();
        let token = SecretString::new("unknown_token".into());

        let result = store.is_token_banished(&token).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_multiple_tokens() {
        let mut store = HashsetBannedTokenStore::default();

        let token1 = SecretString::new("token1".into());
        let token2 = SecretString::new("token2".into());

        store.banish_token(token1.clone()).await;
        store.banish_token(token2.clone()).await;
        let result1 = store.is_token_banished(&token1).await;
        assert!(result1.is_ok());
        assert!(result1.unwrap());

        let result2 = store.is_token_banished(&token2).await;
        assert!(result2.is_ok());
        assert!(result2.unwrap());

        let result3 = store.is_token_banished(&SecretString::new("other_token".into())).await;
        assert!(result3.is_ok());
        assert!(!result3.unwrap());
    }

    #[tokio::test]
    async fn test_banish_same_token_twice() {
        let mut store = HashsetBannedTokenStore::default();
        let token = SecretString::new("duplicate_token".into());

        store.banish_token(token.clone()).await;
        store.banish_token(token.clone()).await;

        let result = store.is_token_banished(&token).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
