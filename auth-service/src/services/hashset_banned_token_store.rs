use std::collections::HashSet;

use crate::BannedTokenStore;

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    set: HashSet<String>
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn banish_token(&mut self, token: &str) {
        self.set.insert(token.to_owned());
    }

    async fn is_token_banished(&self, token: &str) -> bool {
        self.set.contains(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_banish_token() {
        let mut store = HashsetBannedTokenStore::default();
        let token = "my_token";

        store.banish_token(token).await;

        assert!(store.is_token_banished(token).await);
    }

    #[tokio::test]
    async fn test_token_not_banished_by_default() {
        let store = HashsetBannedTokenStore::default();
        let token = "unknown_token";

        assert!(!store.is_token_banished(token).await);
    }

    #[tokio::test]
    async fn test_multiple_tokens() {
        let mut store = HashsetBannedTokenStore::default();

        let token1 = "token1";
        let token2 = "token2";

        store.banish_token(token1).await;
        store.banish_token(token2).await;

        assert!(store.is_token_banished(token1).await);
        assert!(store.is_token_banished(token2).await);
        assert!(!store.is_token_banished("other_token").await);
    }

    #[tokio::test]
    async fn test_banish_same_token_twice() {
        let mut store = HashsetBannedTokenStore::default();
        let token = "duplicate_token";

        store.banish_token(token).await;
        store.banish_token(token).await;

        assert!(store.is_token_banished(token).await);
    }
}
