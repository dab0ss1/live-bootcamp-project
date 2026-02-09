use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{UserStore, services::hashmap_user_store::HashmapUserStore};

// Using a type alias to improve readability!
pub type UserStoreType = Arc<RwLock<dyn UserStore>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
}

impl AppState {
    pub fn new(user_store: UserStoreType) -> Self {
        Self { user_store }
    }
}
