use crate::{Email, HashedPassword};

#[derive(Clone)]
pub struct User {
    pub email: Email,
    pub password: HashedPassword,
    pub requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: HashedPassword, requires_2fa: bool) -> Self {
        Self { email, password, requires_2fa }
    }
}