use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use std::error::Error;

#[derive(Debug, Clone, PartialEq)]
pub struct HashedPassword(String);

impl HashedPassword {

  pub async fn parse(s: String) -> Result<Self, String> {
    // validate password
    if s.len() < 8 {
        return Err("Password must be at minimum length of 8".to_string());
    }

    // compute hash
    let hashed_password = match compute_password_hash(&s).await {
        Ok(pass) => pass,
        Err(_) => return Err("Failed to compute password hash".to_string())
    };

    // return hashed password 
    Ok(Self(hashed_password))
  }

  pub fn parse_password_hash(
      hash: String
    ) -> Result<HashedPassword, String>{
      if PasswordHash::new(&hash).is_err() {
        return Err("Failed to parse password hash".to_string());
      }
      Ok(HashedPassword(hash))
    }

  pub async fn verify_raw_password(
        &self,
        password_candidate: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let password_hash = self.as_ref().to_owned();
        let password_candidate = password_candidate.to_owned();

        tokio::task::spawn_blocking(move || {
            let expected_password_hash: PasswordHash<'_> = PasswordHash::new(&password_hash)?;
            return Argon2::default().verify_password(
                password_candidate.as_bytes(),
                &expected_password_hash).map_err(|e| e.into());
        }).await?
    }
}

// Helper function to hash passwords before persisting them in storage.
async fn compute_password_hash(password: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    let password = password.to_owned();

    let password_hash = tokio::task::spawn_blocking(move || {
        let salt: SaltString = SaltString::generate(&mut OsRng);

        let hash = Argon2::new(
                    Algorithm::Argon2id,
                    Version::V0x13,
                    Params::new(15000, 2, 1, None)?,
                )
                .hash_password(password.as_bytes(), &salt)?
                .to_string();

        Ok(hash)
    }).await?;
    
    password_hash
}

impl AsRef<str> for HashedPassword {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::HashedPassword; // updated!
    use argon2::{ // new
        password_hash::{rand_core::OsRng, SaltString},
        Algorithm, Argon2, Params, PasswordHasher, Version
    };
    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use quickcheck::Gen;
    use rand::SeedableRng;

    // updated!
    #[tokio::test]
    async fn empty_string_is_rejected() {
        let password = "".to_owned();
        
        // updated!
        assert!(HashedPassword::parse(password).await.is_err()); 
    }

    // updated!
    #[tokio::test]
    async fn string_less_than_8_characters_is_rejected() {
      let password = "1234567".to_owned();
      // updated!
      assert!(HashedPassword::parse(password).await.is_err());
    }
  
    // new
   #[test]
    fn can_parse_valid_argon2_hash() {
        // Arrange - Create a valid Argon2 hash
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        // Act
        let hash_password = HashedPassword::parse_password_hash
            (hash_string.clone()).unwrap();

        // Assert
        assert_eq!(hash_password.as_ref(), hash_string.as_str());
        assert!(hash_password.as_ref().starts_with("$argon2id$v=19$"));
    }

    // new
    #[tokio::test]
    async fn can_verify_raw_password() {
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let hash_password = HashedPassword::parse_password_hash(
            hash_string
            .clone())
            .unwrap();

        assert_eq!(hash_password.as_ref(), hash_string.as_str());
        assert!(hash_password.as_ref().starts_with("$argon2id$v=19$"));

        let result = hash_password.verify_raw_password(raw_password).await.unwrap();
        assert_eq!(result, ())
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub String);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
            let password = FakePassword(8..30).fake_with_rng(&mut rng);
            Self(password)
        }
    }

    // updated!
    #[tokio::test]
    #[quickcheck_macros::quickcheck]
    async fn valid_passwords_are_parsed_successfully(valid_password: 
    ValidPasswordFixture) -> bool {
        HashedPassword::parse(valid_password.0).await.is_ok() // updated!
    }
}
