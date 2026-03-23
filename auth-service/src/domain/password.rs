use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use color_eyre::eyre::{eyre, Context, Result};
use secrecy::{ExposeSecret, SecretString};

#[derive(Debug, Clone)]
pub struct HashedPassword(SecretString);

impl PartialEq for HashedPassword {
    fn eq(&self, other: &Self) -> bool {
        // We can use the expose_secret method to expose the SecretString           
        // in a controlled manner when needed!
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl HashedPassword {
    #[tracing::instrument(name = "HashedPassword Parse", skip_all)]
    pub async fn parse(s: SecretString) -> Result<Self> {
       if validate_password(&s) {
            let result = compute_password_hash(&s)
                .await
                .map_err(|e| eyre!("Failed to compute password hash: {}", e))?;

            Ok(Self(result))
        } else {
            Err(eyre!("Failed to parse string to a HashedPassword type"))
        }
    }

    #[tracing::instrument(name = "HashedPassword Parse password hash", skip_all)]
    pub fn parse_password_hash(hash: SecretString) -> Result<HashedPassword> {
          if let Ok(hashed_string) = 
            PasswordHash::new(hash.expose_secret().as_ref()) {
                Ok(Self(SecretString::new(
                    hashed_string.to_string().into_boxed_str(),
                    )))
          } else {
            Err(eyre!("Failed to parse string to a HashedPassword type"))
          }
    }

    #[tracing::instrument(name = "HashedPassword Verify raw password", skip_all)]
    pub async fn verify_raw_password(&self, password_candidate: &SecretString) -> Result<()> {
        let current_span: tracing::Span = tracing::Span::current();

        let password_hash = self.as_ref().expose_secret().to_owned();
        let password_candidate =            
            password_candidate.expose_secret().to_owned();
        let result = tokio::task::spawn_blocking(move || {
            current_span.in_scope(|| {
                let expected_password_hash: PasswordHash<'_> = 
                    PasswordHash::new(&password_hash)?;

                Argon2::default()
                    .verify_password(
                    password_candidate.as_bytes(), 
                    &expected_password_hash)
                    .wrap_err("failed to verify password hash")
            })
        })
        .await?;

        result
    }
}

// Helper function to hash passwords before persisting them in storage.
#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: &SecretString) -> Result<SecretString> {
    // This line retrieves the current span from the tracing context. 
    // The span represents the execution context for the compute_password_hash function.
    let current_span: tracing::Span = tracing::Span::current();

    let password = password.expose_secret().to_owned();
    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
          let salt: SaltString = SaltString::generate(&mut OsRng);
          let password_hash = Argon2::new(
              Algorithm::Argon2id,
              Version::V0x13,
              Params::new(15000, 2, 1, None)?,
          )
          .hash_password(password.as_bytes(), &salt)?
          .to_string();

          Ok(SecretString::new(password_hash.into_boxed_str()))
        })
    })
    .await?;

    result
}

fn validate_password(s: &SecretString) -> bool {
    s.expose_secret().len() >= 8
}

impl AsRef<SecretString> for HashedPassword {
    fn as_ref(&self) -> &SecretString {
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
    use secrecy::{ExposeSecret, SecretString};

    // updated!
    #[tokio::test]
    async fn empty_string_is_rejected() {
        let password = SecretString::new("".to_string().into_boxed_str());
        
        // updated!
        assert!(HashedPassword::parse(password).await.is_err()); 
    }

    // updated!
    #[tokio::test]
    async fn string_less_than_8_characters_is_rejected() {
      let password = SecretString::new("1234567".to_owned().into_boxed_str());
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
            (SecretString::new(hash_string.clone().into_boxed_str())).unwrap();

        // Assert
        assert_eq!(hash_password.0.expose_secret(), hash_string.as_str());
        assert!(hash_password.0.expose_secret().starts_with("$argon2id$v=19$"));
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
            SecretString::new(hash_string.clone().into_boxed_str()))
            .unwrap();

        assert_eq!(hash_password.as_ref().expose_secret(), hash_string.as_str());
        assert!(hash_password.as_ref().expose_secret().starts_with("$argon2id$v=19$"));

        let result = hash_password.verify_raw_password(
                &SecretString::new(raw_password.to_string().into_boxed_str())
            ).await.unwrap();
        assert_eq!(result, ())
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub SecretString);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
            let password: String = FakePassword(8..30).fake_with_rng(&mut rng);
            Self(SecretString::new(password.into_boxed_str()))
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
