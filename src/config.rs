use std::env;

pub struct JwtConfig {
    pub secret: String,
    pub expiry_minutes: i64,
    pub refresh_expiry_days: i64,
}

impl JwtConfig {
    /// Create a new JwtConfig, validating JWT_SECRET at startup.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - JWT_SECRET environment variable is not set
    /// - JWT_SECRET is less than 32 characters (insufficient strength)
    /// - JWT_SECRET is a known weak value like "secret" or "password"
    pub fn new() -> Self {
        let secret = env::var("JWT_SECRET")
            .expect("JWT_SECRET environment variable must be set for security");

        // Validate secret strength
        Self::validate_secret_strength(&secret);

        Self {
            secret,
            expiry_minutes: 15,
            refresh_expiry_days: 7,
        }
    }

    /// Validates that the JWT secret meets minimum security requirements.
    ///
    /// # Panics
    ///
    /// Panics if the secret is too weak (< 32 chars or common values).
    fn validate_secret_strength(secret: &str) {
        const MIN_SECRET_LENGTH: usize = 32;
        const WEAK_SECRETS: &[&str] = &[
            "secret",
            "password",
            "changeme",
            "default",
            "test",
            "jwt_secret",
            "mySecretKey",
            "supersecret",
            "12345678901234567890123456789012", // 32 digits
        ];

        if secret.len() < MIN_SECRET_LENGTH {
            panic!(
                "JWT_SECRET is too short ({} chars). Must be at least {} characters for security. \
                Generate a strong secret with: openssl rand -base64 48",
                secret.len(),
                MIN_SECRET_LENGTH
            );
        }

        // Check against common weak values (case-insensitive)
        let secret_lower = secret.to_lowercase();
        for weak in WEAK_SECRETS {
            if secret_lower == *weak || secret_lower.starts_with(weak) {
                panic!(
                    "JWT_SECRET appears to be a weak or common value. \
                    Generate a strong secret with: openssl rand -base64 48"
                );
            }
        }
    }

    pub fn expiry_seconds(&self) -> i64 {
        self.expiry_minutes * 60
    }

    pub fn refresh_expiry_seconds(&self) -> i64 {
        self.refresh_expiry_days * 24 * 60 * 60
    }
}

pub const COOKIE_NAME: &str = "jwt";
pub const REFRESH_COOKIE_NAME: &str = "refresh_token";
