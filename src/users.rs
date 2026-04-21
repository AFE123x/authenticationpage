use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::rngs::OsRng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use tracing::error;

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RegisterForm {
    pub username: String,
    pub email: String,
    pub password: String,
    pub password_confirm: String,
}

#[derive(Deserialize)]
pub struct ResetPassword {
    pub username: String,
    pub currentpassword: String,
    pub newpassword: String,
    pub confirmnewpassword: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub enum UserRole {
    User,
    Admin,
    Guest,
    #[serde(other)]
    Unknown,
}

impl Default for UserRole {
    fn default() -> Self {
        Self::Unknown
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::User => write!(f, "User"),
            UserRole::Admin => write!(f, "Admin"),
            UserRole::Guest => write!(f, "Guest"),
            UserRole::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub username: String,
    pub email: String,
    pub password_hash: String,
    #[serde(default)]
    pub role: UserRole,
    #[serde(default)]
    pub failed_attempts: u32,
    #[serde(default)]
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
}

const USERS_FILE: &str = "data/users.json";

pub fn load_users() -> HashMap<String, User> {
    tokio::task::block_in_place(|| {
        if !Path::new(USERS_FILE).exists() {
            return HashMap::new();
        }

        let contents = match fs::read_to_string(USERS_FILE) {
            Ok(contents) => contents,
            Err(e) => {
                error!("Failed to read users file '{}': {}", USERS_FILE, e);
                // Fall back to an empty user map instead of panicking to keep the server running.
                return HashMap::new();
            }
        };

        match serde_json::from_str(&contents) {
            Ok(users) => users,
            Err(e) => {
                error!("Failed to parse users file '{}': {}", USERS_FILE, e);
                // Fall back to an empty user map instead of panicking to keep the server running.
                HashMap::new()
            }
        }
    })
}

pub fn save_users(users: &HashMap<String, User>) -> Result<(), std::io::Error> {
    tokio::task::block_in_place(|| {
        let json = serde_json::to_string_pretty(users)?;

        // Use a unique temporary file to avoid conflicts with concurrent saves
        use rand::{Rng, distributions::Alphanumeric};
        let tmp_suffix: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        let tmp_path = format!("{}.{}.tmp", USERS_FILE, tmp_suffix);

        fs::write(&tmp_path, json)?;

        // On Windows, std::fs::rename fails if the destination already exists.
        // Remove the existing file (if any) before renaming to ensure cross-platform behavior.
        if Path::new(USERS_FILE).exists() {
            fs::remove_file(USERS_FILE)?;
        }

        fs::rename(&tmp_path, USERS_FILE)
    })
}

pub fn validate_username(username: &str) -> Result<(), String> {
    let len = username.chars().count();
    if len < 3 || len > 20 {
        return Err("Username must be 3-20 characters long".to_string());
    }
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(
            "Username can only contain alphanumeric characters and underscores".to_string(),
        );
    }
    Ok(())
}

static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();

pub fn validate_email(email: &str) -> Result<(), String> {
    let email_regex = EMAIL_REGEX.get_or_init(|| {
        Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .expect("Invalid email regex")
    });
    if !email_regex.is_match(email) {
        return Err("Invalid email format".to_string());
    }
    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 12 {
        return Err("Password must be at least 12 characters long".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err("Password must contain at least one uppercase letter".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err("Password must contain at least one lowercase letter".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one number".to_string());
    }
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err("Password must contain at least one special character".to_string());
    }
    Ok(())
}

// Users are now stored in data/users.json

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}
