use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{
    Form, Router,
    response::Html,
    routing::{get, post},
};
use rand::rngs::OsRng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use tracing_appender::non_blocking::WorkerGuard;

use tokio::sync::Mutex;
use tracing::{error, info}; //add Level and warn if needed
use tracing_subscriber::{fmt, prelude::*}; //add Registry if needed

fn init_log() -> (WorkerGuard, WorkerGuard) {
    /* configure general logs */
    let general_file_appender = tracing_appender::rolling::never("./logs", "general.log");
    let (general_writer, guard1) = tracing_appender::non_blocking(general_file_appender);

    let general_layer = fmt::layer().with_writer(general_writer).with_filter(
        tracing_subscriber::filter::filter_fn(|metadata| metadata.target() != "security"),
    );

    /* configure security logs */
    let security_file_appender = tracing_appender::rolling::never("./logs", "security.log");
    let (security_writer, guard2) = tracing_appender::non_blocking(security_file_appender);

    let security_layer = fmt::layer().with_writer(security_writer).with_filter(
        tracing_subscriber::filter::filter_fn(|metadata| metadata.target() == "security"),
    );

    /* register both layers in one subscriber */
    tracing_subscriber::registry()
        .with(general_layer)
        .with(security_layer)
        .init();

    (guard1, guard2)
}

#[tokio::main]
async fn main() {
    let (_guard1, _guard2) = init_log();
    info!("general log initialized successfully");
    info!(target: "security", "security log initialized");
    let app = Router::new()
        .route("/", get(login_html))
        .route("/login", post(handle_login))
        .route("/register", get(register_html).post(handle_register));

    let port: u16 = env::var("PORTNUM")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(3000);
    let address = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&address).await;
    let listener = match listener {
        Ok(listener) => listener,
        Err(e) => {
            error!("Failed to bind to port 3000: {}", e);
            panic!(
                "error occurred: read logs/general.log or security.log for more details: {}",
                e
            );
        }
    };
    println!("Server running on http://localhost:3000");
    let axum_result = axum::serve(listener, app).await;
    if let Err(e) = axum_result {
        error!("Server error: {}", e);
        panic!(
            "error occurred: read logs/general.log or security.log for more details: {}",
            e
        );
    }
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct RegisterForm {
    username: String,
    email: String,
    password: String,
    password_confirm: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct User {
    username: String,
    email: String,
    password_hash: String,
}

const USERS_FILE: &str = "data/users.json";

fn load_users() -> HashMap<String, User> {
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

fn save_users(users: &HashMap<String, User>) -> Result<(), std::io::Error> {
    tokio::task::block_in_place(|| {
        let json = serde_json::to_string_pretty(users)?;
        // Write to a temporary file first, then move it into place.
        let tmp_path = format!("{}.tmp", USERS_FILE); //consider putting this in /tmp≥
        fs::write(&tmp_path, json)?;

        // On Windows, std::fs::rename fails if the destination already exists.
        // Remove the existing file (if any) before renaming to ensure cross-platform behavior.
        if Path::new(USERS_FILE).exists() {
            fs::remove_file(USERS_FILE)?;
        }

        fs::rename(&tmp_path, USERS_FILE)
    })
}

fn validate_username(username: &str) -> Result<(), String> {
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

fn validate_email(email: &str) -> Result<(), String> {
    let email_regex = EMAIL_REGEX.get_or_init(|| {
        Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .expect("Invalid email regex")
    });
    if !email_regex.is_match(email) {
        return Err("Invalid email format".to_string());
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), String> {
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

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}

async fn handle_login(Form(form): Form<LoginForm>) -> impl IntoResponse {
    info!(target: "security", "Login attempt for username: {}", form.username);

    // Ensure we don't read the users file while a registration is writing it.
    let lock = USER_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().await;

    let users = load_users();

    match users.get(&form.username) {
        Some(user) => match verify_password(&form.password, &user.password_hash) {
            Ok(true) => {
                info!(target: "security", "Login successful for username: {}", form.username);
                info!("sending response with status code: {}", StatusCode::OK);
                (
                    StatusCode::OK,
                    Html(format!(
                        "<h1>Login Successful</h1>\
                             <p>Welcome, {}!</p>\
                             <a href='/'>Back to login</a>",
                        form.username
                    )),
                )
            }
            Ok(false) => {
                info!(target: "security", "Login failed: invalid password for username: {}", form.username);
                info!("sending response with status code: {}", StatusCode::UNAUTHORIZED);
                (
                    StatusCode::UNAUTHORIZED,
                    Html("<h1>Login Failed</h1><p>Invalid username or password.</p><a href='/'>Back to login</a>".to_string()),
                )
            }
            Err(e) => {
                error!("Error verifying password: {}", e);
                info!("sending response with status code: {}", StatusCode::INTERNAL_SERVER_ERROR);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Html("<h1>Login Failed</h1><p>An internal error occurred while verifying your credentials.</p><a href='/'>Back to login</a>".to_string()),
                )
            }
        },
        None => {
            info!(target: "security", "Login failed: unknown username: {}", form.username);
            (
                StatusCode::UNAUTHORIZED,
                Html("<h1>Login Failed</h1><p>Invalid username or password.</p><a href='/'>Back to login</a>".to_string()),
            )
        }
    }
}

static USER_FILE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

async fn handle_register(Form(form): Form<RegisterForm>) -> impl IntoResponse {
    info!(target: "security", "Registration attempt for username: {}", form.username);

    // Validate username
    if let Err(e) = validate_username(&form.username) {
        info!(target: "security", "Registration failed: {}", e);
        return (
            StatusCode::BAD_REQUEST,
            Html(format!(
                "<h1>Registration Failed</h1><p>{}</p><a href='/register'>Back</a>",
                e
            )),
        );
    }

    // Validate email
    if let Err(e) = validate_email(&form.email) {
        info!(target: "security", "Registration failed: {}", e);
        return (
            StatusCode::BAD_REQUEST,
            Html(format!(
                "<h1>Registration Failed</h1><p>{}</p><a href='/register'>Back</a>",
                e
            )),
        );
    }

    // Validate password
    if let Err(e) = validate_password(&form.password) {
        info!(target: "security", "Registration failed: {}", e);
        return (
            StatusCode::BAD_REQUEST,
            Html(format!(
                "<h1>Registration Failed</h1><p>{}</p><a href='/register'>Back</a>",
                e
            )),
        );
    }

    // Check password confirmation
    if form.password != form.password_confirm {
        info!(target: "security", "Registration failed: passwords do not match");
        info!("sending response with status code: {}", StatusCode::BAD_REQUEST);
        return (
            StatusCode::BAD_REQUEST,
            Html("<h1>Registration Failed</h1><p>Passwords do not match</p><a href='/register'>Back</a>".to_string()),
        );
    }

    // Hash password before taking the lock to reduce contention
    let password_hash = match hash_password(&form.password) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to hash password: {}", e);
            info!("sending response with status code: {}", StatusCode::INTERNAL_SERVER_ERROR);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<h1>Registration Failed</h1><p>Server error</p><a href='/register'>Back</a>".to_string()),
            );
        }
    };

    // Serialize access to the user store to avoid concurrent read-modify-write races.
    let lock = USER_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().await;

    // Re-check for duplicates under the lock before saving
    let mut users = load_users();
    if users.contains_key(&form.username) {
        info!(target: "security", "Registration failed: username '{}' already exists", form.username);
        info!("sending response with status code: {}", StatusCode::CONFLICT);
        return (
            StatusCode::CONFLICT,
            Html("<h1>Registration Failed</h1><p>Username already exists</p><a href='/register'>Back</a>".to_string()),
        );
    }
    if users.values().any(|u| u.email == form.email) {
        info!(target: "security", "Registration failed: email '{}' already exists", form.email);
        info!("sending response with status code: {}", StatusCode::CONFLICT);
        return (
            StatusCode::CONFLICT,
            Html("<h1>Registration Failed</h1><p>Email already exists</p><a href='/register'>Back</a>".to_string()),
        );
    }

    // Save user
    let user = User {
        username: form.username.clone(),
        email: form.email.clone(),
        password_hash,
    };
    users.insert(form.username.clone(), user);

    if let Err(e) = save_users(&users) {
        error!("Failed to save users: {}", e);
        info!("sending response with status code: {}", StatusCode::INTERNAL_SERVER_ERROR);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html("<h1>Registration Failed</h1><p>Server error</p><a href='/register'>Back</a>".to_string()),
        );
    }

    info!(target: "security", "Registration successful for username: {}", form.username);
    info!("sending response with status code: {}", StatusCode::OK);
    (
        StatusCode::OK,
        Html("<h1>Registration Successful</h1><p>Account created successfully!</p><a href='/'>Login</a>".to_string()),
    )
}

/* handler for login page */
async fn login_html() -> Html<String> {
    info!("Serving login.html to client");
    let contents = include_str!("../templates/login.html").to_string();
    Html(contents)
}

/* handler for register page */
async fn register_html() -> Html<String> {
    info!("Serving register.html to client");
    let contents = include_str!("../templates/register.html").to_string();
    Html(contents)
}
