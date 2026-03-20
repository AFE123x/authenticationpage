use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{
    Form, Router,
    response::Html,
    routing::{get, post},
};

use std::env;
use std::sync::OnceLock;
use tokio::sync::Mutex;
use tracing::{error, info};
mod log;
use crate::log::init_log;
use crate::users::{
    LoginForm, RegisterForm, User, hash_password, load_users, save_users, validate_email,
    validate_password, validate_username, verify_password,
}; //add Registry if needed

mod users;

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
                info!(
                    "sending response with status code: {}",
                    StatusCode::UNAUTHORIZED
                );
                (
                    StatusCode::UNAUTHORIZED,
                    Html("<h1>Login Failed</h1><p>Invalid username or password.</p><a href='/'>Back to login</a>".to_string()),
                )
            }
            Err(e) => {
                error!("Error verifying password: {}", e);
                info!(
                    "sending response with status code: {}",
                    StatusCode::INTERNAL_SERVER_ERROR
                );
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
        info!(
            "sending response with status code: {}",
            StatusCode::BAD_REQUEST
        );
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
            info!(
                "sending response with status code: {}",
                StatusCode::INTERNAL_SERVER_ERROR
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(
                    "<h1>Registration Failed</h1><p>Server error</p><a href='/register'>Back</a>"
                        .to_string(),
                ),
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
        info!(
            "sending response with status code: {}",
            StatusCode::CONFLICT
        );
        return (
            StatusCode::CONFLICT,
            Html("<h1>Registration Failed</h1><p>Username already exists</p><a href='/register'>Back</a>".to_string()),
        );
    }
    if users.values().any(|u| u.email == form.email) {
        info!(target: "security", "Registration failed: email '{}' already exists", form.email);
        info!(
            "sending response with status code: {}",
            StatusCode::CONFLICT
        );
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
        info!(
            "sending response with status code: {}",
            StatusCode::INTERNAL_SERVER_ERROR
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(
                "<h1>Registration Failed</h1><p>Server error</p><a href='/register'>Back</a>"
                    .to_string(),
            ),
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
