use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{
    Form, Router,
    response::Html,
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;

use std::env;
use std::sync::{OnceLock, Arc};
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{error, info};
mod log;
use crate::log::init_log;
use crate::users::{
    LoginForm, RegisterForm, User, UserRole, hash_password, load_users, save_users, validate_email,
    validate_password, validate_username, verify_password,
}; //add Registry if needed

use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

mod users;

#[tokio::main]
async fn main() {
    let (_guard1, _guard2) = init_log();
    info!("general log initialized successfully");
    info!(target: "security", "security log initialized");

    let dotenv_result = dotenvy::dotenv(); //load .env file if it exists
    if let Err(e) = dotenv_result {
        error!("Failed to load .env file: {}", e);
    }

    let certfile = env::var("CERTFILE").unwrap_or_else(|_| "cert.pem".to_string());
    let keyfile = env::var("KEYFILE").unwrap_or_else(|_| "key.pem".to_string());
    info!(target: "security", "Using TLS certificate file: {}", certfile);
    info!(target: "security", "Using TLS key file: {}", keyfile);

    let config = RustlsConfig::from_pem_file(&certfile, &keyfile).await;
    let config = match config {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load TLS configuration: {}", e);
            error!(
                target: "security",
                "to create self-signed cert and key, you can run:\nopenssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'"
            );
            eprintln!(
                "Failed to load TLS configuration: {}, you can run:\nopenssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'",
                e
            );
            panic!(
                "error occurred: read logs/general.log or security.log for more details: {}",
                e
            );
        }
    };

    let login_governor_conf = Arc::new(
    GovernorConfigBuilder::default()
        .period(Duration::from_secs(6)) // 1 token every 6 seconds
        .burst_size(10)                 // allow up to 10 requests at once
        .finish()
        .unwrap(),
    );

    let app = Router::new()
        .route("/", get(login_html))
        .route("/login", post(handle_login).layer(GovernorLayer::new(login_governor_conf.clone())),)
        .route("/register", get(register_html).post(handle_register));

    let port: u16 = env::var("PORTNUM")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(3000);

    let address: std::net::SocketAddr = match format!("0.0.0.0:{port}").parse() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Failed to parse server address from port {}: {}", port, e);
            panic!(
                "error occurred: read logs/general.log or security.log for more details: {}",
                e
            );
        }
    };

    info!("Server running on https://{address}");
    println!("Server running on https://{address}");

    // Use axum_server with Rustls — this replaces TcpListener + axum::serve
    if let Err(e) = axum_server::bind_rustls(address, config)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
    {
        error!("Server error: {}", e);
        panic!(
            "error occurred: read logs/general.log or security.log for more details: {}",
            e
        );
    }
}

async fn handle_login(Form(form): Form<LoginForm>) -> impl IntoResponse {
    let user_lock = USER_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = user_lock.lock().await;
    let users = load_users();

    match users.get(&form.username) {
        Some(user) => match verify_password(&form.password, &user.password_hash) {
            Ok(true) => {
                info!(target: "security", "Login successful for username: {}", form.username);
                info!("sending response with status code: {}", StatusCode::OK);
                if user.role == UserRole::Unknown {
                    error!(target: "security", "User '{}' has unknown role, defaulting to 'Unknown'", form.username);
                }
                (
                    StatusCode::OK,
                    Html(format!(
                        "<h1>Login Successful</h1>\
                             <p>Welcome, {}! Your role is {}</p>\
                             <a href='/'>Back to login</a>",
                        form.username, user.role
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
        role: UserRole::User,
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
