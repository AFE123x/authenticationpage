use axum::extract::DefaultBodyLimit;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect};
use axum::{
    Form, Json, Router,
    extract::Multipart,
    extract::Path as AxumPath,
    response::Html,
    routing::{delete, get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;

use serde::{Deserialize, Serialize};
use std::env;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Mutex as TokioMutex;
use tracing::{error, info, warn};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::{RngCore, thread_rng};

mod log;
use crate::log::init_log;
use crate::users::{
    LoginForm, RegisterForm, ResetPassword, USER_FILE_LOCK, User, UserRole, hash_password,
    load_users, save_users, validate_email, validate_password, validate_username, verify_password,
}; //add Registry if needed

use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};

mod documents;
mod sessions;
mod users;
use crate::documents::{
    DocumentResponse, add_document, create_document, delete_document, get_document_by_id,
    get_user_documents, init_documents_dir,
};
use crate::sessions::SessionManager;
use axum_extra::extract::cookie::{Cookie, CookieJar};

static MASTER_KEY_CACHE: OnceLock<Vec<u8>> = OnceLock::new();

fn get_master_key() -> &'static [u8] {
    MASTER_KEY_CACHE.get_or_init(|| {
        let key_hex = env::var("MASTER_KEY").unwrap_or_else(|_| {
            error!("MASTER_KEY variable not found. generate key with 'openssl rand -hex 32'");
            panic!("MASTER_KEY variable not found. generate key with 'openssl rand -hex 32'");
        });

        if key_hex.len() != 64 {
            error!("MASTER_KEY not 32 bytes");
            panic!("MASTER_KEY not 32 bytes");
        }

        let bytes = hex::decode(key_hex).unwrap_or_else(|_| {
            error!("Failed to decode MASTER_KEY hex.");
            panic!("Failed to decode MASTER_KEY hex.")
        });

        info!("MASTER_KEY successfully validated and cached");
        bytes
    })
}

fn encrypt_data(data: &[u8]) -> Result<Vec<u8>, String> {
    let key_bytes = get_master_key();
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_data(encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted_data.len() < 12 {
        return Err("Invalid encrypted data: too short".to_string());
    }

    let key_bytes = get_master_key();
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))
}

fn percent_encode(s: &str) -> String {
    let mut encoded = String::new();
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' {
            encoded.push(b as char);
        } else {
            encoded.push_str(&format!("%{:02X}", b));
        }
    }
    encoded
}

fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "._- ".contains(*c))
        .collect()
}

fn sanitize_log_str(s: &str) -> String {
    let sanitized: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if sanitized.len() > 100 {
        format!("{}...", &sanitized[..97])
    } else {
        sanitized
    }
}

#[tokio::main]
async fn main() {
    let (_guard1, _guard2, _guard3) = init_log();
    info!("general log initialized successfully");
    info!(target: "security", "security log initialized");
    info!(target: "access", "access log initialized");

    let dotenv_result = dotenvy::dotenv();
    if let Err(e) = dotenv_result {
        // Not fatal — env vars may be set externally (systemd, Docker, etc.)
        warn!(
            "No .env file found, relying on environment variables: {}",
            e
        );
    } else {
        info!(".env file loaded successfully"); // ← confirm it was found
    }

    // Initialize documents directory
    if let Err(e) = init_documents_dir().await {
        error!("Failed to initialize documents directory: {}", e);
        panic!(
            "Documents directory init failed — see logs for details: {}",
            e
        );
    }

    let certfile = env::var("CERTFILE").unwrap_or_else(|_| "cert.pem".to_string());
    let keyfile = env::var("KEYFILE").unwrap_or_else(|_| "key.pem".to_string());

    // ← Log whether these came from env or the default fallback
    let cert_source = if env::var("CERTFILE").is_ok() {
        "env"
    } else {
        "default"
    };
    let key_source = if env::var("KEYFILE").is_ok() {
        "env"
    } else {
        "default"
    };
    info!(target: "security", "TLS cert: {} (source: {})", certfile, cert_source);
    info!(target: "security", "TLS key:  {} (source: {})", keyfile,  key_source);

    let config = RustlsConfig::from_pem_file(&certfile, &keyfile).await;
    let config = match config {
        Ok(config) => {
            info!(target: "security", "TLS configuration loaded successfully"); // ← confirm success
            config
        }
        Err(e) => {
            error!(target: "security", "Failed to load TLS configuration: {}", e);
            error!(
                target: "security",
                "Hint: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'"
            );
            eprintln!(
                "Failed to load TLS configuration: {}\nHint: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'",
                e
            );
            panic!("TLS init failed — see logs for details: {}", e);
        }
    };

    /* check for master key */
    let _master_key = get_master_key();

    let login_governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .period(Duration::from_secs(6)) // 1 token every 6 seconds
            .burst_size(10) // allow up to 10 requests at once
            .finish()
            .expect("Failed to build login rate limiter configuration"),
    );

    let app = Router::new()
        .route("/", get(login_html))
        .route(
            "/login",
            post(handle_login).layer(GovernorLayer::new(login_governor_conf.clone())),
        )
        .route("/register", get(register_html).post(handle_register))
        .route("/logout", post(handle_logout))
        .route(
            "/resetpassword",
            get(reset_password_html).post(handle_reset_password),
        )
        .route("/share", get(share_html))
        .route("/api/user", get(api_get_user))
        .route("/api/documents", get(api_list_documents))
        .route(
            "/api/documents/upload",
            post(api_upload_document).layer(DefaultBodyLimit::max(100 * 1024 * 1024)),
        )
        .route("/api/documents/{id}", delete(api_delete_document))
        .route("/api/documents/{id}/download", get(api_download_document))
        .route(
            "/api/documents/{id}/share",
            post(api_share_document).delete(api_unshare_document),
        )
        .route(
            "/api/documents/{id}/update",
            post(api_update_document).layer(DefaultBodyLimit::max(100 * 1024 * 1024)),
        )
        .route("/api/documents/{id}/audit", get(api_get_audit_log))
        .route("/api/admin/users", get(api_admin_list_users))
        .route(
            "/api/admin/users/{username}/role",
            post(api_admin_update_role),
        )
        .nest_service("/static", ServeDir::new("./static"))
        .layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            header::HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            header::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            header::HeaderValue::from_static("default-src 'self'; style-src 'self' 'unsafe-inline';"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            header::HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("permissions-policy"),
            header::HeaderValue::from_static("geolocation=(), microphone=(), camera=(), interest-cohort=()"),
        ));

    let port: u16 = env::var("PORTNUM")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or_else(|| {
            info!("PORTNUM not set, using default port 3000"); // ← surface the fallback
            3000
        });

    let address: std::net::SocketAddr = match format!("0.0.0.0:{port}").parse() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Failed to parse server address from port {}: {}", port, e);
            panic!("Address parse failed — see logs for details: {}", e);
        }
    };

    info!("Server starting on https://{address}");
    println!("Server running on https://{address}");

    if let Err(e) = axum_server::bind_rustls(address, config)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
    {
        error!("Server exited unexpectedly: {}", e);
        panic!("Server error — see logs for details: {}", e);
    }
}

async fn handle_login(jar: CookieJar, Form(form): Form<LoginForm>) -> impl IntoResponse {
    info!(target: "security", "Login attempt for username: {}", form.username);

    // Acquire lock to prevent race with concurrent registrations that modify users.json.
    // save_users() deletes the file before renaming, so unprotected reads can see an empty store.
    let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
    let _guard = lock.lock().await;
    let mut users = load_users();

    /* check if cookie already exists for user */
    if let Some(cookie) = jar.get("session_token") {
        let token = cookie.value();
        let session_manager = SessionManager::new();
        if let Some(session) = session_manager.validate_session(token).await {
            // Only auto-login if the session's user matches the submitted username
            if session.user_id == form.username {
                info!(target: "security", "User '{}' auto-login successful via valid session cookie", session.user_id);
                return (jar, Redirect::to("/share")).into_response();
            } else {
                warn!(target: "security", "Session cookie exists for user '{}' but login attempt submitted for different user '{}', proceeding with full authentication", session.user_id, form.username);
            }
        } else {
            info!(target: "security", "Session cookie found but invalid/expired for user '{}', proceeding with login attempt", form.username);
        }
    }

    if let Some(user) = users.get_mut(&form.username) {
        let now = chrono::Utc::now();

        // Check if account is currently locked
        if let Some(lock_time) = user.locked_until {
            if now < lock_time {
                warn!(target: "security", "Login rejected: Account {} is locked", form.username);
                return (
                    StatusCode::FORBIDDEN,
                    Html("<h1>Account locked for 15 minutes</h1>"),
                )
                    .into_response();
            } else {
                // Lock expired, reset
                user.failed_attempts = 0;
                user.locked_until = None;
            }
        }

        match verify_password(&form.password, &user.password_hash) {
            Ok(true) => {
                // Successful login: Reset attempts and save
                user.failed_attempts = 0;
                user.locked_until = None;
                let _ = save_users(&users);

                let session_manager = SessionManager::new();
                let token = session_manager.create_session(&form.username).await;

                // ← Log the token prefix only — never the full token
                info!(
                    target: "security",
                    "Session created for username: {} (token prefix: {}...)",
                    form.username,
                    &token[..8]
                );

                let cookie = Cookie::build(("session_token", token))
                    .path("/")
                    .http_only(true)
                    .secure(true)
                    .same_site(axum_extra::extract::cookie::SameSite::Strict)
                    .build();

                // ← Confirm cookie was set (security-relevant event)
                info!(
                    target: "security",
                    "Session cookie set for username: {} (http_only=true, secure=true, same_site=Strict)",
                    form.username
                );
                info!(target: "security", "Login successful for username: {}", form.username);

                (jar.add(cookie), Redirect::to("/share")).into_response()
            }
            Ok(false) => {
                // Failed login: Increment counter
                user.failed_attempts += 1;
                if user.failed_attempts >= 5 {
                    user.locked_until = Some(now + chrono::Duration::minutes(15));
                    warn!(target: "security", "Account {} locked due to too many failed attempts", form.username);
                }
                let _ = save_users(&users);

                // ← warn instead of info — invalid credentials are noteworthy
                warn!(
                    target: "security",
                    "Login failed: invalid password for username: {}",
                    form.username
                );
                (
                    StatusCode::UNAUTHORIZED,
                    Html("<h1>Login Failed</h1><a href='/'>Back</a>"),
                )
                    .into_response()
            }
            Err(e) => {
                error!(
                    "Password verification error for username {}: {}",
                    form.username, e
                ); // ← log the error
                (StatusCode::INTERNAL_SERVER_ERROR, Html("<h1>Error</h1>")).into_response()
            }
        }
    } else {
        warn!(
            target: "security",
            "Login failed: unknown username: {}",
            form.username
        );
        (
            StatusCode::UNAUTHORIZED,
            Html("<h1>Login Failed</h1><a href='/'>Back</a>"),
        )
            .into_response()
    }
}

async fn handle_register(jar: CookieJar, Form(form): Form<RegisterForm>) -> impl IntoResponse {
    info!(target: "security", "Registration attempt for username: {}", form.username);

    if let Err(e) = validate_username(&form.username) {
        info!(target: "security", "Registration rejected — username validation failed: {}", e);
        return (
            StatusCode::BAD_REQUEST,
            Html(format!(
                "<h1>Registration Failed</h1><p>{}</p><a href='/register'>Back</a>",
                e
            )),
        )
            .into_response();
    }
    info!("Username '{}' passed validation", form.username); // ← confirm each step passes

    if let Err(e) = validate_email(&form.email) {
        info!(target: "security", "Registration rejected — email validation failed for username {}: {}", form.username, e);
        return (
            StatusCode::BAD_REQUEST,
            Html(format!(
                "<h1>Registration Failed</h1><p>{}</p><a href='/register'>Back</a>",
                e
            )),
        )
            .into_response();
    }
    info!("Email passed validation for username '{}'", form.username);

    if let Err(e) = validate_password(&form.password) {
        info!(target: "security", "Registration rejected — password validation failed for username {}: {}", form.username, e);
        return (
            StatusCode::BAD_REQUEST,
            Html(format!(
                "<h1>Registration Failed</h1><p>{}</p><a href='/register'>Back</a>",
                e
            )),
        )
            .into_response();
    }
    info!(
        "Password passed validation for username '{}'",
        form.username
    );

    if form.password != form.password_confirm {
        warn!(target: "security", "Registration rejected — passwords do not match for username: {}", form.username);
        return (
            StatusCode::BAD_REQUEST,
            Html("<h1>Registration Failed</h1><p>Passwords do not match</p><a href='/register'>Back</a>".to_string()),
        ).into_response();
    }

    let password_hash = match hash_password(&form.password) {
        Ok(hash) => {
            info!(
                "Password hashed successfully for username '{}'",
                form.username
            ); // ← confirm hashing worked
            hash
        }
        Err(e) => {
            error!(
                "Failed to hash password for username '{}': {}",
                form.username, e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(
                    "<h1>Registration Failed</h1><p>Server error</p><a href='/register'>Back</a>"
                        .to_string(),
                ),
            )
                .into_response();
        }
    };

    // Check for duplicate username/email before acquiring lock (optimization)
    let users_check = {
        let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
        let _guard = lock.lock().await;
        load_users()
    };
    if users_check.contains_key(&form.username) {
        warn!(
            target: "security",
            "Registration rejected — username '{}' already exists",
            form.username
        );
        return (
            StatusCode::CONFLICT,
            Html("<h1>Registration Failed</h1><p>Username already exists</p><a href='/register'>Back</a>".to_string()),
        ).into_response();
    }
    if users_check.values().any(|u| u.email == form.email) {
        warn!(
            target: "security",
            "Registration rejected — email already registered (attempted by username '{}')",
            form.username
        );
        return (
            StatusCode::CONFLICT,
            Html("<h1>Registration Failed</h1><p>Email already exists</p><a href='/register'>Back</a>".to_string()),
        ).into_response();
    }

    // Now acquire lock for the critical write section
    info!(
        "Acquiring user file lock for registration of '{}'",
        form.username
    );
    let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
    let _guard = lock.lock().await;
    info!("User file lock acquired for '{}'", form.username);

    // Re-check after acquiring lock (TOCTOU protection)
    let mut users = load_users();

    if users.contains_key(&form.username) {
        warn!(
            target: "security",
            "Registration rejected — username '{}' already exists",
            form.username
        );
        return (
            StatusCode::CONFLICT,
            Html("<h1>Registration Failed</h1><p>Username already exists</p><a href='/register'>Back</a>".to_string()),
        ).into_response();
    }
    if users.values().any(|u| u.email == form.email) {
        warn!(
            target: "security",
            "Registration rejected (under lock) — email already registered (attempted by username '{}')",
            form.username
        );
        return (
            StatusCode::CONFLICT,
            Html("<h1>Registration Failed</h1><p>Email already exists</p><a href='/register'>Back</a>".to_string()),
        ).into_response();
    }

    let user = User {
        username: form.username.clone(),
        email: form.email.clone(),
        password_hash,
        role: UserRole::User,
        failed_attempts: 0,
        locked_until: None,
    };
    users.insert(form.username.clone(), user);

    if let Err(e) = save_users(&users) {
        error!(
            "Failed to persist user store after registering '{}': {}",
            form.username, e
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(
                "<h1>Registration Failed</h1><p>Server error</p><a href='/register'>Back</a>"
                    .to_string(),
            ),
        )
            .into_response();
    }

    info!(target: "security", "Registration successful for username: {}", form.username);
    info!(
        "User store saved successfully after adding '{}'",
        form.username
    );

    // Create a session for the new user
    let session_manager = SessionManager::new();
    let token = session_manager.create_session(&form.username).await;

    let cookie = Cookie::build(("session_token", token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .build();

    let body = Html(format!(
        "<h1>Registration Successful</h1><p>Account created successfully!</p>\
        <form action='/logout' method='post' style='margin-top: 20px;'>\
            <button type='submit'>Logout</button>\
        </form>\
        <a href='/'>Login</a>",
    ));

    (jar.add(cookie), (StatusCode::CREATED, body)).into_response()
}

async fn handle_logout(jar: CookieJar) -> impl IntoResponse {
    info!(target: "security", "Logout requested");

    // Delete the session from storage if token exists
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();
        session_manager.delete_session(token).await;
    }

    // Remove the session cookie with matching attributes to ensure proper removal
    let removal_cookie = Cookie::build(("session_token", ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .build();

    let cleared_jar = jar.remove(removal_cookie);

    (
        cleared_jar,
        Html("<h1>Logged out successfully</h1><a href='/'>Back to login</a>".to_string()),
    )
}

async fn login_html(jar: CookieJar) -> impl IntoResponse {
    info!("GET / — serving login page");

    // Check if user already has a valid session cookie
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        // validate_session already checks user existence, so if it returns Some, user is valid
        if let Some(session) = session_manager.validate_session(token).await {
            info!(target: "security", "Auto-login successful for user: {} via existing session cookie", session.user_id);
            return Redirect::to("/share").into_response();
        } else {
            info!(target: "security", "Session cookie found but invalid/expired, showing login page");
        }
    }

    // No valid session, show login page
    let contents = include_str!("../templates/login.html").to_string();
    Html(contents).into_response()
}

async fn handle_reset_password(Form(form): Form<ResetPassword>) -> impl IntoResponse {
    info!(target: "security", "Attempting to reset password for account associated with the username: {}", form.username);

    if let Err(e) = validate_password(&form.newpassword) {
        info!(target: "security", "Password reset rejected — password does not meet requirements: {}", e);
        return (
            StatusCode::BAD_REQUEST,
            Html(format!(
                "<h1>Password Reset Failed</h1><p>{}</p><a href='/resetpassword'>Back</a>",
                e
            )),
        )
            .into_response();
    }

    info!(
        "Password passed validation for username '{}'",
        form.username
    );

    if form.newpassword != form.confirmnewpassword {
        warn!(target: "security", "Password reset rejected — passwords do not match for username: {}", form.username);
        return (
            StatusCode::BAD_REQUEST,
            Html("<h1>Password Reset Failed</h1><p>Passwords do not match</p><a href='/resetpassword'>Back</a>".to_string()),
        ).into_response();
    }

    let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
    let _guard = lock.lock().await;

    let mut users = load_users();

    if let Some(user) = users.get_mut(&form.username) {
        match verify_password(&form.currentpassword, &user.password_hash) {
            Ok(true) => match hash_password(&form.newpassword) {
                Ok(new_hash) => {
                    user.password_hash = new_hash;

                    if let Err(e) = save_users(&users) {
                        error!("Saving user file failed: {}", e);
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Server error").into_response();
                    }

                    info!("Password updates successful for {}", form.username);
                    Redirect::to("/").into_response()
                }
                Err(_) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Hashing password failed").into_response()
                }
            },
            Ok(false) => (StatusCode::UNAUTHORIZED, "Current password incorrect").into_response(),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Verification error").into_response(),
        }
    } else {
        (StatusCode::NOT_FOUND, "User not found").into_response()
    }
}

async fn register_html() -> Html<String> {
    info!("GET /register — serving register page");
    let contents = include_str!("../templates/register.html").to_string();
    Html(contents)
}

async fn share_html(jar: CookieJar) -> impl IntoResponse {
    info!("GET /share — serving document sharing page");

    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if session_manager.validate_session(token).await.is_some() {
            let contents = include_str!("../templates/share.html").to_string();
            return Html(contents).into_response();
        }
    }

    info!(target: "security", "Unauthorized access attempt to /share");
    (
        StatusCode::UNAUTHORIZED,
        Html("<h1>Unauthorized</h1><a href='/'>Back</a>".to_string()),
    )
        .into_response()
}

#[derive(Serialize, Deserialize)]
struct UserResponse {
    username: String,
    role: UserRole,
}

async fn api_get_user(jar: CookieJar) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
            let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
            let _guard = lock.lock().await;
            let users = load_users();

            if let Some(user) = users.get(&session.user_id) {
                return (
                    StatusCode::OK,
                    Json(UserResponse {
                        username: session.user_id,
                        role: user.role.clone(),
                    }),
                )
                    .into_response();
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "Unauthorized"})),
    )
        .into_response()
}

#[derive(Serialize)]
struct AdminUserResponse {
    username: String,
    email: String,
    role: UserRole,
}

async fn api_admin_list_users(jar: CookieJar) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
            let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
            let _guard = lock.lock().await;
            let users = load_users();

            if let Some(user) = users.get(&session.user_id) {
                if user.role != UserRole::Admin {
                    warn!(target: "security", "Non-admin user '{}' attempted to list users", session.user_id);
                    return (StatusCode::FORBIDDEN, "Only admins can list users").into_response();
                }

                let response: Vec<AdminUserResponse> = users
                    .values()
                    .map(|u| AdminUserResponse {
                        username: u.username.clone(),
                        email: u.email.clone(),
                        role: u.role.clone(),
                    })
                    .collect();
                return (StatusCode::OK, Json(response)).into_response();
            }
        }
    }
    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}

#[derive(Deserialize)]
struct UpdateRoleForm {
    role: UserRole,
}

async fn api_admin_update_role(
    jar: CookieJar,
    AxumPath(username): AxumPath<String>,
    Json(payload): Json<UpdateRoleForm>,
) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
            // Prevent users from changing their own role
            if username == session.user_id {
                warn!(target: "security", "User '{}' attempted to change their own role", session.user_id);
                return (StatusCode::BAD_REQUEST, "You cannot change your own role")
                    .into_response();
            }

            let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
            let _guard = lock.lock().await;
            let mut users = load_users();

            if let Some(current_user) = users.get(&session.user_id) {
                if current_user.role != UserRole::Admin {
                    warn!(target: "security", "Non-admin user '{}' attempted to update role for '{}'", session.user_id, username);
                    return (StatusCode::FORBIDDEN, "Only admins can update roles").into_response();
                }

                if let Some(target_user) = users.get_mut(&username) {
                    target_user.role = payload.role.clone();
                    if let Err(e) = save_users(&users) {
                        error!("Failed to save users after role update: {}", e);
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to save users")
                            .into_response();
                    }
                    info!(target: "security", "User '{}' role updated to '{:?}' by admin '{}'", username, payload.role, session.user_id);
                    return (StatusCode::OK, "Role updated successfully").into_response();
                } else {
                    return (StatusCode::NOT_FOUND, "User not found").into_response();
                }
            }
        }
    }
    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}

async fn api_list_documents(jar: CookieJar) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
            let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
            let _guard = lock.lock().await;
            let users = crate::users::load_users();
            let is_admin = users
                .get(&session.user_id)
                .map_or(false, |u| u.role == crate::users::UserRole::Admin);
            drop(_guard);

            let documents = if is_admin {
                crate::documents::get_all_documents().await
            } else {
                get_user_documents(&session.user_id).await
            };

            let response: Vec<DocumentResponse> = documents
                .into_iter()
                .map(|doc| {
                    let is_owner = doc.uploaded_by == session.user_id;

                    // Construct response manually to avoid cloning audit_log
                    DocumentResponse {
                        id: doc.id,
                        filename: doc.filename,
                        size: doc.size,
                        uploaded_at: doc.uploaded_at,
                        uploaded_by: doc.uploaded_by,
                        version: doc.version,
                        audit_log: None, // Always redact in list view
                        permissions: if is_owner || is_admin {
                            Some(doc.permissions)
                        } else {
                            // Non-owners only see their own permission
                            let mut limited_perms = std::collections::HashMap::new();
                            if let Some(role) = doc.permissions.get(&session.user_id) {
                                limited_perms.insert(session.user_id.clone(), role.clone());
                            }
                            Some(limited_perms)
                        },
                    }
                })
                .collect();
            return (StatusCode::OK, Json(response)).into_response();
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "Unauthorized"})),
    )
        .into_response()
}

async fn api_get_audit_log(jar: CookieJar, AxumPath(id): AxumPath<String>) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
            if let Some(document) = get_document_by_id(&id).await {
                // Only the owner can see the audit log
                if document.uploaded_by != session.user_id {
                    return (
                        StatusCode::FORBIDDEN,
                        "Only the owner can view the audit log".to_string(),
                    )
                        .into_response();
                }

                return (StatusCode::OK, Json(document.audit_log)).into_response();
            }
            return (StatusCode::NOT_FOUND, "Document not found".to_string()).into_response();
        }
    }
    (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response()
}

async fn api_upload_document(jar: CookieJar, mut multipart: Multipart) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
            let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
            let _guard = lock.lock().await;
            let users = load_users();

            if let Some(user) = users.get(&session.user_id) {
                if user.role == UserRole::Guest {
                    warn!(target: "security", "Guest user '{}' attempted to upload a document", session.user_id);
                    return (
                        StatusCode::FORBIDDEN,
                        "Guests are not allowed to upload documents".to_string(),
                    )
                        .into_response();
                }
            }

            info!("Upload attempt by user: {}", session.user_id);

            loop {
                let field_result =
                    tokio::time::timeout(Duration::from_secs(30), multipart.next_field()).await;
                match field_result {
                    Ok(Ok(Some(field))) => {
                        let field_name = field
                            .name()
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "unknown".to_string());
                        info!("Processing multipart field: {}", field_name);

                        if field_name == "file" {
                            let filename = match field.file_name() {
                                Some(name) => name.to_string(),
                                None => {
                                    warn!(
                                        "Upload failed: No filename provided in the 'file' field for user {}",
                                        session.user_id
                                    );
                                    return (
                                        StatusCode::BAD_REQUEST,
                                        "No filename provided".to_string(),
                                    )
                                        .into_response();
                                }
                            };

                            match field.bytes().await {
                                Ok(bytes) => {
                                    info!(
                                        "Received {} bytes for file: {}",
                                        bytes.len(),
                                        sanitize_log_str(&filename)
                                    );

                                    let encrypted_bytes = match encrypt_data(&bytes) {
                                        Ok(enc) => enc,
                                        Err(e) => {
                                            error!(
                                                "Encryption failed during upload for user {}: {}",
                                                session.user_id, e
                                            );
                                            return (StatusCode::INTERNAL_SERVER_ERROR, e)
                                                .into_response();
                                        }
                                    };

                                    let document = match create_document(
                                        filename.clone(),
                                        bytes.len() as u64,
                                        session.user_id.clone(),
                                    ) {
                                        Ok(doc) => doc,
                                        Err(e) => {
                                            error!(
                                                "Metadata creation failed for user {}: {}",
                                                session.user_id, e
                                            );
                                            return (StatusCode::INTERNAL_SERVER_ERROR, e)
                                                .into_response();
                                        }
                                    };

                                    if let Err(e) =
                                        tokio::fs::write(&document.path, &encrypted_bytes).await
                                    {
                                        error!(
                                            "File system write failed for user {}: {}",
                                            session.user_id, e
                                        );
                                        return (
                                            StatusCode::INTERNAL_SERVER_ERROR,
                                            format!("Failed to save file: {}", e),
                                        )
                                            .into_response();
                                    }
                                    if let Err(e) = add_document(document.clone()).await {
                                        error!(
                                            "Metadata persistence failed for user {}: {}",
                                            session.user_id, e
                                        );

                                        // Clean up the orphan file since metadata persistence failed
                                        if let Err(cleanup_err) =
                                            tokio::fs::remove_file(&document.path).await
                                        {
                                            error!(
                                                "Failed to clean up orphan file {} after metadata persistence failure: {}",
                                                document.path, cleanup_err
                                            );
                                        }

                                        return (
                                            StatusCode::INTERNAL_SERVER_ERROR,
                                            format!("Failed to save document metadata: {}", e),
                                        )
                                            .into_response();
                                    }

                                    info!(
                                        "Document uploaded successfully: {} (ID: {}) by {}",
                                        sanitize_log_str(&filename),
                                        document.id,
                                        session.user_id
                                    );

                                    return (
                                        StatusCode::OK,
                                        Json(serde_json::json!({"id": document.id, "filename": document.filename})),
                                    )
                                        .into_response();
                                }
                                Err(e) => {
                                    warn!(
                                        "Upload failed: Could not read bytes for file {} from user {}: {}",
                                        sanitize_log_str(&filename),
                                        session.user_id,
                                        e
                                    );
                                    return (
                                        StatusCode::BAD_REQUEST,
                                        format!("Failed to read file: {}", e),
                                    )
                                        .into_response();
                                }
                            }
                        }
                    }
                    Ok(Ok(None)) => {
                        warn!(
                            "Upload failed: Multipart stream ended without finding a 'file' field for user {}",
                            session.user_id
                        );
                        break;
                    }
                    Ok(Err(e)) => {
                        warn!(
                            "Upload failed: Multipart stream error for user {}: {}",
                            session.user_id, e
                        );
                        return (StatusCode::BAD_REQUEST, format!("Multipart error: {}", e))
                            .into_response();
                    }
                    Err(_) => {
                        warn!(
                            "Upload failed: Timeout while waiting for multipart field from user {}",
                            session.user_id
                        );
                        return (StatusCode::REQUEST_TIMEOUT, "Request timed out".to_string())
                            .into_response();
                    }
                }
            }

            warn!(
                "Upload failed: No 'file' field found in multipart form for user {}",
                session.user_id
            );
            return (StatusCode::BAD_REQUEST, "No file field found".to_string()).into_response();
        }
    }

    warn!("Unauthorized upload attempt: invalid or missing session token");
    (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response()
}

async fn api_update_document(
    jar: CookieJar,
    AxumPath(id): AxumPath<String>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
            let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
            let _guard = lock.lock().await;
            let users = load_users();

            if let Some(user) = users.get(&session.user_id) {
                if user.role == UserRole::Guest {
                    warn!(target: "security", "Guest user '{}' attempted to update document {}", session.user_id, id);
                    return (
                        StatusCode::FORBIDDEN,
                        "Guests are not allowed to update documents".to_string(),
                    )
                        .into_response();
                }
            }
            drop(_guard);

            // First check permissions without a long-held write lock
            if let Some(document) = get_document_by_id(&id).await {
                let is_owner = document.uploaded_by == session.user_id;
                let is_editor =
                    document.permissions.get(&session.user_id) == Some(&"editor".to_string());

                if !is_owner && !is_editor {
                    return (
                        StatusCode::FORBIDDEN,
                        "Only the owner or an editor can update this document".to_string(),
                    )
                        .into_response();
                }

                info!(
                    "Update attempt for document {} by user: {}",
                    id, session.user_id
                );

                loop {
                    let field_result =
                        tokio::time::timeout(Duration::from_secs(30), multipart.next_field()).await;
                    match field_result {
                        Ok(Ok(Some(field))) => {
                            if field.name() == Some("file") {
                                let filename =
                                    field.file_name().unwrap_or(&document.filename).to_string();

                                match field.bytes().await {
                                    Ok(bytes) => {
                                        let encrypted_bytes = match encrypt_data(&bytes) {
                                            Ok(enc) => enc,
                                            Err(e) => {
                                                return (StatusCode::INTERNAL_SERVER_ERROR, e)
                                                    .into_response();
                                            }
                                        };

                                        // Write to a temporary file first to ensure atomicity
                                        let temp_path = format!("{}.tmp", document.path);
                                        if let Err(e) =
                                            tokio::fs::write(&temp_path, &encrypted_bytes).await
                                        {
                                            error!(
                                                "Failed to write temporary file during update: {}",
                                                e
                                            );
                                            return (
                                                StatusCode::INTERNAL_SERVER_ERROR,
                                                format!("Failed to save file: {}", e),
                                            )
                                                .into_response();
                                        }

                                        // On Windows, std::fs::rename fails if the destination already exists.
                                        // We attempt to remove it first.
                                        if std::path::Path::new(&document.path).exists() {
                                            if let Err(e) =
                                                tokio::fs::remove_file(&document.path).await
                                            {
                                                warn!(
                                                    "Could not remove existing document file '{}' before rename: {}. Attempting rename anyway.",
                                                    document.path, e
                                                );
                                            }
                                        }

                                        // Swap files to ensure disk state is updated
                                        if let Err(e) =
                                            tokio::fs::rename(&temp_path, &document.path).await
                                        {
                                            error!(
                                                "Failed to finalize file update for document {}: {}",
                                                id, e
                                            );
                                            // Clean up temp file
                                            let _ = tokio::fs::remove_file(&temp_path).await;
                                            return (
                                                StatusCode::INTERNAL_SERVER_ERROR,
                                                format!("Failed to finalize file update: {}", e),
                                            )
                                                .into_response();
                                        }

                                        // Now update metadata atomically
                                        let update_result =
                                            crate::documents::with_document_mut(&id, |doc| {
                                                let now = chrono::Utc::now();
                                                doc.filename = filename.clone();
                                                doc.size = bytes.len() as u64;
                                                doc.uploaded_at = now;
                                                doc.version += 1;

                                                let entry = format!(
                                                    "[{}] User {} uploaded new version {}",
                                                    now.to_rfc3339(),
                                                    session.user_id,
                                                    doc.version
                                                );
                                                info!(target: "access", "{}", entry);
                                                doc.audit_log.push(entry);
                                                if doc.audit_log.len() > 50 {
                                                    doc.audit_log.remove(0);
                                                }
                                                doc.version
                                            })
                                            .await;

                                        let new_version = match update_result {
                                            Ok(v) => v,
                                            Err(e) => {
                                                error!(
                                                    "Failed to update metadata for document {}: {}",
                                                    id, e
                                                );
                                                // File swapped but metadata update failed
                                                return (
                                                    StatusCode::INTERNAL_SERVER_ERROR,
                                                    format!("File updated but metadata update failed: {}", e),
                                                )
                                                    .into_response();
                                            }
                                        };

                                        info!(
                                            "Document {} successfully updated to version {} by {}",
                                            id, new_version, session.user_id
                                        );
                                        return (
                                            StatusCode::OK,
                                            Json(
                                                serde_json::json!({"id": id, "filename": filename}),
                                            ),
                                        )
                                            .into_response();
                                    }
                                    Err(e) => {
                                        return (
                                            StatusCode::BAD_REQUEST,
                                            format!("Failed to read file: {}", e),
                                        )
                                            .into_response();
                                    }
                                }
                            }
                        }
                        Ok(Ok(None)) => break,
                        Ok(Err(e)) => {
                            return (StatusCode::BAD_REQUEST, format!("Multipart error: {}", e))
                                .into_response();
                        }
                        Err(_) => {
                            warn!(
                                "Update failed: Timeout while waiting for multipart field for document {} from user {}",
                                id, session.user_id
                            );
                            return (StatusCode::REQUEST_TIMEOUT, "Request timed out".to_string())
                                .into_response();
                        }
                    }
                }
                return (StatusCode::BAD_REQUEST, "No file field found".to_string())
                    .into_response();
            }
            return (StatusCode::NOT_FOUND, "Document not found".to_string()).into_response();
        }
    }
    (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response()
}

#[derive(Deserialize)]
struct ShareForm {
    target_username: String,
    role: String,
}

async fn api_share_document(
    jar: CookieJar,
    AxumPath(id): AxumPath<String>,
    Json(payload): Json<ShareForm>,
) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
            let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
            let _guard = lock.lock().await;
            let users = load_users();

            if let Some(user) = users.get(&session.user_id) {
                if user.role == UserRole::Guest {
                    warn!(target: "security", "Guest user '{}' attempted to share document {}", session.user_id, id);
                    return (
                        StatusCode::FORBIDDEN,
                        "Guests are not allowed to share documents".to_string(),
                    )
                        .into_response();
                }
            }
            drop(_guard);

            // Validate role
            let role = payload.role.to_lowercase();
            if role != "viewer" && role != "editor" {
                warn!(target: "security", "Invalid role share attempt: '{}' for document {} by user {}", payload.role, id, session.user_id);
                return (
                    StatusCode::BAD_REQUEST,
                    "Invalid role. Must be 'viewer' or 'editor'".to_string(),
                )
                    .into_response();
            }

            // Prevent sharing with self
            if payload.target_username == session.user_id {
                warn!(target: "security", "Self-share attempt for document {} by user {}", id, session.user_id);
                return (
                    StatusCode::BAD_REQUEST,
                    "You cannot share a document with yourself".to_string(),
                )
                    .into_response();
            }

            // Verify target user exists
            let users = {
                let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
                let _user_file_guard = lock.lock().await;
                load_users()
            };
            if !users.contains_key(&payload.target_username) {
                info!(
                    "Share failed: target user '{}' not found (requested by {})",
                    payload.target_username, session.user_id
                );
                return (
                    StatusCode::NOT_FOUND,
                    format!("User '{}' not found", payload.target_username),
                )
                    .into_response();
            }

            let share_result = crate::documents::with_document_mut(&id, |doc| {
                // Only the owner can share
                if doc.uploaded_by != session.user_id {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "Only the owner can share this document".to_string(),
                    ));
                }

                doc.permissions
                    .insert(payload.target_username.clone(), role.clone());

                let entry = format!(
                    "[{}] User {} shared document with {} as {}",
                    chrono::Utc::now().to_rfc3339(),
                    session.user_id,
                    payload.target_username,
                    role
                );
                info!(target: "access", "{}", entry);
                doc.audit_log.push(entry);
                if doc.audit_log.len() > 50 {
                    doc.audit_log.remove(0);
                }

                Ok(())
            })
            .await;

            return match share_result {
                Ok(Ok(_)) => {
                    info!(
                        "Document {} shared with {} as {} by {}",
                        id, payload.target_username, role, session.user_id
                    );
                    (StatusCode::OK, "Document shared successfully".to_string()).into_response()
                }
                Ok(Err((status, msg))) => {
                    warn!(target: "security", "Unauthorized share attempt for document {} by user {}: {}", id, session.user_id, msg);
                    (status, msg).into_response()
                }
                Err(e) => {
                    error!(
                        "Failed to update document metadata for sharing (doc: {}, target: {}): {}",
                        id, payload.target_username, e
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to update metadata".to_string(),
                    )
                        .into_response()
                }
            };
        }
    }

    warn!(target: "security", "Unauthorized access attempt to share API: invalid or missing session");
    (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response()
}

#[derive(Deserialize)]
struct UnshareForm {
    target_username: String,
}

async fn api_unshare_document(
    jar: CookieJar,
    AxumPath(id): AxumPath<String>,
    Json(payload): Json<UnshareForm>,
) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
            let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
            let _guard = lock.lock().await;
            let users = load_users();

            if let Some(user) = users.get(&session.user_id) {
                if user.role == UserRole::Guest {
                    warn!(target: "security", "Guest user '{}' attempted to manage document access for {}", session.user_id, id);
                    return (
                        StatusCode::FORBIDDEN,
                        "Guests are not allowed to manage document access".to_string(),
                    )
                        .into_response();
                }
            }
            drop(_guard);

            let unshare_result = crate::documents::with_document_mut(&id, |doc| {
                // Only the owner can unshare
                if doc.uploaded_by != session.user_id {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "Only the owner can manage access to this document".to_string(),
                    ));
                }

                if doc.permissions.remove(&payload.target_username).is_some() {
                    let entry = format!(
                        "[{}] User {} revoked access for {}",
                        chrono::Utc::now().to_rfc3339(),
                        session.user_id,
                        payload.target_username
                    );
                    info!(target: "access", "{}", entry);
                    doc.audit_log.push(entry);
                    if doc.audit_log.len() > 50 {
                        doc.audit_log.remove(0);
                    }
                    Ok(true)
                } else {
                    Ok(false)
                }
            })
            .await;

            return match unshare_result {
                Ok(Ok(true)) => {
                    info!(
                        "Access removed for {} from document {} by {}",
                        payload.target_username, id, session.user_id
                    );
                    (StatusCode::OK, "Access removed successfully".to_string()).into_response()
                }
                Ok(Ok(false)) => {
                    info!(
                        "Unshare failed: user '{}' did not have access to document {} (requested by {})",
                        payload.target_username, id, session.user_id
                    );
                    (
                        StatusCode::NOT_FOUND,
                        "User did not have access".to_string(),
                    )
                        .into_response()
                }
                Ok(Err((status, msg))) => {
                    warn!(target: "security", "Unauthorized unshare attempt for document {} by user {}: {}", id, session.user_id, msg);
                    (status, msg).into_response()
                }
                Err(e) => {
                    error!(
                        "Failed to update document metadata for unsharing (doc: {}, target: {}): {}",
                        id, payload.target_username, e
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to update metadata".to_string(),
                    )
                        .into_response()
                }
            };
        }
    }

    warn!(target: "security", "Unauthorized access attempt to unshare API: invalid or missing session");
    (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response()
}

async fn api_download_document(
    jar: CookieJar,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
            let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
            let _guard = lock.lock().await;
            let users = crate::users::load_users();
            let is_admin = users
                .get(&session.user_id)
                .map_or(false, |u| u.role == crate::users::UserRole::Admin);
            drop(_guard);

            // First check authorization and get path
            let auth_check = if let Some(doc) = get_document_by_id(&id).await {
                if doc.uploaded_by == session.user_id
                    || doc.permissions.contains_key(&session.user_id)
                    || is_admin
                {
                    Ok((doc.path.clone(), doc.filename.clone()))
                } else {
                    Err(StatusCode::FORBIDDEN)
                }
            } else {
                Err(StatusCode::NOT_FOUND)
            };

            let (path, filename) = match auth_check {
                Ok(res) => res,
                Err(status) => return (status, "Access denied").into_response(),
            };

            // Read the file from disk (IO-intensive, do outside the lock)
            let encrypted_contents = match tokio::fs::read(&path).await {
                Ok(contents) => contents,
                Err(e) => {
                    error!("Failed to read document file: {}", e);
                    return match e.kind() {
                        std::io::ErrorKind::NotFound => {
                            (StatusCode::NOT_FOUND, "Document not found".to_string())
                        }
                        _ => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to read file".to_string(),
                        ),
                    }
                    .into_response();
                }
            };

            // Decrypt contents
            let contents = match decrypt_data(&encrypted_contents) {
                Ok(contents) => contents,
                Err(e) => {
                    error!("Failed to decrypt document: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to decrypt file".to_string(),
                    )
                        .into_response();
                }
            };

            // 1. Permanent Audit: Log to access.log immediately (primary security record)
            let timestamp = chrono::Utc::now().to_rfc3339();
            info!(
                target: "access",
                "[{}] User {} downloaded version of document {}",
                timestamp, session.user_id, id
            );

            // 2. Metadata Audit: Best-effort update to the inline audit log (for UI display)
            let audit_id = id.clone();
            let audit_user = session.user_id.clone();
            tokio::spawn(async move {
                let res = crate::documents::with_document_mut(&audit_id, |doc| {
                    let entry = format!(
                        "[{}] User {} downloaded version {}",
                        chrono::Utc::now().to_rfc3339(),
                        audit_user,
                        doc.version
                    );
                    doc.audit_log.push(entry);
                    if doc.audit_log.len() > 50 {
                        doc.audit_log.remove(0);
                    }
                })
                .await;

                if let Err(e) = res {
                    error!(target: "security", "Best-effort audit log update failed for document {}: {}", audit_id, e);
                }
            });

            // 3. Finalize Response: Serve the file regardless of metadata update outcome
            info!(
                "Document download successful: {} by {}",
                sanitize_log_str(&filename),
                session.user_id
            );

            let sanitized_simple = sanitize_filename(&filename);
            let encoded_utf8 = percent_encode(&filename);
            let content_disposition = format!(
                r#"attachment; filename="{}"; filename*=UTF-8''{}"#,
                sanitized_simple, encoded_utf8
            );

            return (
                StatusCode::OK,
                [("Content-Disposition", content_disposition)],
                contents,
            )
                .into_response();
        }
    }

    (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response()
}

async fn api_delete_document(jar: CookieJar, AxumPath(id): AxumPath<String>) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
            let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
            let _guard = lock.lock().await;
            let users = load_users();

            if let Some(user) = users.get(&session.user_id) {
                if user.role == UserRole::Guest {
                    warn!(target: "security", "Guest user '{}' attempted to delete document {}", session.user_id, id);
                    return (
                        StatusCode::FORBIDDEN,
                        "Guests are not allowed to delete documents".to_string(),
                    )
                        .into_response();
                }
            }
            drop(_guard);

            if let Some(document) = get_document_by_id(&id).await {
                if document.uploaded_by != session.user_id {
                    return (
                        StatusCode::FORBIDDEN,
                        "You can only delete your own documents".to_string(),
                    )
                        .into_response();
                }

                match delete_document(&id).await {
                    Ok(_) => {
                        info!(
                            "Document deleted successfully: {} by {}",
                            sanitize_log_str(&document.filename),
                            session.user_id
                        );
                        return (StatusCode::OK, "Document deleted".to_string()).into_response();
                    }
                    Err(e) => {
                        error!("Failed to delete document: {}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to delete document: {}", e),
                        )
                            .into_response();
                    }
                }
            }

            return (StatusCode::NOT_FOUND, "Document not found".to_string()).into_response();
        }
    }

    (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response()
}

#[cfg(test)]
mod tests {
    use rand::random;

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_session_lifecycle() {
        // Create a test user in the user store so session validation can find it
        let user_id = "test_user";
        let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
        let _guard = lock.lock().await;

        let mut users = load_users();
        users.insert(
            user_id.to_string(),
            User {
                username: user_id.to_string(),
                email: "test@example.com".to_string(),
                password_hash: "dummy_hash".to_string(),
                role: UserRole::User,
                failed_attempts: 0,
                locked_until: None,
            },
        );
        save_users(&users).expect("Failed to save test user");
        drop(_guard);

        // Use a unique temp file to avoid interfering with production data or parallel tests
        let temp_file = format!("test_sessions_{}.json", random::<u64>());
        let manager = SessionManager::new_with_path(temp_file.clone(), 1800);

        let token = manager.create_session(user_id).await;
        assert_eq!(token.len(), 32);

        let session = manager.validate_session(&token).await;
        assert!(
            session.is_some(),
            "Session should be valid immediately after creation"
        );
        assert_eq!(session.unwrap().user_id, user_id);

        // Verify the session is stored (as a hash, not plaintext)
        let sessions = manager.load_sessions().await;
        assert_eq!(sessions.len(), 1);
        // We can't check by token directly since it's hashed, but we validated it works above

        // Clean up: remove the temp file and test user
        let _ = std::fs::remove_file(&temp_file);
        let _guard = lock.lock().await;
        let mut users = load_users();
        users.remove(user_id);
        let _ = save_users(&users);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_admin_access_control() {
        let admin_id = "admin_user";
        let user_id = "regular_user";
        let lock = USER_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
        let _guard = lock.lock().await;

        let mut users = load_users();

        users.insert(
            admin_id.to_string(),
            User {
                username: admin_id.to_string(),
                email: "admin@example.com".to_string(),
                password_hash: "dummy_hash".to_string(),
                role: UserRole::Admin,
                failed_attempts: 0,
                locked_until: None,
            },
        );
        users.insert(
            user_id.to_string(),
            User {
                username: user_id.to_string(),
                email: "user@example.com".to_string(),
                password_hash: "dummy_hash".to_string(),
                role: UserRole::User,
                failed_attempts: 0,
                locked_until: None,
            },
        );
        save_users(&users).expect("Failed to save test users");
        drop(_guard);

        let session_manager = SessionManager::new();
        let admin_token = session_manager.create_session(admin_id).await;
        let user_token = session_manager.create_session(user_id).await;

        // Helper to simulate request with cookie
        async fn check_list_users(token: &str) -> StatusCode {
            let jar = CookieJar::new().add(Cookie::new("session_token", token.to_string()));
            let response = api_admin_list_users(jar).await.into_response();
            response.status()
        }

        async fn check_update_role(token: &str, target: &str, new_role: UserRole) -> StatusCode {
            let jar = CookieJar::new().add(Cookie::new("session_token", token.to_string()));
            let payload = Json(UpdateRoleForm { role: new_role });
            let response = api_admin_update_role(jar, AxumPath(target.to_string()), payload)
                .await
                .into_response();
            response.status()
        }

        // Test 1: Admin can list users
        assert_eq!(check_list_users(&admin_token).await, StatusCode::OK);

        // Test 2: Regular user cannot list users
        assert_eq!(check_list_users(&user_token).await, StatusCode::FORBIDDEN);

        // Test 3: Admin can update role
        assert_eq!(
            check_update_role(&admin_token, user_id, UserRole::Admin).await,
            StatusCode::OK
        );

        // Verify role was updated
        let updated_users = {
            let _guard = lock.lock().await;
            load_users()
        };
        assert_eq!(updated_users.get(user_id).unwrap().role, UserRole::Admin);

        // Test 4: Regular user (even if upgraded, let's use another user) cannot update role
        let another_user_id = "another_user";
        let _guard = lock.lock().await;
        let mut users = load_users();
        users.insert(
            another_user_id.to_string(),
            User {
                username: another_user_id.to_string(),
                email: "another@example.com".to_string(),
                password_hash: "dummy_hash".to_string(),
                role: UserRole::User,
                failed_attempts: 0,
                locked_until: None,
            },
        );
        save_users(&users).unwrap();
        drop(_guard);

        let another_user_token = session_manager.create_session(another_user_id).await;

        assert_eq!(
            check_update_role(&another_user_token, admin_id, UserRole::User).await,
            StatusCode::FORBIDDEN
        );

        // Test 5: Admin cannot change their own role
        assert_eq!(
            check_update_role(&admin_token, admin_id, UserRole::User).await,
            StatusCode::BAD_REQUEST
        );

        // Clean up
        let _guard = lock.lock().await;
        let mut users = load_users();
        users.remove(admin_id);
        users.remove(user_id);
        users.remove(another_user_id);
        let _ = save_users(&users);
    }
}

async fn reset_password_html() -> Html<String> {
    info!("Serving resetpassword.html to client");
    let contents = include_str!("../templates/resetpassword.html").to_string();
    Html(contents)
}
