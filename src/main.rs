use argon2::password_hash;
use axum::extract::DefaultBodyLimit;
use axum::http::{StatusCode, status};
use axum::response::{IntoResponse, Redirect};
use axum::{
    Form, Json, Router,
    extract::Multipart,
    extract::Path as AxumPath,
    response::Html,
    routing::{delete, get, post},
};
use axum_server::tls_rustls::RustlsConfig;

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
    LoginForm, RegisterForm, ResetPassword, User, UserRole, hash_password, load_users, save_users,
    validate_email, validate_password, validate_username, verify_password,
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
    let (_guard1, _guard2) = init_log();
    info!("general log initialized successfully");
    info!(target: "security", "security log initialized");

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
        .route("/api/documents/{id}/download", get(api_download_document));

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
    let users = load_users();

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

    match users.get(&form.username) {
        Some(user) => match verify_password(&form.password, &user.password_hash) {
            Ok(true) => {
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
        },
        None => {
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
}

static USER_FILE_LOCK: OnceLock<TokioMutex<()>> = OnceLock::new();

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
    let users_check = load_users();
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
}

async fn api_get_user(jar: CookieJar) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
            return (
                StatusCode::OK,
                Json(UserResponse {
                    username: session.user_id,
                }),
            )
                .into_response();
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "Unauthorized"})),
    )
        .into_response()
}

async fn api_list_documents(jar: CookieJar) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
            let documents = get_user_documents(&session.user_id).await;
            let response: Vec<DocumentResponse> = documents.into_iter().map(Into::into).collect();
            return (StatusCode::OK, Json(response)).into_response();
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "Unauthorized"})),
    )
        .into_response()
}

async fn api_upload_document(jar: CookieJar, mut multipart: Multipart) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
            info!("Upload attempt by user: {}", session.user_id);

            loop {
                match multipart.next_field().await {
                    Ok(Some(field)) => {
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
                    Ok(None) => {
                        warn!(
                            "Upload failed: Multipart stream ended without finding a 'file' field for user {}",
                            session.user_id
                        );
                        break;
                    }
                    Err(e) => {
                        warn!(
                            "Upload failed: Multipart stream error for user {}: {}",
                            session.user_id, e
                        );
                        return (StatusCode::BAD_REQUEST, format!("Multipart error: {}", e))
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

async fn api_download_document(
    jar: CookieJar,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(_session) = session_manager.validate_session(token).await {
            if let Some(document) = get_document_by_id(&id).await {
                if document.uploaded_by != _session.user_id {
                    return (StatusCode::FORBIDDEN, "Access denied").into_response();
                }

                match tokio::fs::read(&document.path).await {
                    Ok(encrypted_contents) => match decrypt_data(&encrypted_contents) {
                        Ok(contents) => {
                            info!(
                                "Document downloaded: {} by {}",
                                sanitize_log_str(&document.filename),
                                _session.user_id
                            );

                            let sanitized_simple = sanitize_filename(&document.filename);
                            let encoded_utf8 = percent_encode(&document.filename);
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
                        Err(e) => {
                            error!("Failed to decrypt document: {}", e);
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Failed to decrypt file".to_string(),
                            )
                                .into_response();
                        }
                    },
                    Err(e) => {
                        error!("Failed to read document file: {}", e);
                        return match e.kind() {
                            std::io::ErrorKind::NotFound => {
                                (StatusCode::NOT_FOUND, "Document not found".to_string())
                                    .into_response()
                            }
                            _ => (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Failed to read file".to_string(),
                            )
                                .into_response(),
                        };
                    }
                }
            }

            return (StatusCode::NOT_FOUND, "Document not found".to_string()).into_response();
        }
    }

    (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response()
}

async fn api_delete_document(jar: CookieJar, AxumPath(id): AxumPath<String>) -> impl IntoResponse {
    if let Some(session_cookie) = jar.get("session_token") {
        let token = session_cookie.value();
        let session_manager = SessionManager::new();

        if let Some(session) = session_manager.validate_session(token).await {
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
        let mut users = load_users();
        users.insert(
            user_id.to_string(),
            User {
                username: user_id.to_string(),
                email: "test@example.com".to_string(),
                password_hash: "dummy_hash".to_string(),
                role: UserRole::User,
            },
        );
        save_users(&users).expect("Failed to save test user");

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
        let mut users = load_users();
        users.remove(user_id);
        let _ = save_users(&users);
    }
}

async fn reset_password_html() -> Html<String> {
    info!("Serving resetpassword.html to client");
    let contents = include_str!("../templates/resetpassword.html").to_string();
    Html(contents)
}
