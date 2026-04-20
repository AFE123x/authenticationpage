use argon2::password_hash;
use axum::http::{StatusCode, status};
use axum::response::{IntoResponse, Redirect};
use axum::{
    Form, Router,
    response::Html,
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;

use std::env;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Mutex as TokioMutex;
use tracing::{error, info, warn};

mod log;
use crate::log::init_log;
use crate::users::{
    LoginForm, RegisterForm, ResetPassword, User, UserRole, hash_password, load_users, save_users,
    validate_email, validate_password, validate_username, verify_password,
}; //add Registry if needed

use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};

mod sessions;
mod users;
use crate::sessions::SessionManager;
use axum_extra::extract::cookie::{Cookie, CookieJar};

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
        );

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
                return (jar, Redirect::to("/")).into_response();
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

                let body = Html(format!(
                    "<h1>Login Successful</h1><p>Welcome, {}! Your role is {}</p>\
                    <form action='/logout' method='post' style='margin-top: 20px;'>\
                        <button type='submit'>Logout</button>\
                    </form>\
                    <a href='/'>Back</a>",
                    form.username, user.role
                ));
                (jar.add(cookie), body).into_response()
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

            let welcome_html = format!(
                r#"<html>
<head><title>Welcome</title></head>
<body>
    <h1>Welcome back, {}!</h1>
    <p>You are already logged in (auto-login from saved session).</p>
    <form action="/logout" method="post">
        <button type="submit">Logout</button>
    </form>
</body>
</html>"#,
                session.user_id
            );

            return Html(welcome_html).into_response();
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
