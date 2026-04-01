use rand::{Rng, distributions::Alphanumeric};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::Mutex as TokioMutex;
use tracing::{error, info, warn};

// Global lock to synchronize all session file read-modify-write operations
static SESSIONS_FILE_LOCK: OnceLock<TokioMutex<()>> = OnceLock::new();

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Session {
    // Note: token is NOT stored here - only the hash is used as the HashMap key
    pub user_id: String,
    pub created_at: u64,
    pub last_activity: u64,
}

pub struct SessionManager {
    file_path: String,
    timeout: u64,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            file_path: "data/sessions.json".to_string(),
            timeout: 1800, // 30 minutes
        }
    }

    #[cfg(test)]
    pub fn new_with_path(file_path: String, timeout: u64) -> Self {
        Self { file_path, timeout }
    }

    fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    pub async fn load_sessions(&self) -> HashMap<String, Session> {
        if !Path::new(&self.file_path).exists() {
            info!(target: "security", "Sessions file does not exist, starting with empty session store");
            return HashMap::new();
        }
        let content = fs::read_to_string(&self.file_path)
            .await
            .unwrap_or_else(|e| {
                error!(target: "security", "Failed to read sessions file: {}", e);
                String::new()
            });

        let sessions: HashMap<String, Session> =
            serde_json::from_str(&content).unwrap_or_else(|e| {
                error!(target: "security", "Failed to parse sessions JSON: {}", e);
                HashMap::new()
            });

        info!(target: "security", "Loaded {} active session(s) from storage", sessions.len());
        sessions
    }

    pub async fn save_sessions(&self, sessions: &HashMap<String, Session>) {
// <<<<<<< HEAD
        let content = match serde_json::to_string_pretty(sessions) {
            Ok(content) => content,
            Err(e) => {
                error!(target: "security", "Failed to serialize sessions JSON: {}", e);
                return;
            }
        };
        let tmp_suffix: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        let tmp_path = format!("{}.{}.tmp", &self.file_path, tmp_suffix);
// =======
//         let content = serde_json::to_string_pretty(sessions).unwrap();
//         let tmp_path = format!("{}.tmp", &self.file_path);
// >>>>>>> 6c88f6e (snoethu)

        if let Err(e) = fs::write(&tmp_path, content).await {
            error!(target: "security", "Failed to write sessions temp file: {}", e);
            return;
        }

        // On Windows, tokio::fs::rename fails if the destination already exists.
        // Remove the existing file (if any) before renaming to ensure cross-platform behavior.
        if Path::new(&self.file_path).exists() {
            if let Err(e) = fs::remove_file(&self.file_path).await {
                error!(target: "security", "Failed to remove existing sessions file: {}", e);
                let _ = fs::remove_file(&tmp_path).await;
                return;
            }
        }

        if let Err(e) = fs::rename(&tmp_path, &self.file_path).await {
            error!(target: "security", "Failed to rename sessions temp file: {}", e);
            let _ = fs::remove_file(&tmp_path).await;
        } else {
            info!(target: "security", "Saved {} session(s) to storage", sessions.len());
        }
    }

    pub async fn create_session(&self, user_id: &str) -> String {
        let token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let now = Self::current_time();
        let session = Session {
            user_id: user_id.to_string(),
            created_at: now,
            last_activity: now,
        };

        // Hash the token before storing - never store plaintext tokens
        let token_hash = Self::hash_token(&token);

        // Lock the entire read-modify-write cycle to prevent races
        let lock = SESSIONS_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
        let _guard = lock.lock().await;

        let mut sessions = self.load_sessions().await;
        sessions.insert(token_hash, session);
        self.save_sessions(&sessions).await;

        info!(
            target: "security",
            "Session created for user: {} (token prefix: {}..., timeout: {}s)",
            user_id,
            &token[..8],
            self.timeout
        );

        token
    }

    pub async fn validate_session(&self, token: &str) -> Option<Session> {
        let token_prefix = if token.len() >= 8 { &token[..8] } else { token };
        let token_hash = Self::hash_token(token);

        // Lock the entire read-modify-write cycle to prevent races
        let lock = SESSIONS_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
        let _guard = lock.lock().await;

        let mut sessions = self.load_sessions().await;

        if let Some(session) = sessions.get_mut(&token_hash) {
            let now = Self::current_time();
            let time_since_activity = now.saturating_sub(session.last_activity);

            if time_since_activity > self.timeout {
                warn!(
                    target: "security",
                    "Session expired for user: {} (token prefix: {}..., inactive for {}s)",
                    session.user_id,
                    token_prefix,
                    time_since_activity
                );
                sessions.remove(&token_hash);
                self.save_sessions(&sessions).await;
                return None;
            }

            info!(
                target: "security",
                "Session validated and refreshed for user: {} (token prefix: {}...)",
                session.user_id,
                token_prefix
            );

            session.last_activity = now;
            let result = session.clone();
            self.save_sessions(&sessions).await;
            return Some(result);
        }

        warn!(
            target: "security",
            "Session validation failed: token not found (token prefix: {}...)",
            token_prefix
        );
        None
    }

    pub async fn delete_session(&self, token: &str) -> bool {
        let token_prefix = if token.len() >= 8 { &token[..8] } else { token };
        let token_hash = Self::hash_token(token);

        // Lock the entire read-modify-write cycle to prevent races
        let lock = SESSIONS_FILE_LOCK.get_or_init(|| TokioMutex::new(()));
        let _guard = lock.lock().await;

        let mut sessions = self.load_sessions().await;

        if let Some(session) = sessions.remove(&token_hash) {
            self.save_sessions(&sessions).await;
            info!(
                target: "security",
                "Session deleted for user: {} (token prefix: {}...)",
                session.user_id,
                token_prefix
            );
            true
        } else {
            warn!(
                target: "security",
                "Attempted to delete non-existent session (token prefix: {}...)",
                token_prefix
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_token_consistency() {
        let token = "test123abc";
        let hash1 = SessionManager::hash_token(token);
        let hash2 = SessionManager::hash_token(token);
        assert_eq!(hash1, hash2, "Hash should be consistent");
        assert_ne!(hash1, token, "Hash should differ from token");
    }
}
