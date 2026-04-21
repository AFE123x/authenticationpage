use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: String,
    pub filename: String,
    pub size: u64,
    pub uploaded_by: String,
    pub uploaded_at: DateTime<Utc>,
    pub path: String,
    pub permissions: HashMap<String, String>, // e.g., {"alice": "viewer", "bob": "editor"}
    pub version: u32,
    pub audit_log: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentResponse {
    pub id: String,
    pub filename: String,
    pub size: u64,
    pub uploaded_at: DateTime<Utc>,
    pub uploaded_by: String,
    pub permissions: Option<HashMap<String, String>>,
    pub version: u32,
    pub audit_log: Option<Vec<String>>,
}

impl From<Document> for DocumentResponse {
    fn from(doc: Document) -> Self {
        Self {
            id: doc.id,
            filename: doc.filename,
            size: doc.size,
            uploaded_at: doc.uploaded_at,
            uploaded_by: doc.uploaded_by,
            permissions: Some(doc.permissions),
            version: doc.version,
            audit_log: Some(doc.audit_log),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentMetadata {
    pub documents: HashMap<String, Document>,
}

const METADATA_FILE: &str = "data/documents_metadata.json";
const DOCUMENTS_DIR: &str = "data/files";

static METADATA_LOCK: OnceLock<RwLock<()>> = OnceLock::new();

fn get_lock() -> &'static RwLock<()> {
    METADATA_LOCK.get_or_init(|| RwLock::new(()))
}

pub async fn init_documents_dir() -> Result<(), String> {
    let _guard = get_lock().write().await;
    if !Path::new(DOCUMENTS_DIR).exists() {
        fs::create_dir_all(DOCUMENTS_DIR)
            .await
            .map_err(|e| format!("Failed to create documents directory: {}", e))?;
        info!("Documents directory created at {}", DOCUMENTS_DIR);
    }
    Ok(())
}

async fn load_document_metadata_internal() -> HashMap<String, Document> {
    if !Path::new(METADATA_FILE).exists() {
        return HashMap::new();
    }

    match fs::read_to_string(METADATA_FILE).await {
        Ok(contents) => match serde_json::from_str::<DocumentMetadata>(&contents) {
            Ok(metadata) => {
                info!(
                    "Loaded {} documents from metadata",
                    metadata.documents.len()
                );
                metadata.documents
            }
            Err(e) => {
                error!("Failed to parse documents metadata: {}", e);
                HashMap::new()
            }
        },
        Err(e) => {
            error!("Failed to read documents metadata: {}", e);
            HashMap::new()
        }
    }
}

async fn save_document_metadata_internal(
    documents: &HashMap<String, Document>,
) -> Result<(), String> {
    let metadata = DocumentMetadata {
        documents: documents.clone(),
    };

    let json = serde_json::to_string_pretty(&metadata)
        .map_err(|e| format!("Failed to serialize documents: {}", e))?;

    // Use a unique temporary file to avoid conflicts with concurrent saves
    let tmp_suffix = Uuid::new_v4().to_string();
    let temp_file = format!("{}.{}.tmp", METADATA_FILE, tmp_suffix);

    if let Err(e) = fs::write(&temp_file, json).await {
        return Err(format!("Failed to write temporary metadata file: {}", e));
    }

    // On Windows, std::fs::rename fails if the destination already exists.
    // We attempt to remove it first.
    if Path::new(METADATA_FILE).exists() {
        if let Err(e) = fs::remove_file(METADATA_FILE).await {
            warn!(
                "Could not remove existing metadata file '{}' before rename: {}. Attempting rename anyway.",
                METADATA_FILE, e
            );
        }
    }

    if let Err(e) = fs::rename(&temp_file, METADATA_FILE).await {
        // Clean up the temp file if rename fails
        let _ = fs::remove_file(&temp_file).await;
        return Err(format!("Failed to rename metadata file: {}", e));
    }

    info!("Saved {} documents to metadata", documents.len());
    Ok(())
}

pub fn create_document(
    filename: String,
    size: u64,
    uploaded_by: String,
) -> Result<Document, String> {
    let id = Uuid::new_v4().to_string();
    let path = format!("{}/{}", DOCUMENTS_DIR, id);

    let now = Utc::now();
    let document = Document {
        id: id.clone(),
        filename,
        size,
        uploaded_by: uploaded_by.clone(),
        uploaded_at: now,
        path,
        permissions: HashMap::new(),
        version: 1,
        audit_log: vec![format!(
            "[{}] User {} uploaded version 1",
            now.to_rfc3339(),
            uploaded_by
        )],
    };

    Ok(document)
}

pub async fn get_document_by_id(id: &str) -> Option<Document> {
    let _guard = get_lock().read().await;
    let documents = load_document_metadata_internal().await;
    documents.get(id).cloned()
}

pub async fn get_user_documents(username: &str) -> Vec<Document> {
    let _guard = get_lock().read().await;
    let documents = load_document_metadata_internal().await;
    let mut user_docs: Vec<_> = documents
        .values()
        .filter(|doc| doc.uploaded_by == username || doc.permissions.contains_key(username))
        .cloned()
        .collect();

    // Sort by upload date, newest first
    user_docs.sort_by(|a, b| b.uploaded_at.cmp(&a.uploaded_at));
    user_docs
}

pub async fn get_all_documents() -> Vec<Document> {
    let _guard = get_lock().read().await;
    let documents = load_document_metadata_internal().await;
    let mut all_docs: Vec<_> = documents.values().cloned().collect();
    all_docs.sort_by(|a, b| b.uploaded_at.cmp(&a.uploaded_at));
    all_docs
}

pub async fn delete_document(id: &str) -> Result<(), String> {
    let _guard = get_lock().write().await;
    let mut documents = load_document_metadata_internal().await;

    if let Some(doc) = documents.remove(id) {
        // Delete the actual file
        if Path::new(&doc.path).exists() {
            fs::remove_file(&doc.path)
                .await
                .map_err(|e| format!("Failed to delete file: {}", e))?;
        }

        // Update metadata
        save_document_metadata_internal(&documents).await?;
        info!("Deleted document: {}", id);
        Ok(())
    } else {
        Err("Document not found".to_string())
    }
}

pub async fn add_document(document: Document) -> Result<(), String> {
    let _guard = get_lock().write().await;
    let mut documents = load_document_metadata_internal().await;
    documents.insert(document.id.clone(), document);
    save_document_metadata_internal(&documents).await?;
    Ok(())
}

pub async fn with_document_mut<F, R>(id: &str, f: F) -> Result<R, String>
where
    F: FnOnce(&mut Document) -> R,
{
    let _guard = get_lock().write().await;
    let mut documents = load_document_metadata_internal().await;

    if let Some(doc) = documents.get_mut(id) {
        let result = f(doc);
        save_document_metadata_internal(&documents).await?;
        Ok(result)
    } else {
        Err("Document not found".to_string())
    }
}
