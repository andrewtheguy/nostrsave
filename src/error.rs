use thiserror::Error;

#[derive(Error, Debug)]
pub enum NostrSaveError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Invalid file path: {0}")]
    InvalidPath(String),

    #[error("Missing chunks: {0:?}")]
    MissingChunks(Vec<usize>),

    #[error("Hash mismatch - expected: {expected}, got: {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("No relays available")]
    NoRelays,

    #[error("Failed to connect to any relay")]
    ConnectionFailed,

    #[error("Invalid manifest: {0}")]
    InvalidManifest(String),
}
