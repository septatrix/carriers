//! Error types for the carriers core.

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("key error: {0}")]
    Key(String),

    #[error("mail authentication/signing error: {0}")]
    Auth(String),

    #[error("delivery error: {0}")]
    Delivery(String),

    #[error("list not found: {0}")]
    ListNotFound(String),

    /// The message was intentionally not distributed (policy, loop, duplicate).
    #[error("message rejected: {0}")]
    Rejected(String),
}
