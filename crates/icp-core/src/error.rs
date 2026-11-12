//! Errors.

use std::fmt;

/// Everything that can go wrong.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Proto(String),

    #[error("{0}")]
    Crypto(String),

    #[error("{0}")]
    Apple(String),

    #[error("network error talking to {url}: {source}")]
    Network {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("unexpected response from {url}")]
    BadResponse { url: String },

    #[error("not signed in - run `icp login`")]
    NotSignedIn,

    #[error("not joined to the keychain - run `icp login`")]
    NotJoined,

    #[error("the keychain trust does not include the key of this view yet")]
    NoViewKey,

    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Json(#[from] serde_json::Error),

    #[error("bad hex: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("bad key: {0}")]
    Key(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A CloudKit operation failure, with the code Apple returned.
#[derive(Debug, Clone)]
pub struct CloudKitFailure {
    pub code: i64,
    pub description: Option<String>,
}

impl fmt::Display for CloudKitFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.description {
            Some(d) => write!(f, "{}", d),
            None => write!(f, "CloudKit error {}", self.code),
        }
    }
}
