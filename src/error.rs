use crate::hotp::HotpError;
use rkv::StoreError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("{0}")]
    HotpError(#[from] HotpError),

    #[error("{0}")]
    IOError(#[from] std::io::Error),

    #[error("Could not read/write one time password: {0}")]
    RWError(String),

    #[error("{0}")]
    GenericError(String),

    #[error("{0}")]
    StoreError(#[from] StoreError),

    #[error("{0}")]
    KeyringError(#[from] keyring::Error),

    #[error("{0}")]
    SerdeError(#[from] serde_json::Error),
}
