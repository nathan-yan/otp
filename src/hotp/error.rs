use thiserror::Error;

#[derive(Error, Debug)]
pub enum HotpError {
    #[error("Error parsing secret: {0}")]
    SecretError(String),
}
