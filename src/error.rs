use thiserror::Error;

#[derive(Error, Debug)]
pub enum KapsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Password validation failed: {0}")]
    PasswordValidation(String),

    #[error("Invalid file format: {0}")]
    FileFormat(String),

    #[error("Invalid key/IV length: {0}")]
    KeyLength(#[from] aes::cipher::InvalidLength),

    #[error("Context error: {0}")]
    Context(String),
}

impl From<anyhow::Error> for KapsError {
    fn from(err: anyhow::Error) -> Self {
        KapsError::Context(err.to_string())
    }
}