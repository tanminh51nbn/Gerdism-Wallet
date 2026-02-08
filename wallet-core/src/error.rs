use thiserror::Error;

pub type WalletResult<T> = std::result::Result<T, WalletError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WalletError {
    #[error("Mnemonic Error: {0}")]
    Mnemonic(#[from] MnemonicError),

    #[error("Cryptography Error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Validation Error: {0}")]
    Validation(String),

    #[error("IO Error: {0}")]
    Io(String),

    #[error("Unknown Error: {0}")]
    Unknown(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MnemonicError {
    #[error("Invalid word count: {0}. Expected 12 or 24 words.")]
    InvalidWordCount(usize),

    #[error("Word '{0}' not found in the BIP39 wordlist.")]
    UnknownWord(String),

    #[error("Checksum validation failed.")]
    ChecksumFailed,

    #[error("BIP39 internal error: {0}")]
    Bip39Error(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),
}
