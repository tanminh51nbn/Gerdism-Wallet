#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletError {
    // ===== Generic =====
    Unknown,
    InvalidInput,

    // ===== Cryptography =====
    InvalidSignature,
    InvalidPublicKey,
    InvalidPrivateKey,
    CryptographyFailed,

    // ===== Wallet =====
    InvalidMnemonic,
    InvalidDerivationPath,
    AccountNotFound,
    KeyManagementFailed,

    // ===== Transaction =====
    InvalidTransactionData,
    TransactionBuildFailed,
    InsufficientGas,
    InsufficientFunds,

    // ===== Network / RPC =====
    NetworkFailed,
    RpcFailed,
    RequestTimeout,

    // ===== Hardware Wallet =====
    HardwareWalletFailed,
    DeviceNotFound,
    DeviceActionCancelled,
}

impl WalletError {
    pub fn message(&self) -> &'static str {
        match self {
            WalletError::Unknown => "Unknown error",
            WalletError::InvalidInput => "Invalid input",

            WalletError::InvalidSignature => "Invalid signature",
            WalletError::InvalidPublicKey => "Invalid public key",
            WalletError::InvalidPrivateKey => "Invalid private key",
            WalletError::CryptographyFailed => "Cryptography failed",

            WalletError::InvalidMnemonic => "Invalid mnemonic",
            WalletError::InvalidDerivationPath => "Invalid derivation path",
            WalletError::AccountNotFound => "Account not found",
            WalletError::KeyManagementFailed => "Key management failed",

            WalletError::InvalidTransactionData => "Invalid transaction data",
            WalletError::TransactionBuildFailed => "Transaction build failed",
            WalletError::InsufficientGas => "Insufficient gas",
            WalletError::InsufficientFunds => "Insufficient funds",

            WalletError::NetworkFailed => "Network error",
            WalletError::RpcFailed => "RPC request failed",
            WalletError::RequestTimeout => "Request timeout",

            WalletError::HardwareWalletFailed => "Hardware wallet error",
            WalletError::DeviceNotFound => "Device not found",
            WalletError::DeviceActionCancelled => "Action cancelled on device",
        }
    }
}
