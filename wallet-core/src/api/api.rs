use crate::error::WalletError;
use crate::types::{WalletCredential, ChainConfig};
use crate::crypto;
use crate::chains::ethereum;

// Core Initialization
pub fn init_core() -> Result<(), WalletError> {
    // Initialize standard logging (example)
    Ok(())
}

// Check 'flutter_rust_bridge' for async handling. 
// It automatically handles async fn as Futures on Dart side.

// --- Key Management ---

pub fn create_wallet() -> Result<WalletCredential, WalletError> {
    crypto::create_wallet()
}

pub fn restore_wallet(mnemonic: String) -> Result<WalletCredential, WalletError> {
    crypto::restore_wallet(&mnemonic)
}

pub fn get_private_key_from_mnemonic(mnemonic: String) -> Result<String, WalletError> {
    crypto::get_private_key_from_seed(&mnemonic)
}

// --- Chain Operations ---

pub async fn get_balance(rpc_url: String, address: String) -> Result<String, WalletError> {
    ethereum::get_balance(rpc_url, address).await
}

pub async fn send_transaction(
    rpc_url: String, 
    private_key: String, 
    to: String, 
    amount: String
) -> Result<String, WalletError> {
    ethereum::send_native_token(rpc_url, private_key, to, amount).await
}

// --- Config Helpers ---

pub fn get_default_chains() -> Vec<ChainConfig> {
    vec![
        ChainConfig {
            name: "Ethereum Mainnet".to_string(),
            chain_id: 1,
            rpc_url: "https://eth.llamarpc.com".to_string(),
            symbol: "ETH".to_string(),
            explorer_url: "https://etherscan.io".to_string(),
        },
        ChainConfig {
            name: "Sepolia Testnet".to_string(),
            chain_id: 11155111,
            rpc_url: "https://rpc.sepolia.org".to_string(),
            symbol: "ETH".to_string(),
            explorer_url: "https://sepolia.etherscan.io".to_string(),
        },
        ChainConfig {
            name: "BNB Smart Chain".to_string(),
            chain_id: 56,
            rpc_url: "https://binance.llamarpc.com".to_string(),
            symbol: "BNB".to_string(),
            explorer_url: "https://bscscan.com".to_string(),
        },
        ChainConfig {
            name: "Base Mainnet".to_string(),
            chain_id: 8453,
            rpc_url: "https://mainnet.base.org".to_string(),
            symbol: "ETH".to_string(),
            explorer_url: "https://basescan.org".to_string(),
        },
    ]
}
