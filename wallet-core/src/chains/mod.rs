// src/chains/mod.rs
pub mod trait_api;
pub mod ethereum;

// Định nghĩa cấu hình chung cho các EVM Chain
#[derive(Debug, Clone)]
pub struct EvmChainConfig {
    pub chain_id: u64,
    pub rpc_url: String,
    pub indexer_api_url: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}

// Helper để tạo nhanh config cho các mạng phổ biến
impl EvmChainConfig {
    pub fn ethereum() -> Self {
        Self {
            chain_id: 1,
            rpc_url: "https://eth.llamarpc.com".to_string(),
            indexer_api_url: "https://api.etherscan.io/api".to_string(),
            name: "Ethereum Mainnet".to_string(),
            symbol: "ETH".to_string(),
            decimals: 18,
        }
    }

    pub fn sepolia() -> Self {
        Self {
            chain_id: 11155111,
            rpc_url: "https://ethereum-sepolia-rpc.publicnode.com".to_string(),
            indexer_api_url: "https://api.etherscan.io/v2/api".to_string(),
            name: "Ethereum Sepolia".to_string(),
            symbol: "ETH".to_string(),
            decimals: 18,
        }
    }

    pub fn bsc() -> Self {
        Self {
            chain_id: 56,
            rpc_url: "https://binance.llamarpc.com".to_string(),
            indexer_api_url: "https://api.bscscan.com/api".to_string(),
            name: "BNB Smart Chain".to_string(),
            symbol: "BNB".to_string(),
            decimals: 18,
        }
    }
}