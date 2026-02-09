// wallet-core/src/network/models.rs
//
// Universal Data Models - Chain-Agnostic Structures for Multi-Chain Wallet
// Thiết kế theo chuẩn các ví hiện đại: MetaMask, Trust Wallet, Phantom
//
// Tất cả structs đều:
// - Serialize/Deserialize friendly (JSON cho Flutter FFI)
// - Không phụ thuộc vào chain-specific types (EVM U256, Solana Pubkey, etc.)
// - Clone + Debug cho flexibility

use serde::{Deserialize, Serialize};

// =============================================================================
// CHAIN IDENTIFICATION
// =============================================================================

/// Loại blockchain (để phân biệt logic xử lý)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    /// Ethereum Virtual Machine (Ethereum, BSC, Polygon, Arbitrum, etc.)
    Evm,
    /// Bitcoin và các fork (Litecoin, Dogecoin, etc.)
    Bitcoin,
    /// Solana Virtual Machine
    Solana,
    /// Cosmos SDK chains (Cosmos Hub, Osmosis, etc.)
    Cosmos,
    /// Tron
    Tron,
}

/// Thông tin một blockchain network
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInfo {
    /// Chain ID (unique identifier)
    pub chain_id: String,
    /// Tên hiển thị (e.g., "Ethereum Mainnet")
    pub name: String,
    /// Symbol của native token (e.g., "ETH", "BTC", "SOL")
    pub native_symbol: String,
    /// Số decimals của native token
    pub native_decimals: u8,
    /// Loại chain
    pub chain_type: ChainType,
    /// RPC URL (có thể là array cho fallback)
    pub rpc_url: String,
    /// Block explorer URL (optional)
    pub explorer_url: Option<String>,
    /// Logo URL (optional)
    pub logo_url: Option<String>,
    /// Có phải testnet không
    pub is_testnet: bool,
}

// =============================================================================
// BALANCE & ASSETS
// =============================================================================

/// Số dư tài sản (chain-agnostic)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Balance {
    /// Số dư raw (string để tránh overflow với số lớn)
    pub raw: String,
    /// Số dư đã format với decimals (e.g., "1.5")
    pub formatted: String,
    /// Symbol (e.g., "ETH", "USDT")
    pub symbol: String,
    /// Số decimals
    pub decimals: u8,
    /// Giá trị USD (optional, nếu có price feed)
    pub usd_value: Option<String>,
}

impl Balance {
    /// Tạo Balance từ raw value và decimals
    pub fn new(raw: impl Into<String>, decimals: u8, symbol: impl Into<String>) -> Self {
        let raw_str = raw.into();
        let formatted = Self::format_balance(&raw_str, decimals);
        Self {
            raw: raw_str,
            formatted,
            symbol: symbol.into(),
            decimals,
            usd_value: None,
        }
    }

    /// Tạo Balance với giá trị = 0
    pub fn zero(symbol: impl Into<String>, decimals: u8) -> Self {
        Self {
            raw: "0".to_string(),
            formatted: "0".to_string(),
            symbol: symbol.into(),
            decimals,
            usd_value: None,
        }
    }

    /// Format raw balance thành human-readable string
    fn format_balance(raw: &str, decimals: u8) -> String {
        if decimals == 0 || raw == "0" {
            return raw.to_string();
        }

        let raw_len = raw.len();
        let decimals_usize = decimals as usize;

        if raw_len <= decimals_usize {
            // Số nhỏ hơn 1 (e.g., 0.001)
            let padding = decimals_usize - raw_len;
            let decimal_part = format!("{}{}", "0".repeat(padding), raw);
            let trimmed = decimal_part.trim_end_matches('0');
            if trimmed.is_empty() {
                "0".to_string()
            } else {
                format!("0.{}", trimmed)
            }
        } else {
            // Số >= 1
            let integer_part = &raw[..raw_len - decimals_usize];
            let decimal_part = &raw[raw_len - decimals_usize..];
            let trimmed_decimal = decimal_part.trim_end_matches('0');
            if trimmed_decimal.is_empty() {
                integer_part.to_string()
            } else {
                format!("{}.{}", integer_part, trimmed_decimal)
            }
        }
    }
}

/// Thông tin Token (ERC-20, SPL, TRC-20, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenInfo {
    /// Contract address / Mint address
    pub address: String,
    /// Symbol (e.g., "USDT")
    pub symbol: String,
    /// Tên đầy đủ (e.g., "Tether USD")
    pub name: String,
    /// Số decimals
    pub decimals: u8,
    /// Logo URL (optional)
    pub logo_url: Option<String>,
    /// Có verified không (từ token list)
    pub verified: bool,
}

/// Token Balance (Token + Balance)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenBalance {
    /// Thông tin token
    pub token: TokenInfo,
    /// Số dư
    pub balance: Balance,
}

// =============================================================================
// NFT
// =============================================================================

/// Thông tin NFT (ERC-721, ERC-1155, SPL, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NftInfo {
    /// Contract address / Mint address
    pub contract_address: String,
    /// Token ID (string vì có thể rất lớn)
    pub token_id: String,
    /// Tên NFT
    pub name: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Image URL
    pub image_url: Option<String>,
    /// Animation URL (video/audio)
    pub animation_url: Option<String>,
    /// Collection name
    pub collection_name: Option<String>,
    /// Attributes/Traits
    pub attributes: Vec<NftAttribute>,
    /// Token standard (ERC721, ERC1155, SPL, etc.)
    pub token_standard: String,
    /// Số lượng (cho ERC-1155)
    pub amount: u64,
}

/// NFT Attribute/Trait
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NftAttribute {
    pub trait_type: String,
    pub value: String,
    /// Rarity percentage (optional)
    pub rarity: Option<f64>,
}

// =============================================================================
// TRANSACTIONS
// =============================================================================

/// Trạng thái giao dịch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransactionStatus {
    /// Đang chờ xác nhận
    Pending,
    /// Đã xác nhận thành công
    Confirmed,
    /// Thất bại
    Failed,
    /// Đã bị thay thế (speed up / cancel)
    Replaced,
}

/// Loại giao dịch (để hiển thị icon/label)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransactionType {
    /// Gửi native token
    Send,
    /// Nhận native token
    Receive,
    /// Chuyển token
    TokenTransfer,
    /// Swap
    Swap,
    /// Approve token
    Approve,
    /// Mint NFT
    NftMint,
    /// Transfer NFT
    NftTransfer,
    /// Contract interaction khác
    ContractCall,
    /// Không xác định
    Unknown,
}

/// Chi tiết giao dịch (chain-agnostic)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    /// Transaction hash
    pub hash: String,
    /// Địa chỉ người gửi
    pub from: String,
    /// Địa chỉ người nhận (có thể là contract)
    pub to: Option<String>,
    /// Giá trị gửi (raw string)
    pub value: String,
    /// Giá trị đã format (human-readable)
    pub value_formatted: String,
    /// Symbol của token được chuyển
    pub symbol: String,
    /// Loại giao dịch
    pub tx_type: TransactionType,
    /// Trạng thái
    pub status: TransactionStatus,
    /// Phí giao dịch (raw string)
    pub fee: String,
    /// Phí đã format
    pub fee_formatted: String,
    /// Block number (nếu confirmed)
    pub block_number: Option<u64>,
    /// Timestamp (Unix seconds)
    pub timestamp: Option<u64>,
    /// Số confirmations
    pub confirmations: u64,
    /// Chain ID
    pub chain_id: String,
    /// Nonce (cho EVM)
    pub nonce: Option<u64>,
    /// Explorer URL
    pub explorer_url: Option<String>,
}

/// Transaction Receipt (kết quả sau khi broadcast)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionReceipt {
    /// Transaction hash
    pub hash: String,
    /// Trạng thái
    pub status: TransactionStatus,
    /// Block number
    pub block_number: Option<u64>,
    /// Phí thực tế đã trả
    pub fee_paid: String,
    /// Gas used (cho EVM)
    pub gas_used: Option<u64>,
    /// Explorer URL
    pub explorer_url: Option<String>,
}

// =============================================================================
// FEE ESTIMATION
// =============================================================================

/// Mức phí giao dịch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeeLevel {
    /// Chậm (tiết kiệm)
    Slow,
    /// Trung bình
    Average,
    /// Nhanh
    Fast,
    /// Rất nhanh (instant)
    Instant,
}

/// Ước tính phí giao dịch
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeEstimate {
    /// Mức phí
    pub level: FeeLevel,
    /// Phí ước tính (raw)
    pub fee_raw: String,
    /// Phí ước tính (formatted)
    pub fee_formatted: String,
    /// Symbol của phí (e.g., "ETH", "SOL")
    pub fee_symbol: String,
    /// Thời gian ước tính (giây)
    pub estimated_time_seconds: u64,
    /// Giá trị USD (optional)
    pub usd_value: Option<String>,
    // === EVM specific (optional) ===
    /// Gas limit
    pub gas_limit: Option<u64>,
    /// Gas price (Legacy)
    pub gas_price: Option<String>,
    /// Max fee per gas (EIP-1559)
    pub max_fee_per_gas: Option<String>,
    /// Max priority fee (EIP-1559)
    pub max_priority_fee: Option<String>,
}

/// Tập hợp các mức phí
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeOptions {
    pub slow: FeeEstimate,
    pub average: FeeEstimate,
    pub fast: FeeEstimate,
    pub instant: Option<FeeEstimate>,
    /// Base fee hiện tại (EVM)
    pub base_fee: Option<String>,
}

// =============================================================================
// ACCOUNT & ADDRESS
// =============================================================================

/// Thông tin Account
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    /// Địa chỉ
    pub address: String,
    /// Tên hiển thị (user-defined)
    pub label: Option<String>,
    /// Derivation path (nếu là HD wallet)
    pub derivation_path: Option<String>,
    /// Account index
    pub index: u32,
    /// Loại chain
    pub chain_type: ChainType,
}

/// Kết quả validation địa chỉ
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressValidation {
    /// Có hợp lệ không
    pub is_valid: bool,
    /// Địa chỉ đã normalize (checksum, etc.)
    pub normalized: Option<String>,
    /// Lý do không hợp lệ (nếu có)
    pub error: Option<String>,
}

// =============================================================================
// GAS / NETWORK STATUS
// =============================================================================

/// Trạng thái mạng
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkStatus {
    /// Có đang hoạt động không
    pub is_online: bool,
    /// Block number mới nhất
    pub latest_block: u64,
    /// Thời gian block trung bình (giây)
    pub block_time_seconds: f64,
    /// Network congestion level (0-100)
    pub congestion_level: Option<u8>,
    /// Latency (ms)
    pub latency_ms: u64,
}

// =============================================================================
// ERROR RESPONSE
// =============================================================================

/// Error response cho Flutter
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    /// Error code
    pub code: String,
    /// Human-readable message
    pub message: String,
    /// Chi tiết kỹ thuật (optional)
    pub details: Option<String>,
}

impl ApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balance_formatting() {
        // 1 ETH = 1000000000000000000 wei (18 decimals)
        let balance = Balance::new("1000000000000000000", 18, "ETH");
        assert_eq!(balance.formatted, "1");

        // 1.5 ETH
        let balance = Balance::new("1500000000000000000", 18, "ETH");
        assert_eq!(balance.formatted, "1.5");

        // 0.001 ETH
        let balance = Balance::new("1000000000000000", 18, "ETH");
        assert_eq!(balance.formatted, "0.001");

        // 1 USDT (6 decimals)
        let balance = Balance::new("1000000", 6, "USDT");
        assert_eq!(balance.formatted, "1");
    }

    #[test]
    fn test_balance_zero() {
        let balance = Balance::zero("ETH", 18);
        assert_eq!(balance.raw, "0");
        assert_eq!(balance.formatted, "0");
    }

    #[test]
    fn test_serialization() {
        let tx = Transaction {
            hash: "0x123...".to_string(),
            from: "0xabc...".to_string(),
            to: Some("0xdef...".to_string()),
            value: "1000000000000000000".to_string(),
            value_formatted: "1".to_string(),
            symbol: "ETH".to_string(),
            tx_type: TransactionType::Send,
            status: TransactionStatus::Confirmed,
            fee: "21000000000000".to_string(),
            fee_formatted: "0.000021".to_string(),
            block_number: Some(12345678),
            timestamp: Some(1699999999),
            confirmations: 10,
            chain_id: "1".to_string(),
            nonce: Some(5),
            explorer_url: Some("https://etherscan.io/tx/0x123...".to_string()),
        };

        let json = serde_json::to_string(&tx).unwrap();
        assert!(json.contains("camelCase") == false); // Đã convert sang camelCase
        assert!(json.contains("txType")); // camelCase field
    }
}
