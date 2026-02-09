// wallet-core/src/network/traits.rs

// Universal Blockchain Provider Traits - Chain-Agnostic Interface
// Thiết kế theo chuẩn các ví hiện đại: MetaMask, Trust Wallet, Phantom
//
// Mọi blockchain provider PHẢI implement các traits này để đảm bảo
// tính nhất quán trong toàn bộ ứng dụng.

use crate::error::WalletResult;
use crate::network::models::{
    AccountInfo, AddressValidation, Balance, FeeEstimate, FeeOptions, NetworkInfo, NetworkStatus,
    NftInfo, TokenBalance, TokenInfo, Transaction, TransactionReceipt,
};
use async_trait::async_trait;

// =============================================================================
// CORE PROVIDER TRAIT
// =============================================================================

/// BlockchainProvider - Interface chính cho mọi blockchain
///
/// Đây là trait cốt lõi định nghĩa các hành vi BẮT BUỘC mà mọi
/// blockchain provider phải implement.
///
/// # Design Principles
/// - **Chain-Agnostic**: Không phụ thuộc vào chain-specific types
/// - **Async-First**: Tất cả network operations đều async
/// - **Error Handling**: Sử dụng `WalletResult` thống nhất
/// - **Composable**: Có thể kết hợp với các traits mở rộng
#[async_trait]
pub trait BlockchainProvider: Send + Sync {
    // =========================================================================
    // NETWORK INFO
    // =========================================================================

    /// Lấy thông tin mạng (chain ID, name, native token, etc.)
    fn network_info(&self) -> &NetworkInfo;

    /// Kiểm tra trạng thái kết nối
    async fn check_connection(&self) -> WalletResult<NetworkStatus>;

    // =========================================================================
    // BALANCE
    // =========================================================================

    /// Lấy số dư native token (ETH, BTC, SOL, etc.)
    ///
    /// # Arguments
    /// * `address` - Địa chỉ cần query
    ///
    /// # Returns
    /// Balance với raw value, formatted value, và symbol
    async fn get_balance(&self, address: &str) -> WalletResult<Balance>;

    // =========================================================================
    // TRANSACTION
    // =========================================================================

    /// Broadcast giao dịch đã ký
    ///
    /// # Arguments
    /// * `raw_tx` - Raw transaction bytes (đã RLP encode cho EVM, serialized cho others)
    ///
    /// # Returns
    /// Transaction hash
    async fn broadcast_transaction(&self, raw_tx: &[u8]) -> WalletResult<String>;

    /// Lấy trạng thái giao dịch theo hash
    async fn get_transaction(&self, tx_hash: &str) -> WalletResult<Option<Transaction>>;

    /// Lấy transaction receipt (sau khi confirmed)
    async fn get_transaction_receipt(
        &self,
        tx_hash: &str,
    ) -> WalletResult<Option<TransactionReceipt>>;

    /// Chờ giao dịch được confirm
    ///
    /// # Arguments
    /// * `tx_hash` - Transaction hash
    /// * `confirmations` - Số confirmations cần chờ
    /// * `timeout_secs` - Timeout (giây)
    async fn wait_for_confirmation(
        &self,
        tx_hash: &str,
        confirmations: u64,
        timeout_secs: u64,
    ) -> WalletResult<TransactionReceipt>;

    // =========================================================================
    // FEE ESTIMATION
    // =========================================================================

    /// Ước tính phí giao dịch
    ///
    /// # Arguments
    /// * `from` - Địa chỉ gửi
    /// * `to` - Địa chỉ nhận
    /// * `value` - Giá trị gửi (raw string)
    /// * `data` - Transaction data (optional, cho contract calls)
    async fn estimate_fee(
        &self,
        from: &str,
        to: &str,
        value: &str,
        data: Option<&[u8]>,
    ) -> WalletResult<FeeOptions>;

    // =========================================================================
    // ADDRESS
    // =========================================================================

    /// Validate địa chỉ
    fn validate_address(&self, address: &str) -> AddressValidation;

    // =========================================================================
    // HISTORY
    // =========================================================================

    /// Lấy lịch sử giao dịch
    ///
    /// # Arguments
    /// * `address` - Địa chỉ cần query
    /// * `page` - Trang (0-indexed)
    /// * `limit` - Số lượng mỗi trang
    async fn get_transaction_history(
        &self,
        address: &str,
        page: u32,
        limit: u32,
    ) -> WalletResult<Vec<Transaction>>;
}

// =============================================================================
// TOKEN PROVIDER TRAIT
// =============================================================================

/// TokenProvider - Interface cho blockchain hỗ trợ tokens (ERC-20, SPL, TRC-20, etc.)
///
/// Đây là trait MỞ RỘNG, không bắt buộc cho mọi chain (e.g., Bitcoin không có tokens).
#[async_trait]
pub trait TokenProvider: BlockchainProvider {
    /// Lấy thông tin token
    async fn get_token_info(&self, token_address: &str) -> WalletResult<Option<TokenInfo>>;

    /// Lấy số dư token của một địa chỉ
    async fn get_token_balance(&self, address: &str, token_address: &str) -> WalletResult<Balance>;

    /// Lấy tất cả token balances của một địa chỉ
    async fn get_all_token_balances(&self, address: &str) -> WalletResult<Vec<TokenBalance>>;

    /// Ước tính phí cho token transfer
    async fn estimate_token_transfer_fee(
        &self,
        from: &str,
        to: &str,
        token_address: &str,
        amount: &str,
    ) -> WalletResult<FeeOptions>;
}

// =============================================================================
// NFT PROVIDER TRAIT
// =============================================================================

/// NftProvider - Interface cho blockchain hỗ trợ NFTs (ERC-721, ERC-1155, SPL NFT, etc.)
#[async_trait]
pub trait NftProvider: BlockchainProvider {
    /// Lấy thông tin một NFT
    async fn get_nft_info(
        &self,
        contract_address: &str,
        token_id: &str,
    ) -> WalletResult<Option<NftInfo>>;

    /// Lấy tất cả NFTs của một địa chỉ
    async fn get_nfts_by_owner(&self, owner: &str) -> WalletResult<Vec<NftInfo>>;

    /// Ước tính phí cho NFT transfer
    async fn estimate_nft_transfer_fee(
        &self,
        from: &str,
        to: &str,
        contract_address: &str,
        token_id: &str,
    ) -> WalletResult<FeeOptions>;
}

// =============================================================================
// SMART CONTRACT PROVIDER TRAIT
// =============================================================================

/// ContractProvider - Interface cho blockchain hỗ trợ smart contracts
///
/// Cho phép đọc/ghi với smart contracts một cách generic.
#[async_trait]
pub trait ContractProvider: BlockchainProvider {
    /// Gọi read-only function (không tốn gas)
    ///
    /// # Arguments
    /// * `contract_address` - Địa chỉ contract
    /// * `data` - Encoded function call data
    ///
    /// # Returns
    /// Raw bytes response
    async fn call(&self, contract_address: &str, data: &[u8]) -> WalletResult<Vec<u8>>;

    /// Ước tính gas cho contract call
    async fn estimate_gas(
        &self,
        from: &str,
        to: &str,
        value: &str,
        data: &[u8],
    ) -> WalletResult<u64>;
}

// =============================================================================
// STAKING PROVIDER TRAIT
// =============================================================================

/// StakingProvider - Interface cho blockchain hỗ trợ staking
#[async_trait]
pub trait StakingProvider: BlockchainProvider {
    /// Lấy danh sách validators/delegators
    async fn get_validators(&self) -> WalletResult<Vec<ValidatorInfo>>;

    /// Lấy số dư đang stake
    async fn get_staked_balance(&self, address: &str) -> WalletResult<Balance>;

    /// Lấy rewards chưa claim
    async fn get_pending_rewards(&self, address: &str) -> WalletResult<Balance>;
}

/// Thông tin Validator
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorInfo {
    /// Địa chỉ validator
    pub address: String,
    /// Tên validator
    pub name: Option<String>,
    /// Commission rate (0-100)
    pub commission_rate: f64,
    /// Total staked
    pub total_staked: String,
    /// APY ước tính
    pub estimated_apy: Option<f64>,
    /// Có active không
    pub is_active: bool,
}

// =============================================================================
// SUBSCRIPTION TRAIT
// =============================================================================

/// SubscriptionProvider - Interface cho realtime updates
#[async_trait]
pub trait SubscriptionProvider: BlockchainProvider {
    /// Subscribe balance updates
    async fn subscribe_balance(
        &self,
        address: &str,
        callback: Box<dyn Fn(Balance) + Send + Sync>,
    ) -> WalletResult<SubscriptionId>;

    /// Subscribe pending transactions
    async fn subscribe_pending_transactions(
        &self,
        address: &str,
        callback: Box<dyn Fn(Transaction) + Send + Sync>,
    ) -> WalletResult<SubscriptionId>;

    /// Unsubscribe
    async fn unsubscribe(&self, subscription_id: SubscriptionId) -> WalletResult<()>;
}

/// ID của subscription
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubscriptionId(pub String);

// =============================================================================
// PROVIDER FACTORY
// =============================================================================

/// Trait để tạo provider instances
pub trait ProviderFactory {
    /// Tạo provider từ network info
    fn create_provider(network: &NetworkInfo) -> WalletResult<Box<dyn BlockchainProvider>>;
}

// =============================================================================
// MULTI-PROVIDER MANAGER
// =============================================================================

/// Interface quản lý nhiều providers
#[async_trait]
pub trait MultiProviderManager: Send + Sync {
    /// Lấy provider theo chain ID
    fn get_provider(&self, chain_id: &str) -> Option<&dyn BlockchainProvider>;

    /// Thêm provider mới
    fn add_provider(&mut self, provider: Box<dyn BlockchainProvider>) -> WalletResult<()>;

    /// Xóa provider
    fn remove_provider(&mut self, chain_id: &str) -> WalletResult<()>;

    /// Lấy danh sách tất cả chain IDs đang active
    fn active_chain_ids(&self) -> Vec<String>;

    /// Lấy tổng số dư trên tất cả chains (theo USD)
    async fn get_total_balance_usd(&self, address: &str) -> WalletResult<String>;
}
