// wallet-core\src\chains\evm\signer.rs
//
// EVM Signer Module - Professional Grade Offline Signing
// Hỗ trợ: EIP-155 (Replay Protection), EIP-191 (Personal Sign), EIP-712 (Typed Data), EIP-1559/2930/2718

use crate::error::{CryptoError, WalletError, WalletResult};
use alloy::{
    eips::eip2718::Encodable2718,
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address, Signature, B256, U256},
    rpc::types::eth::TransactionRequest,
    signers::{local::LocalSigner, Signer, SignerSync},
    sol_types::{Eip712Domain, SolStruct},
};
use k256::ecdsa::SigningKey;

/// EVM Signer - High-performance & Secure Offline Signing
///
/// # Security Architecture
/// - **ZeroizeOnDrop**: `SigningKey` tự động ghi đè bộ nhớ bằng 0 khi Drop
/// - **Replay Protection**: Chain ID bắt buộc để ngăn chặn replay attack
/// - **No Debug Leak**: Custom Debug impl không hiển thị private key
/// - **Memory Safety**: Rust ownership đảm bảo key không bị copy ngoài ý muốn
///
/// # Performance
/// - **Cached Address**: Địa chỉ được tính toán một lần khi khởi tạo
/// - **Sync Variants**: Các hàm `_sync` cho signing không cần async overhead
/// - **Zero-copy**: Sử dụng references khi có thể
pub struct EvmSigner {
    signer: LocalSigner<SigningKey>,
    address: Address,
    chain_id: u64,
}

// Custom Debug - KHÔNG BAO GIỜ hiển thị private key
impl std::fmt::Debug for EvmSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvmSigner")
            .field("address", &self.address)
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

// Explicit Drop để logging (production có thể bật audit log)
impl Drop for EvmSigner {
    fn drop(&mut self) {
        // SigningKey bên trong sẽ tự động Zeroize
        // Log này giúp debug memory lifecycle trong development
        #[cfg(debug_assertions)]
        eprintln!("[EvmSigner] Dropped signer for address: {}", self.address);
    }
}

impl EvmSigner {
    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    /// Khởi tạo Signer với Private Key và Chain ID
    ///
    /// # Arguments
    /// * `priv_key` - Private key 32 bytes
    /// * `chain_id` - Chain ID (1 = Ethereum, 56 = BSC, 137 = Polygon, ...)
    ///
    /// # Security
    /// Chain ID bắt buộc để kích hoạt EIP-155 Replay Protection
    pub fn new(priv_key: &[u8], chain_id: u64) -> WalletResult<Self> {
        let signing_key = SigningKey::from_slice(priv_key).map_err(|e| {
            WalletError::Crypto(CryptoError::InvalidKeyFormat(format!(
                "Invalid private key (must be 32 bytes): {}",
                e
            )))
        })?;

        let signer = LocalSigner::from(signing_key).with_chain_id(Some(chain_id));
        let address = signer.address();

        Ok(Self {
            signer,
            address,
            chain_id,
        })
    }

    // =========================================================================
    // GETTERS
    // =========================================================================

    /// Lấy địa chỉ Ethereum (EIP-55 Checksum)
    #[inline]
    pub fn address(&self) -> Address {
        self.address
    }

    /// Lấy Chain ID hiện tại
    #[inline]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    // =========================================================================
    // TRANSACTION SIGNING (EIP-155, EIP-1559, EIP-2930)
    // =========================================================================

    /// Ký giao dịch Offline và trả về Raw Bytes (RLP Encoded)
    ///
    /// Tự động hỗ trợ:
    /// - Legacy Transaction (EIP-155)
    /// - EIP-2930 (Access List)
    /// - EIP-1559 (Dynamic Fee)
    ///
    /// # Returns
    /// Raw transaction bytes sẵn sàng broadcast qua `eth_sendRawTransaction`
    pub async fn sign_transaction(&self, tx: TransactionRequest) -> WalletResult<Vec<u8>> {
        let wallet = EthereumWallet::from(self.signer.clone());

        let envelope = tx
            .build(&wallet)
            .await
            .map_err(|e| WalletError::Crypto(CryptoError::SigningFailed(e.to_string())))?;

        Ok(envelope.encoded_2718())
    }

    // =========================================================================
    // MESSAGE SIGNING (EIP-191)
    // =========================================================================

    /// Ký thông điệp bất kỳ (EIP-191 Personal Sign)
    ///
    /// Tự động thêm prefix: "\x19Ethereum Signed Message:\n{len}{message}"
    /// Dùng cho: Login DApps, Verify ownership, Off-chain authorization
    pub async fn sign_message(&self, message: &[u8]) -> WalletResult<Signature> {
        self.signer
            .sign_message(message)
            .await
            .map_err(|e| WalletError::Crypto(CryptoError::SigningFailed(e.to_string())))
    }

    /// Ký thông điệp (Sync version - nhanh hơn, không cần async runtime)
    pub fn sign_message_sync(&self, message: &[u8]) -> WalletResult<Signature> {
        self.signer
            .sign_message_sync(message)
            .map_err(|e| WalletError::Crypto(CryptoError::SigningFailed(e.to_string())))
    }

    // =========================================================================
    // HASH SIGNING (Low-level)
    // =========================================================================

    /// Ký hash trực tiếp (32 bytes)
    ///
    /// # Warning
    /// Chỉ sử dụng khi bạn đã tự hash dữ liệu theo chuẩn phù hợp.
    /// Sai cách hash có thể dẫn đến lỗ hổng bảo mật.
    pub async fn sign_hash(&self, hash: &B256) -> WalletResult<Signature> {
        self.signer
            .sign_hash(hash)
            .await
            .map_err(|e| WalletError::Crypto(CryptoError::SigningFailed(e.to_string())))
    }

    /// Ký hash (Sync version)
    pub fn sign_hash_sync(&self, hash: &B256) -> WalletResult<Signature> {
        self.signer
            .sign_hash_sync(hash)
            .map_err(|e| WalletError::Crypto(CryptoError::SigningFailed(e.to_string())))
    }

    // =========================================================================
    // TYPED DATA SIGNING (EIP-712)
    // =========================================================================

    /// Ký Typed Data theo chuẩn EIP-712
    ///
    /// Dùng cho: Permit (ERC-20), Orders (DEX), Gasless transactions
    ///
    /// # Arguments
    /// * `data` - Struct implement `SolStruct` (generated by `sol!` macro)
    /// * `domain` - Optional custom domain, mặc định sử dụng chain_id của signer
    pub async fn sign_typed_data<T: SolStruct + Send + Sync>(
        &self,
        data: &T,
        domain: Option<&Eip712Domain>,
    ) -> WalletResult<Signature> {
        // Sử dụng domain được cung cấp hoặc tạo default với chain_id
        let default_domain;
        let signing_domain = match domain {
            Some(d) => d,
            None => {
                default_domain = Eip712Domain {
                    chain_id: Some(U256::from(self.chain_id)),
                    ..Default::default()
                };
                &default_domain
            }
        };

        let hash = data.eip712_signing_hash(signing_domain);

        self.signer
            .sign_hash(&hash)
            .await
            .map_err(|e| WalletError::Crypto(CryptoError::SigningFailed(e.to_string())))
    }

    /// Ký Typed Data (Sync version)
    pub fn sign_typed_data_sync<T: SolStruct>(
        &self,
        data: &T,
        domain: Option<&Eip712Domain>,
    ) -> WalletResult<Signature> {
        let default_domain;
        let signing_domain = match domain {
            Some(d) => d,
            None => {
                default_domain = Eip712Domain {
                    chain_id: Some(U256::from(self.chain_id)),
                    ..Default::default()
                };
                &default_domain
            }
        };

        let hash = data.eip712_signing_hash(signing_domain);

        self.signer
            .sign_hash_sync(&hash)
            .map_err(|e| WalletError::Crypto(CryptoError::SigningFailed(e.to_string())))
    }

    // =========================================================================
    // SIGNATURE VERIFICATION
    // =========================================================================

    /// Verify chữ ký của message (kiểm tra xem có đúng là signer này ký không)
    pub fn verify_message(&self, message: &[u8], signature: &Signature) -> bool {
        signature
            .recover_address_from_msg(message)
            .map(|recovered| recovered == self.address)
            .unwrap_or(false)
    }

    /// Verify chữ ký của hash
    pub fn verify_hash(&self, hash: &B256, signature: &Signature) -> bool {
        signature
            .recover_address_from_prehash(hash)
            .map(|recovered| recovered == self.address)
            .unwrap_or(false)
    }
}

// =============================================================================
// UNIT TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIVATE_KEY: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const TEST_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const TEST_CHAIN_ID: u64 = 31337; // Anvil/Hardhat

    fn create_test_signer() -> EvmSigner {
        let priv_key = hex::decode(TEST_PRIVATE_KEY).unwrap();
        EvmSigner::new(&priv_key, TEST_CHAIN_ID).expect("Create signer")
    }

    #[test]
    fn test_address_derivation() {
        let signer = create_test_signer();
        let expected: Address = TEST_ADDRESS.parse().unwrap();
        assert_eq!(signer.address(), expected);
    }

    #[test]
    fn test_sign_message_sync() {
        let signer = create_test_signer();
        let message = b"Hello, Ethereum!";

        let signature = signer.sign_message_sync(message).expect("Sign message");

        // Verify signature
        assert!(signer.verify_message(message, &signature));
    }

    #[test]
    fn test_sign_hash_sync() {
        let signer = create_test_signer();
        let hash = B256::repeat_byte(0x42);

        let signature = signer.sign_hash_sync(&hash).expect("Sign hash");

        // Verify signature
        assert!(signer.verify_hash(&hash, &signature));
    }

    #[tokio::test]
    async fn test_sign_transaction() {
        let signer = create_test_signer();

        let tx = TransactionRequest::default()
            .with_to(
                "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
                    .parse()
                    .unwrap(),
            )
            .with_value(U256::from(1_000_000_000_000_000_000u128)) // 1 ETH
            .with_nonce(0)
            .with_chain_id(TEST_CHAIN_ID)
            .with_gas_limit(21000)
            .with_gas_price(1_000_000_000);

        let raw_tx = signer.sign_transaction(tx).await.expect("Sign tx");
        let hex_tx = hex::encode(&raw_tx);

        println!("Signed TX: 0x{}", hex_tx);

        // Legacy TX starts with 0xf8, EIP-1559 starts with 0x02
        assert!(hex_tx.starts_with("f8") || hex_tx.starts_with("02"));
    }

    #[tokio::test]
    async fn test_sign_message_async() {
        let signer = create_test_signer();
        let message = b"Test async signing";

        let signature = signer.sign_message(message).await.expect("Sign");
        assert!(signer.verify_message(message, &signature));
    }

    #[test]
    fn test_invalid_private_key() {
        let invalid_key = [0u8; 31]; // 31 bytes instead of 32
        let result = EvmSigner::new(&invalid_key, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_does_not_leak_key() {
        let signer = create_test_signer();
        let debug_output = format!("{:?}", signer);

        // Đảm bảo private key KHÔNG xuất hiện trong debug output
        assert!(!debug_output.contains(TEST_PRIVATE_KEY));
        assert!(debug_output.contains("EvmSigner"));
        // Address xuất hiện trong debug (có thể lowercase hoặc checksummed)
        assert!(debug_output
            .to_lowercase()
            .contains(&TEST_ADDRESS.to_lowercase()));
    }
}
