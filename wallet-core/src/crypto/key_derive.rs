// wallet-core\src\crypto\key_derive.rs
//
// Key Derivation Module - Professional Grade BIP-32/BIP-44 Implementation
// BIP-32 (HD Wallets), BIP-44 (Multi-Account), SLIP-44 (Coin Types)

use crate::error::{CryptoError, WalletError, WalletResult};
use bip32::{ChildNumber, DerivationPath, XPrv};
use std::str::FromStr;
use zeroize::Zeroizing;

/// SLIP-44 standard
pub mod coin_type {
    pub const BITCOIN: u32 = 0;
    pub const ETHEREUM: u32 = 60;
    pub const BINANCE_SMART_CHAIN: u32 = 60; // EVM compatible
    pub const POLYGON: u32 = 60;
    pub const AVALANCHE: u32 = 60;
    pub const ARBITRUM: u32 = 60;
    pub const OPTIMISM: u32 = 60;
    pub const SOLANA: u32 = 501;
    pub const COSMOS: u32 = 118;
    pub const TRON: u32 = 195;
}

/// Key Derivation Engine - High-performance & Secure
///
/// # Security Architecture
/// - Zeroizing Return: Private key được wrap trong `Zeroizing` để tự động xóa khi drop
/// - Stack Allocation: Sử dụng `[u8; 32]` thay vì `Vec<u8>` để tránh heap allocation
/// - No Intermediate Storage: Không lưu trữ master key hoặc intermediate keys
///
/// # Performance
/// - Iterative Derivation: Derivation từng level, tránh recursion overhead
/// - Pre-validated Paths: Cache DerivationPath sau khi parse
pub struct KeyDeriver;

/// Pre-built derivation paths cho các chains phổ biến
pub struct DerivationPaths;

impl DerivationPaths {
    /// Ethereum/EVM: m/44'/60'/0'/0/0
    pub const ETHEREUM_FIRST: &'static str = "m/44'/60'/0'/0/0";

    /// Bitcoin (Native SegWit): m/84'/0'/0'/0/0
    pub const BITCOIN_NATIVE_SEGWIT: &'static str = "m/84'/0'/0'/0/0";

    /// Bitcoin (Legacy): m/44'/0'/0'/0/0
    pub const BITCOIN_LEGACY: &'static str = "m/44'/0'/0'/0/0";

    /// Solana: m/44'/501'/0'/0'
    pub const SOLANA_FIRST: &'static str = "m/44'/501'/0'/0'";

    /// Tạo path cho EVM account theo index
    ///
    /// # Example
    /// ```ignore
    /// let path = DerivationPaths::ethereum(0); // m/44'/60'/0'/0/0
    /// let path = DerivationPaths::ethereum(1); // m/44'/60'/0'/0/1
    /// ```
    #[inline]
    pub fn ethereum(index: u32) -> String {
        format!("m/44'/60'/0'/0/{}", index)
    }

    /// Tạo path cho Bitcoin Native SegWit theo index
    #[inline]
    pub fn bitcoin_native_segwit(index: u32) -> String {
        format!("m/84'/0'/0'/0/{}", index)
    }

    /// Tạo path tùy chỉnh theo BIP-44 standard
    ///
    /// # Arguments
    /// * `coin_type` - SLIP-44 coin type (use `coin_type::*` constants)
    /// * `account` - Account index (thường là 0)
    /// * `change` - 0 = external, 1 = internal (change addresses)
    /// * `index` - Address index
    #[inline]
    pub fn bip44(coin_type: u32, account: u32, change: u32, index: u32) -> String {
        format!("m/44'/{}'/{}'/{}/<{}", coin_type, account, change, index)
    }
}

impl KeyDeriver {
    // =========================================================================
    // CORE DERIVATION
    // =========================================================================

    /// Derive Private Key từ Seed theo chuẩn BIP-32/BIP-44
    ///
    /// # Arguments
    /// * `seed` - BIP-39 seed (64 bytes từ mnemonic.to_seed())
    /// * `path` - Derivation path (e.g., "m/44'/60'/0'/0/0")
    ///
    /// # Returns
    /// - `Ok(Zeroizing<[u8; 32]>)`: Private key 32 bytes, tự động zeroize khi drop
    /// - `Err`: Nếu seed không hợp lệ hoặc path sai format
    ///
    /// # Security
    /// Return value được wrap trong `Zeroizing` để đảm bảo private key
    /// được ghi đè bằng 0 khi biến ra khỏi scope.
    pub fn derive_secp256k1_private_key(
        seed: &[u8],
        path: &str,
    ) -> WalletResult<Zeroizing<[u8; 32]>> {
        // Validate seed length
        if seed.len() != 64 {
            return Err(WalletError::Crypto(CryptoError::DerivationFailed(format!(
                "Invalid seed length: expected 64 bytes, got {}",
                seed.len()
            ))));
        }

        // Create master key from seed
        let root_xprv = XPrv::new(seed)
            .map_err(|e| WalletError::Crypto(CryptoError::DerivationFailed(e.to_string())))?;

        // Parse derivation path
        let derivation_path = DerivationPath::from_str(path).map_err(|e| {
            WalletError::Crypto(CryptoError::DerivationFailed(format!(
                "Invalid derivation path '{}': {}",
                path, e
            )))
        })?;

        // Iterative child derivation (no recursion overhead)
        let mut child_xprv = root_xprv;
        for child_num in derivation_path {
            child_xprv = child_xprv.derive_child(child_num).map_err(|e| {
                WalletError::Crypto(CryptoError::DerivationFailed(format!(
                    "Failed to derive child key: {}",
                    e
                )))
            })?;
        }

        // Extract private key bytes (stack allocated)
        let priv_key_bytes: [u8; 32] = child_xprv.private_key().to_bytes().into();

        Ok(Zeroizing::new(priv_key_bytes))
    }

    /// Derive nhiều private keys từ một seed (batch derivation)
    ///
    /// # Performance
    /// Hiệu quả hơn việc gọi `derive_secp256k1_private_key` nhiều lần
    /// vì master key chỉ được tạo một lần.
    ///
    /// # Example
    /// ```ignore
    /// let keys = KeyDeriver::derive_multiple(&seed, "m/44'/60'/0'/0", 0..10)?;
    /// ```
    pub fn derive_multiple(
        seed: &[u8],
        base_path: &str, // e.g., "m/44'/60'/0'/0"
        indices: std::ops::Range<u32>,
    ) -> WalletResult<Vec<Zeroizing<[u8; 32]>>> {
        if seed.len() != 64 {
            return Err(WalletError::Crypto(CryptoError::DerivationFailed(format!(
                "Invalid seed length: expected 64 bytes, got {}",
                seed.len()
            ))));
        }

        let root_xprv = XPrv::new(seed)
            .map_err(|e| WalletError::Crypto(CryptoError::DerivationFailed(e.to_string())))?;

        // Derive to base path first
        let base_derivation = DerivationPath::from_str(base_path).map_err(|e| {
            WalletError::Crypto(CryptoError::DerivationFailed(format!(
                "Invalid base path '{}': {}",
                base_path, e
            )))
        })?;

        let mut base_xprv = root_xprv;
        for child_num in base_derivation {
            base_xprv = base_xprv
                .derive_child(child_num)
                .map_err(|e| WalletError::Crypto(CryptoError::DerivationFailed(e.to_string())))?;
        }

        // Derive each index from base
        let mut keys = Vec::with_capacity(indices.len());
        for index in indices {
            let child_num = ChildNumber::new(index, false).map_err(|e| {
                WalletError::Crypto(CryptoError::DerivationFailed(format!(
                    "Invalid index {}: {}",
                    index, e
                )))
            })?;

            let child_xprv = base_xprv
                .derive_child(child_num)
                .map_err(|e| WalletError::Crypto(CryptoError::DerivationFailed(e.to_string())))?;

            let priv_key_bytes: [u8; 32] = child_xprv.private_key().to_bytes().into();
            keys.push(Zeroizing::new(priv_key_bytes));
        }

        Ok(keys)
    }

    /// Validate derivation path format
    #[inline]
    pub fn is_valid_path(path: &str) -> bool {
        DerivationPath::from_str(path).is_ok()
    }
}

// =============================================================================
// UNIT TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Test seed (from mnemonic: "abandon abandon ... about")
    const TEST_SEED: &str = "16270f7b026afe7a3746efbfcf43e083500951db9e2699d1e4f372515dabcc80459b9181c3937b5faa4b8f7602f886553d2c32c5f12f3331cef40153aead4de6";

    #[test]
    fn test_derive_ethereum_key() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let path = DerivationPaths::ETHEREUM_FIRST;

        let priv_key = KeyDeriver::derive_secp256k1_private_key(&seed, path).unwrap();

        assert_eq!(priv_key.len(), 32);
        println!("Derived ETH Key: 0x{}", hex::encode(&*priv_key));
    }

    #[test]
    fn test_derive_multiple_ethereum_keys() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let base_path = "m/44'/60'/0'/0";

        let keys = KeyDeriver::derive_multiple(&seed, base_path, 0..5).unwrap();

        assert_eq!(keys.len(), 5);

        // Kiểm tra mỗi key khác nhau
        for (i, key) in keys.iter().enumerate() {
            println!("ETH Key #{}: 0x{}", i, hex::encode(&**key));
        }

        // Keys phải khác nhau
        assert_ne!(&*keys[0], &*keys[1]);
        assert_ne!(&*keys[1], &*keys[2]);
    }

    #[test]
    fn test_derivation_paths() {
        assert_eq!(DerivationPaths::ethereum(0), "m/44'/60'/0'/0/0");
        assert_eq!(DerivationPaths::ethereum(5), "m/44'/60'/0'/0/5");
        assert_eq!(DerivationPaths::bitcoin_native_segwit(0), "m/84'/0'/0'/0/0");
    }

    #[test]
    fn test_is_valid_path() {
        assert!(KeyDeriver::is_valid_path("m/44'/60'/0'/0/0"));
        assert!(KeyDeriver::is_valid_path("m/84'/0'/0'/0/0"));
        assert!(!KeyDeriver::is_valid_path("invalid path"));
        assert!(!KeyDeriver::is_valid_path("m/44'/60'/0'/0/abc")); // Non-numeric
    }

    #[test]
    fn test_invalid_seed_length() {
        let short_seed = [0u8; 32]; // Should be 64
        let result = KeyDeriver::derive_secp256k1_private_key(&short_seed, "m/44'/60'/0'/0/0");
        assert!(result.is_err());
    }

    #[test]
    fn test_consistency() {
        // Derive cùng path từ cùng seed phải cho cùng kết quả
        let seed = hex::decode(TEST_SEED).unwrap();
        let path = "m/44'/60'/0'/0/0";

        let key1 = KeyDeriver::derive_secp256k1_private_key(&seed, path).unwrap();
        let key2 = KeyDeriver::derive_secp256k1_private_key(&seed, path).unwrap();

        assert_eq!(&*key1, &*key2);
    }
}
