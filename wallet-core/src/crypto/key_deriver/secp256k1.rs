// wallet-core/src/crypto/key_deriver/secp256k1.rs
//
// secp256k1 Key Derivation — BIP-32 / BIP-44
//
// Dùng cho: Bitcoin, Ethereum/EVM, Tron, Cosmos, Litecoin, Dogecoin, ...
// Algorithm: HMAC-SHA512 hierarchical deterministic derivation
// Reference: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

use crate::error::{CryptoError, WalletError, WalletResult};
use bip32::{ChildNumber, DerivationPath, XPrv};
use std::str::FromStr;
use zeroize::Zeroizing;

/// secp256k1 Key Deriver — BIP-32 Standard
///
/// # Security
/// - Private keys wrap trong `Zeroizing<[u8; 32]>` (auto-zeroize khi drop)
/// - Stack allocation cho key bytes
/// - Không lưu intermediate keys
///
/// # Performance
/// - Iterative derivation (không recursion)
/// - Batch derivation tối ưu: derive tới base path 1 lần, rồi fan-out
pub struct Secp256k1Deriver;

impl Secp256k1Deriver {
    /// Derive single private key từ seed + path
    ///
    /// # Arguments
    /// * `seed` - 64 bytes BIP-39 seed
    /// * `path` - Derivation path (e.g. "m/44'/60'/0'/0/0")
    ///
    /// # Returns
    /// 32-byte private key, auto-zeroize on drop
    pub fn derive(seed: &[u8], path: &str) -> WalletResult<Zeroizing<[u8; 32]>> {
        let root_xprv = XPrv::new(seed).map_err(|e| {
            WalletError::Crypto(CryptoError::DerivationFailed(format!(
                "Failed to create master key: {}",
                e
            )))
        })?;

        let derivation_path = DerivationPath::from_str(path).map_err(|e| {
            WalletError::Crypto(CryptoError::DerivationFailed(format!(
                "Invalid path '{}': {}",
                path, e
            )))
        })?;

        let mut child = root_xprv;
        for child_num in derivation_path {
            child = child.derive_child(child_num).map_err(|e| {
                WalletError::Crypto(CryptoError::DerivationFailed(format!(
                    "Child derivation failed: {}",
                    e
                )))
            })?;
        }

        let key_bytes: [u8; 32] = child.private_key().to_bytes().into();
        Ok(Zeroizing::new(key_bytes))
    }

    /// Batch derive: derive tới base_path 1 lần, rồi derive từng index
    ///
    /// Hiệu quả hơn N lần gọi `derive()` vì master → base chỉ tính 1 lần.
    ///
    /// # Arguments
    /// * `seed` - 64 bytes
    /// * `base_path` - Path tới trước index cuối (e.g. "m/44'/60'/0'/0")
    /// * `indices` - Range of address indices (e.g. 0..10)
    pub fn derive_batch(
        seed: &[u8],
        base_path: &str,
        indices: std::ops::Range<u32>,
    ) -> WalletResult<Vec<Zeroizing<[u8; 32]>>> {
        let root_xprv = XPrv::new(seed)
            .map_err(|e| WalletError::Crypto(CryptoError::DerivationFailed(e.to_string())))?;

        let base_derivation = DerivationPath::from_str(base_path).map_err(|e| {
            WalletError::Crypto(CryptoError::DerivationFailed(format!(
                "Invalid base path '{}': {}",
                base_path, e
            )))
        })?;

        // Derive tới base path 1 lần
        let mut base_xprv = root_xprv;
        for child_num in base_derivation {
            base_xprv = base_xprv
                .derive_child(child_num)
                .map_err(|e| WalletError::Crypto(CryptoError::DerivationFailed(e.to_string())))?;
        }

        // Fan-out từ base
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

            let key_bytes: [u8; 32] = child_xprv.private_key().to_bytes().into();
            keys.push(Zeroizing::new(key_bytes));
        }

        Ok(keys)
    }

    /// Validate path format
    #[inline]
    pub fn is_valid_path(path: &str) -> bool {
        DerivationPath::from_str(path).is_ok()
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::paths::DerivationPaths;

    const TEST_SEED: &str = "16270f7b026afe7a3746efbfcf43e083500951db9e2699d1e4f372515dabcc80459b9181c3937b5faa4b8f7602f886553d2c32c5f12f3331cef40153aead4de6";

    #[test]
    fn test_derive_evm_key() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let key = Secp256k1Deriver::derive(&seed, DerivationPaths::EVM_0).unwrap();
        assert_eq!(key.len(), 32);
        println!("ETH key: 0x{}", hex::encode(&*key));
    }

    #[test]
    fn test_derive_bitcoin_key() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let key = Secp256k1Deriver::derive(&seed, DerivationPaths::BTC_NATIVE_SEGWIT_0).unwrap();
        assert_eq!(key.len(), 32);
        println!("BTC key: 0x{}", hex::encode(&*key));
    }

    #[test]
    fn test_batch_derivation() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let keys = Secp256k1Deriver::derive_batch(&seed, "m/44'/60'/0'/0", 0..5).unwrap();

        assert_eq!(keys.len(), 5);
        // Tất cả phải khác nhau
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(&*keys[i], &*keys[j], "Key {} and {} should differ", i, j);
            }
        }
    }

    #[test]
    fn test_batch_matches_single() {
        let seed = hex::decode(TEST_SEED).unwrap();

        // Batch derive
        let batch = Secp256k1Deriver::derive_batch(&seed, "m/44'/60'/0'/0", 0..3).unwrap();

        // Single derive từng cái
        for (i, batch_key) in batch.iter().enumerate() {
            let single = Secp256k1Deriver::derive(&seed, &DerivationPaths::evm(i as u32)).unwrap();
            assert_eq!(&**batch_key, &*single, "Batch[{}] != Single[{}]", i, i);
        }
    }

    #[test]
    fn test_consistency() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let k1 = Secp256k1Deriver::derive(&seed, DerivationPaths::EVM_0).unwrap();
        let k2 = Secp256k1Deriver::derive(&seed, DerivationPaths::EVM_0).unwrap();
        assert_eq!(&*k1, &*k2);
    }

    #[test]
    fn test_different_paths_different_keys() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let eth = Secp256k1Deriver::derive(&seed, DerivationPaths::EVM_0).unwrap();
        let btc = Secp256k1Deriver::derive(&seed, DerivationPaths::BTC_NATIVE_SEGWIT_0).unwrap();
        assert_ne!(&*eth, &*btc);
    }

    #[test]
    fn test_is_valid_path() {
        assert!(Secp256k1Deriver::is_valid_path("m/44'/60'/0'/0/0"));
        assert!(Secp256k1Deriver::is_valid_path("m/84'/0'/0'/0/0"));
        assert!(!Secp256k1Deriver::is_valid_path("invalid"));
    }
}
