// wallet-core/src/crypto/key_deriver/mod.rs
//
// Key Derivation Engine - Multi-Curve Support
//
// Kiến trúc:
// ┌─────────────────────────────────────────────────┐
// │  Seed (64 bytes from BIP-39 Mnemonic)           │
// │                    │                            │
// │     ┌──────────────┴──────────────┐             │
// │     ▼                             ▼             │
// │  secp256k1 (BIP-32)        ed25519 (SLIP-0010)  │
// │  ├─ EVM (ETH, BSC...)     ├─ Solana             │
// │  ├─ Bitcoin               ├─ Aptos              │
// │  ├─ Tron                  ├─ Sui                │
// │  ├─ Cosmos                ├─ Near               │
// │  └─ Litecoin...           ├─ TON                │
// │                           └─ Polkadot           │
// └─────────────────────────────────────────────────┘

pub mod ed25519;
pub mod secp256k1;

// Re-exports
pub use ed25519::Ed25519Deriver;
pub use secp256k1::Secp256k1Deriver;

use crate::error::{CryptoError, WalletError, WalletResult};
use zeroize::Zeroizing;

// =============================================================================
// COMMON TYPES
// =============================================================================
/// Curve type cho key derivation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveType {
    /// secp256k1 — Bitcoin, Ethereum, Tron, Cosmos, ...
    Secp256k1,
    /// Ed25519 — Solana, Aptos, Sui, Near, TON, Polkadot, ...
    Ed25519,
}

/// Kết quả derivation chứa private key + metadata
#[derive(Debug)]
pub struct DerivedKey {
    /// Private key bytes (32 bytes, auto-zeroize khi drop)
    pub private_key: Zeroizing<[u8; 32]>,
    /// Curve type
    pub curve: CurveType,
    /// Derivation path đã sử dụng
    pub path: String,
}

// =============================================================================
// UNIFIED DERIVER
// =============================================================================
/// Unified Key Deriver - Entry point cho mọi loại key derivation
///
/// Tự động chọn curve dựa trên coin_type trong path,
/// hoặc gọi trực tiếp `Secp256k1Deriver` / `Ed25519Deriver`.
pub struct KeyDeriver;

impl KeyDeriver {
    /// Derive key tự động dựa trên curve type
    ///
    /// # Arguments
    /// * `seed` - BIP-39 seed (64 bytes)
    /// * `path` - Derivation path (e.g., "m/44'/60'/0'/0/0")
    /// * `curve` - Curve type (secp256k1 hoặc ed25519)
    pub fn derive(seed: &[u8], path: &str, curve: CurveType) -> WalletResult<DerivedKey> {
        Self::validate_seed(seed)?;

        let private_key = match curve {
            CurveType::Secp256k1 => Secp256k1Deriver::derive(seed, path)?,
            CurveType::Ed25519 => Ed25519Deriver::derive(seed, path)?,
        };

        Ok(DerivedKey {
            private_key,
            curve,
            path: path.to_string(),
        })
    }

    /// Derive nhiều keys cùng curve (batch, tối ưu performance)
    ///
    /// # Arguments
    /// * `seed` - BIP-39 seed (64 bytes)
    /// * `base_path` - Base path (e.g., "m/44'/60'/0'/0")
    /// * `indices` - Range of indices (e.g., 0..10)
    /// * `curve` - Curve type
    pub fn derive_batch(
        seed: &[u8],
        base_path: &str,
        indices: std::ops::Range<u32>,
        curve: CurveType,
    ) -> WalletResult<Vec<DerivedKey>> {
        Self::validate_seed(seed)?;

        match curve {
            CurveType::Secp256k1 => {
                let keys = Secp256k1Deriver::derive_batch(seed, base_path, indices.clone())?;
                Ok(keys
                    .into_iter()
                    .enumerate()
                    .map(|(i, pk)| DerivedKey {
                        private_key: pk,
                        curve: CurveType::Secp256k1,
                        path: format!("{}/{}", base_path, indices.start + i as u32),
                    })
                    .collect())
            }
            CurveType::Ed25519 => {
                // Ed25519 batch: derive each independently (all hardened)
                let mut keys = Vec::with_capacity(indices.len());
                for idx in indices {
                    let path = format!("{}'/{}'/0'", base_path, idx);
                    let pk = Ed25519Deriver::derive(seed, &path)?;
                    keys.push(DerivedKey {
                        private_key: pk,
                        curve: CurveType::Ed25519,
                        path,
                    });
                }
                Ok(keys)
            }
        }
    }

    /// Validate seed length
    #[inline]
    fn validate_seed(seed: &[u8]) -> WalletResult<()> {
        if seed.len() != 64 {
            return Err(WalletError::Crypto(CryptoError::DerivationFailed(format!(
                "Invalid seed length: expected 64 bytes, got {}",
                seed.len()
            ))));
        }
        Ok(())
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
    fn test_unified_secp256k1() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let result = KeyDeriver::derive(&seed, DerivationPaths::EVM_0, CurveType::Secp256k1);
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.curve, CurveType::Secp256k1);
        assert_eq!(key.private_key.len(), 32);
        println!("ETH key: 0x{}", hex::encode(&*key.private_key));
    }

    #[test]
    fn test_unified_ed25519() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let result = KeyDeriver::derive(&seed, DerivationPaths::SOLANA_0, CurveType::Ed25519);
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.curve, CurveType::Ed25519);
        assert_eq!(key.private_key.len(), 32);
        println!("SOL key: 0x{}", hex::encode(&*key.private_key));
    }

    #[test]
    fn test_invalid_seed() {
        let bad_seed = [0u8; 32];
        let result = KeyDeriver::derive(&bad_seed, "m/44'/60'/0'/0/0", CurveType::Secp256k1);
        assert!(result.is_err());
    }

    #[test]
    fn test_consistency() {
        let seed = hex::decode(TEST_SEED).unwrap();

        let k1 = KeyDeriver::derive(&seed, DerivationPaths::EVM_0, CurveType::Secp256k1).unwrap();
        let k2 = KeyDeriver::derive(&seed, DerivationPaths::EVM_0, CurveType::Secp256k1).unwrap();
        assert_eq!(&*k1.private_key, &*k2.private_key);

        let k3 = KeyDeriver::derive(&seed, DerivationPaths::SOLANA_0, CurveType::Ed25519).unwrap();
        let k4 = KeyDeriver::derive(&seed, DerivationPaths::SOLANA_0, CurveType::Ed25519).unwrap();
        assert_eq!(&*k3.private_key, &*k4.private_key);
    }

    #[test]
    fn test_different_curves_produce_different_keys() {
        let seed = hex::decode(TEST_SEED).unwrap();
        // Same coin type but different curves must give different keys
        let secp = KeyDeriver::derive(&seed, "m/44'/60'/0'/0/0", CurveType::Secp256k1).unwrap();
        let ed = KeyDeriver::derive(&seed, "m/44'/60'/0'/0'", CurveType::Ed25519).unwrap();
        // They MUST be different because derivation algorithms are fundamentally different
        assert_ne!(&*secp.private_key, &*ed.private_key);
    }
}
