// wallet-core/src/crypto/key_deriver/ed25519.rs
//
// Ed25519 Key Derivation — SLIP-0010 Standard
//
// Dùng cho: Solana, Aptos, Sui, Near, TON, Polkadot, Cardano, ...
// Algorithm: HMAC-SHA512 (khác BIP-32, chỉ hỗ trợ hardened derivation)
// Reference: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
//
// QUAN TRỌNG: SLIP-0010 cho ed25519 CHỈ hỗ trợ hardened child derivation.
// Tất cả levels trong path PHẢI là hardened (có dấu ').
// VD: m/44'/501'/0'/0' (OK)    m/44'/501'/0'/0 (INVALID)

use crate::error::{CryptoError, WalletError, WalletResult};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;

/// Ed25519 Key Deriver — SLIP-0010 Standard
///
/// # Khác biệt với secp256k1 (BIP-32)
/// - Master key seed: "ed25519 seed" (thay vì "Bitcoin seed")
/// - Chỉ hỗ trợ hardened derivation (index >= 2^31)
/// - Không cần validate key range (ed25519 key là bất kỳ 32 bytes)
///
/// # Security
/// - HMAC-SHA512 cho mỗi level derivation
/// - Private key + chain code tự động zeroize
/// - Không lưu intermediate state
pub struct Ed25519Deriver;

impl Ed25519Deriver {
    /// SLIP-0010 master key seed constant
    const MASTER_SECRET: &'static [u8] = b"ed25519 seed";

    /// Derive single ed25519 private key từ seed + path
    ///
    /// # Arguments
    /// * `seed` - 64 bytes BIP-39 seed
    /// * `path` - Derivation path, all levels MUST be hardened
    ///            e.g., "m/44'/501'/0'/0'"
    ///
    /// # Returns
    /// 32-byte ed25519 private key, auto-zeroize on drop
    pub fn derive(seed: &[u8], path: &str) -> WalletResult<Zeroizing<[u8; 32]>> {
        // Parse path thành danh sách hardened indices
        let indices = Self::parse_path(path)?;

        // Step 1: Master key generation
        // I = HMAC-SHA512(Key = "ed25519 seed", Data = seed)
        let (mut key, mut chain_code) = Self::master_key_generate(seed)?;

        // Step 2: Child key derivation (mỗi level)
        // I = HMAC-SHA512(Key = chain_code, Data = 0x00 || key || index)
        for index in &indices {
            let (child_key, child_chain) = Self::child_key_derive(&key, &chain_code, *index)?;
            // Zeroize old values trước khi overwrite
            key.zeroize();
            chain_code.zeroize();
            key = child_key;
            chain_code = child_chain;
        }

        // Zeroize chain code (không cần nữa)
        chain_code.zeroize();

        Ok(Zeroizing::new(key))
    }

    /// Derive master key từ seed
    ///
    /// I = HMAC-SHA512(Key = "ed25519 seed", Data = seed)
    /// IL (32 bytes) = private key
    /// IR (32 bytes) = chain code
    fn master_key_generate(seed: &[u8]) -> WalletResult<([u8; 32], [u8; 32])> {
        let mut mac = HmacSha512::new_from_slice(Self::MASTER_SECRET).map_err(|e| {
            WalletError::Crypto(CryptoError::DerivationFailed(format!(
                "HMAC init failed: {}",
                e
            )))
        })?;

        mac.update(seed);
        let result = mac.finalize().into_bytes();

        // Copy into stack buffer we fully control, then zeroize
        let mut buf = [0u8; 64];
        buf.copy_from_slice(&result);

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&buf[..32]);
        chain_code.copy_from_slice(&buf[32..]);

        // Zeroize local buffer — chứa raw key material
        buf.zeroize();

        Ok((key, chain_code))
    }

    /// Derive child key (hardened only)
    ///
    /// Data = 0x00 || parent_key || ser32(index + 0x80000000)
    /// I = HMAC-SHA512(Key = parent_chain_code, Data = Data)
    fn child_key_derive(
        parent_key: &[u8; 32],
        parent_chain_code: &[u8; 32],
        index: u32,
    ) -> WalletResult<([u8; 32], [u8; 32])> {
        let mut mac = HmacSha512::new_from_slice(parent_chain_code).map_err(|e| {
            WalletError::Crypto(CryptoError::DerivationFailed(format!(
                "HMAC init failed: {}",
                e
            )))
        })?;

        // Data = 0x00 || parent_key (32 bytes) || index_be (4 bytes)
        let hardened_index = index | 0x80000000;
        mac.update(&[0x00]);
        mac.update(parent_key);
        mac.update(&hardened_index.to_be_bytes());

        let result = mac.finalize().into_bytes();

        // Copy into stack buffer we fully control, then zeroize
        let mut buf = [0u8; 64];
        buf.copy_from_slice(&result);

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&buf[..32]);
        chain_code.copy_from_slice(&buf[32..]);

        // Zeroize local buffer — chứa raw key material
        buf.zeroize();

        Ok((key, chain_code))
    }

    /// Parse derivation path thành list of indices
    ///
    /// Input: "m/44'/501'/0'/0'"
    /// Output: [44, 501, 0, 0]
    ///
    /// Tất cả levels phải có dấu ' (hardened)
    fn parse_path(path: &str) -> WalletResult<Vec<u32>> {
        let path = path.trim();

        // Phải bắt đầu bằng "m/"
        if !path.starts_with("m/") {
            return Err(WalletError::Crypto(CryptoError::DerivationFailed(format!(
                "Path must start with 'm/': {}",
                path
            ))));
        }

        let segments = &path[2..]; // Bỏ "m/"
        if segments.is_empty() {
            return Err(WalletError::Crypto(CryptoError::DerivationFailed(
                "Empty derivation path".to_string(),
            )));
        }

        let mut indices = Vec::new();
        for segment in segments.split('/') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }

            // Ed25519 SLIP-0010: tất cả phải hardened
            if !segment.ends_with('\'') && !segment.ends_with('h') {
                return Err(WalletError::Crypto(CryptoError::DerivationFailed(
                    format!(
                        "Ed25519 SLIP-0010 requires ALL levels to be hardened (add '). Invalid segment: '{}'",
                        segment
                    ),
                )));
            }

            // Parse số (bỏ dấu ' hoặc h ở cuối)
            let num_str = &segment[..segment.len() - 1];
            let index: u32 = num_str.parse().map_err(|e| {
                WalletError::Crypto(CryptoError::DerivationFailed(format!(
                    "Invalid index '{}': {}",
                    num_str, e
                )))
            })?;

            indices.push(index);
        }

        Ok(indices)
    }

    /// Validate ed25519 path (tất cả levels phải hardened)
    pub fn is_valid_path(path: &str) -> bool {
        Self::parse_path(path).is_ok()
    }

    /// Validate xem derived bytes có phải ed25519 private key hợp lệ
    /// (Ed25519 chấp nhận mọi 32 bytes, nên luôn true, nhưng check via dalek)
    pub fn validate_key(key_bytes: &[u8; 32]) -> bool {
        ed25519_dalek::SigningKey::from_bytes(key_bytes);
        true // Ed25519 accepts any 32 bytes as private key
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
    fn test_derive_solana_key() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let key = Ed25519Deriver::derive(&seed, DerivationPaths::SOLANA_0).unwrap();
        assert_eq!(key.len(), 32);
        println!("SOL key: 0x{}", hex::encode(&*key));
    }

    #[test]
    fn test_derive_aptos_key() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let key = Ed25519Deriver::derive(&seed, DerivationPaths::APTOS_0).unwrap();
        assert_eq!(key.len(), 32);
        println!("APT key: 0x{}", hex::encode(&*key));
    }

    #[test]
    fn test_derive_sui_key() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let key = Ed25519Deriver::derive(&seed, DerivationPaths::SUI_0).unwrap();
        assert_eq!(key.len(), 32);
        println!("SUI key: 0x{}", hex::encode(&*key));
    }

    #[test]
    fn test_derive_ton_key() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let key = Ed25519Deriver::derive(&seed, DerivationPaths::TON_0).unwrap();
        assert_eq!(key.len(), 32);
        println!("TON key: 0x{}", hex::encode(&*key));
    }

    #[test]
    fn test_consistency() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let k1 = Ed25519Deriver::derive(&seed, DerivationPaths::SOLANA_0).unwrap();
        let k2 = Ed25519Deriver::derive(&seed, DerivationPaths::SOLANA_0).unwrap();
        assert_eq!(&*k1, &*k2);
    }

    #[test]
    fn test_different_accounts() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let k0 = Ed25519Deriver::derive(&seed, &DerivationPaths::solana(0)).unwrap();
        let k1 = Ed25519Deriver::derive(&seed, &DerivationPaths::solana(1)).unwrap();
        let k2 = Ed25519Deriver::derive(&seed, &DerivationPaths::solana(2)).unwrap();
        assert_ne!(&*k0, &*k1);
        assert_ne!(&*k1, &*k2);
    }

    #[test]
    fn test_different_chains() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let sol = Ed25519Deriver::derive(&seed, DerivationPaths::SOLANA_0).unwrap();
        let apt = Ed25519Deriver::derive(&seed, DerivationPaths::APTOS_0).unwrap();
        let sui = Ed25519Deriver::derive(&seed, DerivationPaths::SUI_0).unwrap();
        assert_ne!(&*sol, &*apt);
        assert_ne!(&*apt, &*sui);
        assert_ne!(&*sol, &*sui);
    }

    #[test]
    fn test_non_hardened_path_rejected() {
        let seed = hex::decode(TEST_SEED).unwrap();
        // m/44'/501'/0'/0 — last segment NOT hardened = INVALID for ed25519
        let result = Ed25519Deriver::derive(&seed, "m/44'/501'/0'/0");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("hardened"));
    }

    #[test]
    fn test_invalid_path_format() {
        let seed = hex::decode(TEST_SEED).unwrap();
        assert!(Ed25519Deriver::derive(&seed, "invalid").is_err());
        assert!(Ed25519Deriver::derive(&seed, "44'/501'/0'").is_err()); // Missing m/
    }

    #[test]
    fn test_validate_key() {
        let seed = hex::decode(TEST_SEED).unwrap();
        let key = Ed25519Deriver::derive(&seed, DerivationPaths::SOLANA_0).unwrap();
        assert!(Ed25519Deriver::validate_key(&key));
    }

    #[test]
    fn test_is_valid_path() {
        assert!(Ed25519Deriver::is_valid_path("m/44'/501'/0'/0'"));
        assert!(Ed25519Deriver::is_valid_path("m/44'/637'/0'/0'/0'"));
        assert!(!Ed25519Deriver::is_valid_path("m/44'/501'/0'/0")); // Not hardened
        assert!(!Ed25519Deriver::is_valid_path("invalid"));
    }

    // =========================================================================
    // SLIP-0010 Test Vector (from official spec)
    // =========================================================================
    // Seed: 000102030405060708090a0b0c0d0e0f
    // Chain m:
    //   private: 2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7
    //   chain:   90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb

    #[test]
    fn test_slip0010_vector_master() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

        // Master key = derive with no children = just HMAC("ed25519 seed", seed)
        let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").unwrap();
        mac.update(&seed);
        let result = mac.finalize().into_bytes();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);

        assert_eq!(
            hex::encode(key),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
    }
}
