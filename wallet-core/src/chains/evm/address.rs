// wallet-core/src/chains/evm/address.rs
//
// EVM Address Module - Professional Grade Address Derivation
// EIP-55 (Checksum), Keccak-256, secp256k1

use crate::error::{CryptoError, WalletError, WalletResult};
use alloy::primitives::Address;
use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use tiny_keccak::{Hasher, Keccak};
use zeroize::{Zeroize, Zeroizing};

/// EVM Address Generator
///
/// # Flow:  Private Key (32B) → Public Key (64B) → Keccak256 → Address (20B)
///
/// # Security
/// - Zeroize: Mọi intermediate data (hash, public key bytes) đều bị xóa sau khi dùng
/// - No Storage: Module này KHÔNG lưu private key
/// - Stack First: Sensitive data ưu tiên stack allocation
pub struct EvmAddress;

impl EvmAddress {
    // =========================================================================
    // CORE: Private Key → Address Bytes (20 bytes)
    // Đây là hàm nền tảng, tất cả hàm khác compose từ đây.
    // =========================================================================

    // =========================================================================
    // PRIMARY API — Zeroizing (recommended)
    // =========================================================================

    /// Derive 20 bytes address from a **zeroizing private key**.
    ///
    /// This is the **recommended** API — it takes ownership of the key
    /// material wrapped in [`Zeroizing`], guaranteeing the caller's
    /// buffer is zeroed when this function returns.
    ///
    /// # Algorithm (chuẩn Ethereum Yellow Paper)
    /// 1. `priv_key` (32B) → secp256k1 → `pub_key` (uncompressed, 65B)
    /// 2. Bỏ prefix byte 0x04 → `pub_key_raw` (64B)
    /// 3. Keccak-256(`pub_key_raw`) → `hash` (32B)
    /// 4. `hash[12..32]` → `address` (20B)
    pub fn derive_bytes(priv_key: Zeroizing<Vec<u8>>) -> WalletResult<[u8; 20]> {
        Self::derive_bytes_from_slice(&priv_key)
        // `priv_key` dropped & zeroed here
    }

    /// Derive EIP-55 checksummed address string from a **zeroizing private key**.
    ///
    /// # Returns
    /// `"0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"` (mixed-case checksum)
    #[inline]
    pub fn derive(priv_key: Zeroizing<Vec<u8>>) -> WalletResult<String> {
        Self::derive_from_slice(&priv_key)
        // `priv_key` dropped & zeroed here
    }

    // =========================================================================
    // SECONDARY API — Borrowed slice (caller manages zeroing)
    // =========================================================================

    /// Derive 20 bytes address from a **borrowed byte slice**.
    ///
    /// # ⚠ Security Note
    /// The caller is responsible for zeroing `priv_key` after this call.
    /// Prefer [`derive_bytes()`](Self::derive_bytes) with `Zeroizing<Vec<u8>>`.
    pub fn derive_bytes_from_slice(priv_key: &[u8]) -> WalletResult<[u8; 20]> {
        // Parse & validate private key
        let secret_key = SecretKey::from_slice(priv_key).map_err(|e| {
            WalletError::Crypto(CryptoError::InvalidKeyFormat(format!(
                "Invalid secp256k1 private key: {}",
                e
            )))
        })?;

        // Derive public key (uncompressed), wrap trong Zeroizing
        let public_key = secret_key.public_key();
        let encoded = Zeroizing::new(public_key.to_encoded_point(false));
        let pub_key_raw = &encoded.as_bytes()[1..]; // Bỏ 0x04 prefix

        // Keccak-256 hash (stack allocated)
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(pub_key_raw);
        hasher.finalize(&mut hash);

        // Extract 20 bytes cuối
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);

        // Zeroize hash (chứa thông tin liên quan tới public key)
        hash.zeroize();

        Ok(address)
    }

    /// Derive EIP-55 checksummed address from a **borrowed byte slice**.
    ///
    /// # ⚠ Security Note
    /// The caller is responsible for zeroing `priv_key` after this call.
    /// Prefer [`derive()`](Self::derive) with `Zeroizing<Vec<u8>>`.
    #[inline]
    pub fn derive_from_slice(priv_key: &[u8]) -> WalletResult<String> {
        let bytes = Self::derive_bytes_from_slice(priv_key)?;
        Ok(Address::from_slice(&bytes).to_checksum(None))
    }

    // =========================================================================
    // UTILITIES
    // =========================================================================

    /// Validate chuỗi có phải Ethereum address hợp lệ không
    ///
    /// Kiểm tra: `0x` prefix + 40 hex chars + EIP-55 checksum (nếu mixed case)
    #[inline]
    pub fn is_valid(address: &str) -> bool {
        address.parse::<Address>().is_ok()
    }

    /// Normalize về EIP-55 checksum format
    ///
    /// `"0xabcd..."` → `"0xAbCd..."` (mixed-case theo checksum)
    pub fn to_checksum(address: &str) -> WalletResult<String> {
        let addr: Address = address.parse().map_err(|_| {
            WalletError::Crypto(CryptoError::InvalidKeyFormat(
                "Invalid Ethereum address format".to_string(),
            ))
        })?;
        Ok(addr.to_checksum(None))
    }

    /// So sánh 2 address (case-insensitive, zero-allocation)
    ///
    /// Dùng byte comparison qua `alloy::Address` thay vì `.to_lowercase()` heap allocation.
    #[inline]
    pub fn equals(addr1: &str, addr2: &str) -> bool {
        match (addr1.parse::<Address>(), addr2.parse::<Address>()) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from well-known sources
    const TEST_PRIVATE_KEY: &str =
        "501c797c4b1fdfa88fb7efdf7c9871b8e0f46dbc44259e3e270e0d4c938165f5";
    const TEST_ADDRESS: &str = "0xb611C31e4284BF7A7daD3296e62880F14b3b15DD";

    // Anvil/Hardhat account #0
    const ANVIL_PRIVATE_KEY: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const ANVIL_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    // ── Primary API (Zeroizing) Tests ──────────────────────────────────

    #[test]
    fn test_derive() {
        let priv_key = Zeroizing::new(hex::decode(TEST_PRIVATE_KEY).unwrap());
        let address = EvmAddress::derive(priv_key).unwrap();
        println!("Address: {}", address);
        assert_eq!(address, TEST_ADDRESS);
    }

    #[test]
    fn test_derive_anvil() {
        let priv_key = Zeroizing::new(hex::decode(ANVIL_PRIVATE_KEY).unwrap());
        let address = EvmAddress::derive(priv_key).unwrap();
        println!("Address: {}", address);
        assert_eq!(address, ANVIL_ADDRESS);
    }

    #[test]
    fn test_derive_bytes() {
        let priv_key = Zeroizing::new(hex::decode(TEST_PRIVATE_KEY).unwrap());
        let address_bytes = EvmAddress::derive_bytes(priv_key).unwrap();
        let address_hex = format!("0x{}", hex::encode(address_bytes));
        assert!(EvmAddress::equals(&address_hex, TEST_ADDRESS));
    }

    #[test]
    fn test_derive_consistency() {
        // derive() và derive_from_slice() phải cho kết quả giống nhau
        let raw = hex::decode(TEST_PRIVATE_KEY).unwrap();
        let string_addr = EvmAddress::derive_from_slice(&raw).unwrap();
        let bytes_addr = EvmAddress::derive_bytes_from_slice(&raw).unwrap();
        let reconstructed = Address::from_slice(&bytes_addr).to_checksum(None);
        assert_eq!(string_addr, reconstructed);
    }

    // ── Secondary API (from_slice) Tests ──────────────────────────────

    #[test]
    fn test_derive_from_slice() {
        let priv_key = hex::decode(TEST_PRIVATE_KEY).unwrap();
        let address = EvmAddress::derive_from_slice(&priv_key).unwrap();
        assert_eq!(address, TEST_ADDRESS);
    }

    #[test]
    fn test_derive_bytes_from_slice() {
        let priv_key = hex::decode(TEST_PRIVATE_KEY).unwrap();
        let address_bytes = EvmAddress::derive_bytes_from_slice(&priv_key).unwrap();
        let address_hex = format!("0x{}", hex::encode(address_bytes));
        assert!(EvmAddress::equals(&address_hex, TEST_ADDRESS));
    }

    // ── Utility Tests ────────────────────────────────────────────────

    #[test]
    fn test_is_valid() {
        assert!(EvmAddress::is_valid(TEST_ADDRESS));
        assert!(EvmAddress::is_valid(ANVIL_ADDRESS));
        assert!(EvmAddress::is_valid(
            "0xdead000000000000000000000000000000000000"
        ));

        // Invalid cases
        assert!(!EvmAddress::is_valid("0xinvalid"));
        assert!(!EvmAddress::is_valid("not an address"));
        assert!(!EvmAddress::is_valid("0x123")); // Too short
        assert!(!EvmAddress::is_valid("")); // Empty
    }

    #[test]
    fn test_to_checksum() {
        let lowercase = "0xb611c31e4284bf7a7dad3296e62880f14b3b15dd";
        let checksummed = EvmAddress::to_checksum(lowercase).unwrap();
        assert_eq!(checksummed, TEST_ADDRESS);
    }

    #[test]
    fn test_equals() {
        let upper = "0xABCD1234ABCD1234ABCD1234ABCD1234ABCD1234";
        let lower = "0xabcd1234abcd1234abcd1234abcd1234abcd1234";
        assert!(EvmAddress::equals(upper, lower));
        assert!(!EvmAddress::equals(upper, TEST_ADDRESS));
    }

    // ── Error Handling Tests ─────────────────────────────────────────

    #[test]
    fn test_invalid_private_key() {
        assert!(EvmAddress::derive(Zeroizing::new(vec![0u8; 31])).is_err());
        assert!(EvmAddress::derive(Zeroizing::new(vec![0u8; 33])).is_err());
        assert!(EvmAddress::derive(Zeroizing::new(vec![])).is_err());
    }

    #[test]
    fn test_zero_private_key_rejected() {
        let zero_key = Zeroizing::new(vec![0u8; 32]);
        assert!(EvmAddress::derive(zero_key).is_err());
    }
}
