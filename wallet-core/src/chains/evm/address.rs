// wallet-core\src\chains\evm\address.rs
//
// EVM Address Module - Professional Grade Address Generation
// Chuẩn: EIP-55 (Checksum), Keccak-256 Hashing

use crate::error::{CryptoError, WalletError, WalletResult};
use alloy::primitives::Address;
use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use tiny_keccak::{Hasher, Keccak};
use zeroize::Zeroizing;

/// EVM Address Generator - High-performance & Secure
///
/// # Security Architecture
/// - **Zeroizing**: Tất cả dữ liệu nhạy cảm (public key bytes) được xóa sau khi sử dụng
/// - **No Key Storage**: Module này KHÔNG lưu trữ private key
/// - **Stack Allocation**: Hash output sử dụng stack (32 bytes fixed array)
///
/// # Performance
/// - **Minimal Allocations**: Chỉ allocate khi thực sự cần thiết
/// - **Inline Hashing**: Keccak-256 trực tiếp, không qua wrapper
pub struct EvmAddress;

impl EvmAddress {
    /// Tạo địa chỉ Ethereum từ Private Key
    ///
    /// # Algorithm
    /// 1. Private Key → Public Key (secp256k1)
    /// 2. Public Key (uncompressed, 65 bytes) → lấy 64 bytes (bỏ prefix 0x04)
    /// 3. Keccak-256(64 bytes) → 32 bytes hash
    /// 4. Lấy 20 bytes cuối → Address
    /// 5. EIP-55 Checksum encoding
    ///
    /// # Returns
    /// - `Ok(String)`: EIP-55 checksummed address (e.g., "0xAb5801a7...")
    /// - `Err`: Nếu private key không hợp lệ
    pub fn from_private_key(priv_key: &[u8]) -> WalletResult<String> {
        // Validate và parse private key
        let secret_key = SecretKey::from_slice(priv_key).map_err(|e| {
            WalletError::Crypto(CryptoError::InvalidKeyFormat(format!(
                "Invalid private key (must be 32 bytes): {}",
                e
            )))
        })?;

        // Derive public key và wrap trong Zeroizing để xóa sau khi dùng
        let public_key = secret_key.public_key();
        let public_key_encoded = Zeroizing::new(public_key.to_encoded_point(false));

        // Lấy 64 bytes raw (bỏ prefix byte 0x04)
        let public_key_raw = &public_key_encoded.as_bytes()[1..];

        // Hash bằng Keccak-256 (sử dụng stack allocation)
        let mut hasher = Keccak::v256();
        let mut hash_output = [0u8; 32];
        hasher.update(public_key_raw);
        hasher.finalize(&mut hash_output);

        // Lấy 20 bytes cuối làm address
        let address_bytes = &hash_output[12..];

        // Convert sang Alloy Address và format EIP-55 checksum
        let addr = Address::from_slice(address_bytes);

        Ok(addr.to_checksum(None))
    }

    /// Tạo địa chỉ Ethereum và trả về raw bytes (20 bytes)
    ///
    /// Dùng khi cần Address dạng bytes thay vì string
    #[inline]
    pub fn from_private_key_bytes(priv_key: &[u8]) -> WalletResult<[u8; 20]> {
        let secret_key = SecretKey::from_slice(priv_key).map_err(|e| {
            WalletError::Crypto(CryptoError::InvalidKeyFormat(format!(
                "Invalid private key: {}",
                e
            )))
        })?;

        let public_key = secret_key.public_key();
        let public_key_encoded = Zeroizing::new(public_key.to_encoded_point(false));
        let public_key_raw = &public_key_encoded.as_bytes()[1..];

        let mut hasher = Keccak::v256();
        let mut hash_output = [0u8; 32];
        hasher.update(public_key_raw);
        hasher.finalize(&mut hash_output);

        let mut address = [0u8; 20];
        address.copy_from_slice(&hash_output[12..]);
        Ok(address)
    }

    /// Validate xem một string có phải là địa chỉ Ethereum hợp lệ không
    ///
    /// Kiểm tra:
    /// - Format: 0x + 40 hex characters
    /// - EIP-55 checksum (nếu có mixed case)
    #[inline]
    pub fn is_valid(address: &str) -> bool {
        address.parse::<Address>().is_ok()
    }

    /// Normalize địa chỉ về format EIP-55 checksum
    ///
    /// Input có thể là lowercase, uppercase, hoặc mixed case
    pub fn to_checksum(address: &str) -> WalletResult<String> {
        let addr: Address = address.parse().map_err(|_| {
            WalletError::Crypto(CryptoError::InvalidKeyFormat(
                "Invalid Ethereum address format".to_string(),
            ))
        })?;
        Ok(addr.to_checksum(None))
    }

    /// So sánh hai địa chỉ (case-insensitive)
    #[inline]
    pub fn equals(addr1: &str, addr2: &str) -> bool {
        addr1.to_lowercase() == addr2.to_lowercase()
    }
}

// =============================================================================
// UNIT TESTS
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

    #[test]
    fn test_address_generation() {
        let priv_key = hex::decode(TEST_PRIVATE_KEY).unwrap();
        let address = EvmAddress::from_private_key(&priv_key).unwrap();
        assert_eq!(address, TEST_ADDRESS);
    }

    #[test]
    fn test_address_generation_anvil() {
        let priv_key = hex::decode(ANVIL_PRIVATE_KEY).unwrap();
        let address = EvmAddress::from_private_key(&priv_key).unwrap();
        assert_eq!(address, ANVIL_ADDRESS);
    }

    #[test]
    fn test_address_bytes() {
        let priv_key = hex::decode(TEST_PRIVATE_KEY).unwrap();
        let address_bytes = EvmAddress::from_private_key_bytes(&priv_key).unwrap();
        let address_hex = format!("0x{}", hex::encode(address_bytes));

        // So sánh case-insensitive
        assert!(EvmAddress::equals(&address_hex, TEST_ADDRESS));
    }

    #[test]
    fn test_is_valid() {
        assert!(EvmAddress::is_valid(TEST_ADDRESS));
        assert!(EvmAddress::is_valid(ANVIL_ADDRESS));

        // Invalid cases
        assert!(!EvmAddress::is_valid("0xinvalid"));
        assert!(!EvmAddress::is_valid("not an address"));
        assert!(!EvmAddress::is_valid("0x123")); // Too short
    }

    #[test]
    fn test_to_checksum() {
        let lowercase = "0xb611c31e4284bf7a7dad3296e62880f14b3b15dd";
        let checksummed = EvmAddress::to_checksum(lowercase).unwrap();
        assert_eq!(checksummed, TEST_ADDRESS);
    }

    #[test]
    fn test_equals() {
        let addr1 = "0xABCD1234abcd1234ABCD1234abcd1234ABCD1234";
        let addr2 = "0xabcd1234abcd1234abcd1234abcd1234abcd1234";
        assert!(EvmAddress::equals(addr1, addr2));
    }

    #[test]
    fn test_invalid_private_key() {
        let invalid_key = [0u8; 31]; // 31 bytes instead of 32
        let result = EvmAddress::from_private_key(&invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_private_key_rejected() {
        let zero_key = [0u8; 32];
        let result = EvmAddress::from_private_key(&zero_key);
        assert!(result.is_err()); // Zero is not a valid secp256k1 private key
    }
}
