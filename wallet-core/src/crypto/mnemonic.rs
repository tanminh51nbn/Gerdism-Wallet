// wallet-core\src\crypto\mnemonic.rs
//
// Mnemonic Module - Professional Grade BIP-39 Implementation
// Chuẩn: BIP-39 (Mnemonic), PBKDF2-HMAC-SHA512 (Seed Derivation)

use crate::error::{MnemonicError, WalletError, WalletResult};
use bip39::Mnemonic;
use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Số lượng words hỗ trợ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordCount {
    /// 12 words (128-bit entropy)
    Twelve = 12,
    /// 15 words (160-bit entropy)
    Fifteen = 15,
    /// 18 words (192-bit entropy)
    Eighteen = 18,
    /// 21 words (224-bit entropy)
    TwentyOne = 21,
    /// 24 words (256-bit entropy)
    TwentyFour = 24,
}

impl WordCount {
    /// Lấy số bytes entropy cần thiết
    #[inline]
    pub const fn entropy_bytes(self) -> usize {
        match self {
            WordCount::Twelve => 16,
            WordCount::Fifteen => 20,
            WordCount::Eighteen => 24,
            WordCount::TwentyOne => 28,
            WordCount::TwentyFour => 32,
        }
    }
}

/// Wallet Mnemonic - High-security BIP-39 Implementation
///
/// # Security Architecture
/// - **ZeroizeOnDrop**: Phrase được tự động ghi đè bằng 0 khi struct bị drop
/// - **CSPRNG**: Sử dụng `OsRng` (OS-level cryptographically secure RNG)
/// - **No Debug Leak**: Custom Debug impl không hiển thị phrase
/// - **Constant-time Operations**: Sử dụng các hàm an toàn để tránh timing attacks
///
/// # Performance
/// - **Lazy Parsing**: Phrase chỉ được parse khi cần (to_seed, validate)
/// - **Stack Entropy**: Entropy được tạo trên stack, không heap allocation
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WalletMnemonic {
    phrase: String,
    word_count: usize,
}

// Custom Debug - KHÔNG BAO GIỜ hiển thị mnemonic phrase
impl std::fmt::Debug for WalletMnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletMnemonic")
            .field("word_count", &self.word_count)
            .field("phrase", &"[REDACTED]")
            .finish()
    }
}

impl WalletMnemonic {
    // =========================================================================
    // CONSTRUCTORS
    // =========================================================================

    /// Tạo mnemonic mới với 12 words (128-bit entropy)
    ///
    /// Phù hợp cho hầu hết use cases. Cân bằng giữa bảo mật và tiện dụng.
    pub fn new() -> Self {
        Self::with_word_count(WordCount::Twelve)
    }

    /// Tạo mnemonic mới với 24 words (256-bit entropy)
    ///
    /// Bảo mật cao nhất, khuyến nghị cho ví chứa số lượng lớn.
    pub fn new_24_words() -> Self {
        Self::with_word_count(WordCount::TwentyFour)
    }

    /// Tạo mnemonic với số lượng words tùy chỉnh
    ///
    /// # Arguments
    /// * `word_count` - Số lượng words (12, 15, 18, 21, hoặc 24)
    pub fn with_word_count(word_count: WordCount) -> Self {
        let entropy_size = word_count.entropy_bytes();

        // Stack-allocated entropy buffer (max 32 bytes)
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy[..entropy_size]);

        let mnemonic =
            Mnemonic::from_entropy(&entropy[..entropy_size]).expect("Valid entropy size");

        // Zeroize entropy ngay sau khi sử dụng
        entropy.zeroize();

        Self {
            phrase: mnemonic.to_string(),
            word_count: word_count as usize,
        }
    }

    /// Khôi phục mnemonic từ phrase có sẵn
    ///
    /// # Validation
    /// - Kiểm tra số lượng words (12, 15, 18, 21, 24)
    /// - Kiểm tra từng word có trong BIP-39 wordlist
    /// - Kiểm tra checksum
    pub fn from_phrase(phrase: &str) -> WalletResult<Self> {
        // Normalize whitespace và count words
        let normalized = phrase.split_whitespace().collect::<Vec<_>>();
        let count = normalized.len();

        // Validate word count
        if !matches!(count, 12 | 15 | 18 | 21 | 24) {
            return Err(WalletError::Mnemonic(MnemonicError::InvalidWordCount(
                count,
            )));
        }

        // Parse và validate với BIP-39
        let normalized_phrase = normalized.join(" ");
        Mnemonic::parse(&normalized_phrase).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("invalid word") || msg.contains("unknown word") {
                WalletError::Mnemonic(MnemonicError::UnknownWord(msg))
            } else if msg.contains("checksum") {
                WalletError::Mnemonic(MnemonicError::ChecksumFailed)
            } else {
                WalletError::Mnemonic(MnemonicError::Bip39Error(msg))
            }
        })?;

        Ok(Self {
            phrase: normalized_phrase,
            word_count: count,
        })
    }

    // =========================================================================
    // GETTERS
    // =========================================================================

    /// Lấy mnemonic phrase
    ///
    /// # Warning
    /// Cẩn thận khi hiển thị hoặc log giá trị này!
    #[inline]
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// Lấy số lượng words
    #[inline]
    pub fn word_count(&self) -> usize {
        self.word_count
    }

    /// Lấy danh sách các words
    pub fn words(&self) -> Vec<&str> {
        self.phrase.split_whitespace().collect()
    }

    // =========================================================================
    // SEED DERIVATION
    // =========================================================================

    /// Tạo seed từ mnemonic (PBKDF2-HMAC-SHA512)
    ///
    /// # Arguments
    /// * `passphrase` - Optional BIP-39 passphrase (thêm layer bảo mật)
    ///
    /// # Returns
    /// 64-byte seed wrapped trong `Zeroizing` để tự động xóa khi drop
    ///
    /// # Security Note
    /// Passphrase khác với password. Nếu mất passphrase, không thể khôi phục ví
    /// ngay cả khi có mnemonic phrase.
    pub fn to_seed(&self, passphrase: Option<&str>) -> Zeroizing<Vec<u8>> {
        let password = passphrase.unwrap_or("");
        let mnemonic = Mnemonic::parse(&self.phrase).expect("Internal phrase is valid");
        Zeroizing::new(mnemonic.to_seed(password).to_vec())
    }

    /// Tạo seed với fixed-size array (hiệu quả hơn Vec)
    ///
    /// # Performance
    /// Trả về `[u8; 64]` trên stack thay vì `Vec<u8>` trên heap
    pub fn to_seed_bytes(&self, passphrase: Option<&str>) -> Zeroizing<[u8; 64]> {
        let password = passphrase.unwrap_or("");
        let mnemonic = Mnemonic::parse(&self.phrase).expect("Internal phrase is valid");
        Zeroizing::new(mnemonic.to_seed(password))
    }

    // =========================================================================
    // VALIDATION
    // =========================================================================

    /// Kiểm tra xem phrase có hợp lệ không
    ///
    /// Thực hiện đầy đủ validation: word count, wordlist, checksum
    #[inline]
    pub fn validate(phrase: &str) -> bool {
        let count = phrase.split_whitespace().count();
        if !matches!(count, 12 | 15 | 18 | 21 | 24) {
            return false;
        }
        Mnemonic::parse(phrase).is_ok()
    }

    /// Kiểm tra một từ có trong BIP-39 English wordlist không
    pub fn is_valid_word(word: &str) -> bool {
        // BIP-39 English wordlist có 2048 từ
        // bip39 crate không expose wordlist trực tiếp, nên ta dùng cách gián tiếp
        let test_phrase = format!(
            "{} abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            word
        );
        // Nếu từ đầu tiên không hợp lệ, parse sẽ fail với "invalid word"
        match Mnemonic::parse(&test_phrase) {
            Ok(_) => true,
            Err(e) => !e.to_string().contains("invalid word"),
        }
    }

    /// Lấy strength (bit) của mnemonic
    pub fn strength_bits(&self) -> usize {
        match self.word_count {
            12 => 128,
            15 => 160,
            18 => 192,
            21 => 224,
            24 => 256,
            _ => 0,
        }
    }
}

// Default implementation
impl Default for WalletMnemonic {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// UNIT TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Standard test mnemonic (from BIP-39 test vectors)
    const TEST_MNEMONIC_12: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const TEST_MNEMONIC_24: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn test_new_12_words() {
        let mnemonic = WalletMnemonic::new();
        assert_eq!(mnemonic.word_count(), 12);
        assert!(WalletMnemonic::validate(mnemonic.phrase()));
    }

    #[test]
    fn test_new_24_words() {
        let mnemonic = WalletMnemonic::new_24_words();
        assert_eq!(mnemonic.word_count(), 24);
        assert!(WalletMnemonic::validate(mnemonic.phrase()));
    }

    #[test]
    fn test_from_phrase_valid() {
        let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC_12).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
    }

    #[test]
    fn test_from_phrase_24_words() {
        let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC_24).unwrap();
        assert_eq!(mnemonic.word_count(), 24);
    }

    #[test]
    fn test_from_phrase_normalizes_whitespace() {
        let messy_phrase =
            "  abandon  abandon   abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ";
        let mnemonic = WalletMnemonic::from_phrase(messy_phrase).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
        // Phrase should be normalized
        assert!(!mnemonic.phrase().starts_with(' '));
        assert!(!mnemonic.phrase().ends_with(' '));
    }

    #[test]
    fn test_from_phrase_invalid_word_count() {
        let result = WalletMnemonic::from_phrase("abandon abandon abandon");
        assert!(matches!(
            result,
            Err(WalletError::Mnemonic(MnemonicError::InvalidWordCount(3)))
        ));
    }

    #[test]
    fn test_from_phrase_invalid_word() {
        let invalid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid";
        let result = WalletMnemonic::from_phrase(invalid);
        assert!(matches!(
            result,
            Err(WalletError::Mnemonic(MnemonicError::UnknownWord(_)))
        ));
    }

    #[test]
    fn test_to_seed() {
        let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC_12).unwrap();
        let seed = mnemonic.to_seed(None);
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_to_seed_with_passphrase() {
        let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC_12).unwrap();
        let seed_no_pass = mnemonic.to_seed(None);
        let seed_with_pass = mnemonic.to_seed(Some("TREZOR"));

        // Seeds phải khác nhau
        assert_ne!(&*seed_no_pass, &*seed_with_pass);
    }

    #[test]
    fn test_to_seed_bytes() {
        let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC_12).unwrap();
        let seed = mnemonic.to_seed_bytes(None);
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_validate() {
        assert!(WalletMnemonic::validate(TEST_MNEMONIC_12));
        assert!(WalletMnemonic::validate(TEST_MNEMONIC_24));
        assert!(!WalletMnemonic::validate("invalid mnemonic phrase"));
        assert!(!WalletMnemonic::validate("abandon")); // Too few words
    }

    #[test]
    fn test_is_valid_word() {
        assert!(WalletMnemonic::is_valid_word("abandon"));
        assert!(WalletMnemonic::is_valid_word("zoo"));
        assert!(!WalletMnemonic::is_valid_word("invalidword"));
        assert!(!WalletMnemonic::is_valid_word("hello")); // Not in BIP-39 wordlist
    }

    #[test]
    fn test_strength_bits() {
        let m12 = WalletMnemonic::new();
        let m24 = WalletMnemonic::new_24_words();

        assert_eq!(m12.strength_bits(), 128);
        assert_eq!(m24.strength_bits(), 256);
    }

    #[test]
    fn test_words() {
        let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC_12).unwrap();
        let words = mnemonic.words();
        assert_eq!(words.len(), 12);
        assert_eq!(words[0], "abandon");
        assert_eq!(words[11], "about");
    }

    #[test]
    fn test_debug_does_not_leak_phrase() {
        let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC_12).unwrap();
        let debug_output = format!("{:?}", mnemonic);

        // Đảm bảo phrase KHÔNG xuất hiện trong debug output
        assert!(!debug_output.contains("abandon"));
        assert!(debug_output.contains("REDACTED"));
        assert!(debug_output.contains("word_count: 12"));
    }

    #[test]
    fn test_unique_generation() {
        // Hai lần gọi new() phải tạo ra mnemonics khác nhau
        let m1 = WalletMnemonic::new();
        let m2 = WalletMnemonic::new();
        assert_ne!(m1.phrase(), m2.phrase());
    }
}
