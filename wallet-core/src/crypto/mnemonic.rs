use crate::error::{MnemonicError, WalletError, WalletResult};
use bip39::Mnemonic;
use rand::{thread_rng, Rng};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct WalletMnemonic {
    phrase: String,
}

impl WalletMnemonic {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let entropy: [u8; 16] = rng.gen(); // 128 bits

        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();

        Self {
            phrase: mnemonic.to_string(),
        }
    }
    pub fn new_24_words() -> Self {
        let mut rng = thread_rng();
        let entropy: [u8; 32] = rng.gen(); // 256 bits
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        Self {
            phrase: mnemonic.to_string(),
        }
    }
    pub fn from_phrase(phrase: &str) -> WalletResult<Self> {
        let count = phrase.split_whitespace().count();
        
        if !matches!(count, 12 | 24) {
            return Err(WalletError::Mnemonic(MnemonicError::InvalidWordCount(count)));
        }

        let mnemonic = Mnemonic::parse(phrase).map_err(|e| {
            let err_msg = e.to_string().to_lowercase();
            if err_msg.contains("word") {
                WalletError::Mnemonic(MnemonicError::UnknownWord(phrase.to_string()))
            } else if err_msg.contains("checksum") {
                WalletError::Mnemonic(MnemonicError::ChecksumFailed)
            } else {
                WalletError::Mnemonic(MnemonicError::Bip39Error(e.to_string()))
            }
        })?;

        Ok(Self {
            phrase: mnemonic.to_string(),
        })
    }

    pub fn get_phrase(&self) -> &str {
        &self.phrase
    }

    pub fn validate(phrase: &str) -> bool {
        Mnemonic::parse(phrase).is_ok()
    }

    pub fn to_seed(&self, passphrase: Option<&str>) -> Vec<u8> {
        let password = passphrase.unwrap_or("");
        let mnemonic = Mnemonic::parse(&self.phrase).expect("Valid mnemonic");
        mnemonic.to_seed(password).to_vec()
    }
}

// --- UNIT TEST ---
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_display_wallet_mnemonic_results() {
        println!("\n========================================");
        println!("   WalletMnemonic Function Results");
        println!("========================================");

        // Test display: new() (12 words)
        let wallet_12 = WalletMnemonic::new();
        let phrase_12 = wallet_12.get_phrase();
        println!("\n[1] new() -> 12 words:");
        println!("    Phrase: {}", phrase_12);
        println!("    Valid:  {}", WalletMnemonic::validate(phrase_12));

        // Test display: new_24_words()
        let wallet_24 = WalletMnemonic::new_24_words();
        let phrase_24 = wallet_24.get_phrase();
        println!("\n[2] new_24_words() -> 24 words:");
        println!("    Phrase: {}", phrase_24);
        println!("    Valid:  {}", WalletMnemonic::validate(phrase_24));

        // Test display: to_seed()
        println!("\n[3] to_seed():");
        let seed_default = wallet_12.to_seed(None);
        println!("    Seed (no pass):   {}", hex::encode(seed_default));

        let seed_pass = wallet_12.to_seed(Some("password123"));
        println!("    Seed (w/ pass):   {}", hex::encode(seed_pass));

        println!("\n========================================");
    }
}
