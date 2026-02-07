// src/crypto/mnemonic.rs
use anyhow::{anyhow, Result};
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
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        Mnemonic::parse(phrase).map_err(|_| anyhow!("Invalid mnemonic phrase"))?;

        Ok(Self {
            phrase: phrase.to_string(),
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
    fn test_generate_new_mnemonic() {
        let wallet = WalletMnemonic::new();
        let phrase = wallet.get_phrase();
        println!("Generated 12 words: {}", phrase);

        assert_eq!(phrase.split_whitespace().count(), 12);
        assert!(WalletMnemonic::validate(phrase));
    }

    #[test]
    fn test_generate_24_words() {
        let wallet = WalletMnemonic::new_24_words();
        let phrase = wallet.get_phrase();
        println!("Generated 24 words: {}", phrase);

        assert_eq!(phrase.split_whitespace().count(), 24);
        assert!(WalletMnemonic::validate(phrase));
    }

    #[test]
    fn test_restore_standard_vector() {
        let phrase =
            "shoot island position soft burden budget tooth cruel issue economy destroy above";
        let expected_seed_hex = "577cd910aede2582668a741d476b45e7998e905a4286f701b87b25923501f9d4ea19513b460bcccbc069ebbe4327a59af3d6463045c4b6fa21a5e7004ccfcc3e";

        assert!(WalletMnemonic::validate(phrase));

        let wallet = WalletMnemonic::from_phrase(phrase).expect("Should be valid");
        let seed = wallet.to_seed(None);

        assert_eq!(hex::encode(seed), expected_seed_hex);
    }
}
