use crate::error::{CryptoError, WalletError, WalletResult};
use bip32::{DerivationPath, XPrv};
use std::str::FromStr;

pub struct KeyDeriver;

impl KeyDeriver {
    pub fn derive_secp256k1_private_key(seed: &[u8], path: &str) -> WalletResult<Vec<u8>> {
        let root_xprv = XPrv::new(seed)
            .map_err(|e| WalletError::Crypto(CryptoError::DerivationFailed(e.to_string())))?;

        let derivation_path = DerivationPath::from_str(path).map_err(|e| {
            WalletError::Crypto(CryptoError::DerivationFailed(format!(
                "Invalid path '{}': {}",
                path, e
            )))
        })?;

        let mut child_xprv = root_xprv;
        for child_num in derivation_path {
            child_xprv = child_xprv
                .derive_child(child_num)
                .map_err(|e| WalletError::Crypto(CryptoError::DerivationFailed(e.to_string())))?;
        }

        Ok(child_xprv.private_key().to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_ethereum_key() {
        let seed = hex::decode("16270f7b026afe7a3746efbfcf43e083500951db9e2699d1e4f372515dabcc80459b9181c3937b5faa4b8f7602f886553d2c32c5f12f3331cef40153aead4de6").unwrap();

        let path = "m/44'/60'/0'/0/0";

        let priv_key = KeyDeriver::derive_secp256k1_private_key(&seed, path).unwrap();

        assert_eq!(priv_key.len(), 32);

        println!("Derived ETH Private Key: {}", hex::encode(&priv_key));
    }
}
