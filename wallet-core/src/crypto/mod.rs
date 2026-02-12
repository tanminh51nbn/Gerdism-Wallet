// wallet-core/src/crypto/mod.rs

//! Core Cryptography Module
//!
//! This module implements the fundamental cryptographic operations for a multi-chain wallet:
//!
//! - **Mnemonic Generation**: BIP-39 compliant mnemonic phrases (12/24 words) via [`WalletMnemonic`].
//! - **Key Derivation**: Unified interface for Secp256k1 (Bitcoin/EVM) and Ed25519 (Solana/Sui/Aptos) via [`KeyDeriver`].
//! - **Derivation Paths**: Pre-defined and custom path builders for BIP-44, BIP-84, SLIP-0010 via [`DerivationPaths`].

pub mod key_deriver;
pub mod mnemonic;
pub mod paths;

// Re-exports for cleaner API access
pub use key_deriver::{CurveType, DerivedKey, KeyDeriver};
pub use mnemonic::{WalletMnemonic, WordCount};
pub use paths::DerivationPaths;
