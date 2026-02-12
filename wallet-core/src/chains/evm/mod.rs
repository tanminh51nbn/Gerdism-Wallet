// wallet-core/src/chains/evm/mod.rs

//! Ethereum Virtual Machine (EVM) Chain Support
//!
//! This module provides support for Ethereum and EVM-compatible chains (BSC, Polygon, Avalanche, Base, etc.).
//!
//! # Key Features
//! - **Address Derivation**: EIP-55 checksummed address generation via [`EvmAddress`].
//! - **Signing**: High-performance signing for Transactions (EIP-155), Messages (EIP-191), and Typed Data (EIP-712) via [`EvmSigner`].
//! - **Parallelism**: Optional `rayon` support for batch operations (see `parallel` feature).

pub mod address;
pub mod signer;

// Re-exports for cleaner API access
pub use address::EvmAddress;
pub use signer::{EvmSigner, SignatureOutput};
