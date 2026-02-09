// wallet-core/src/network/mod.rs
//
// Network Module - Multi-Chain Provider Architecture
//
// Cung cấp:
// - Traits định nghĩa hành vi chung cho mọi blockchain
// - Models định nghĩa cấu trúc dữ liệu chain-agnostic

pub mod models;
pub mod traits;

// Re-export cho convenience
pub use models::*;
pub use traits::*;
