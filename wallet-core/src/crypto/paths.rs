// wallet-core/src/crypto/paths.rs
//
// Derivation Paths Module - Multi-Chain HD Wallet Path Generator
// BIP-44 (Purpose), SLIP-44 (Coin Types), BIP-84/49 (Bitcoin SegWit)

// =============================================================================
// SLIP-44 COIN TYPES
// =============================================================================
/// SLIP-44 Registered Coin Types
/// Ref: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
pub mod coin_type {
    // ---- secp256k1 chains ----
    pub const BITCOIN: u32 = 0;
    pub const LITECOIN: u32 = 2;
    pub const DOGECOIN: u32 = 3;
    pub const ETHEREUM: u32 = 60; // EVM chains dùng chung coin_type 60
    pub const COSMOS: u32 = 118;
    pub const TRON: u32 = 195;
    pub const BITCOIN_CASH: u32 = 145;

    // ---- ed25519 chains ----
    pub const SOLANA: u32 = 501;
    pub const APTOS: u32 = 637;
    pub const SUI: u32 = 784;
    pub const NEAR: u32 = 397;
    pub const TON: u32 = 607;

    // ---- sr25519 chains (chưa hỗ trợ, cần Substrate HDKD) ----
    // pub const POLKADOT: u32 = 354;
    // pub const CARDANO: u32 = 1815;
}

// =============================================================================
// DERIVATION PATHS
// =============================================================================
/// Pre-built Derivation Paths cho Multi-Chain Wallet
///
/// # Conventions
/// - BIP-44: `m/44'/coin'/account'/change/index` (secp256k1)
/// - BIP-84: `m/84'/0'/account'/change/index` (Bitcoin Native SegWit, secp256k1)
/// - BIP-49: `m/49'/0'/account'/change/index` (Bitcoin Nested SegWit, secp256k1)
/// - SLIP-0010: `m/44'/coin'/account'/change'` (ed25519, all hardened)
pub struct DerivationPaths;

impl DerivationPaths {
    // =========================================================================
    // EVM CHAINS (secp256k1) — BIP-44, coin_type = 60
    // Ethereum, BSC, Polygon, Arbitrum, Optimism, Avalanche, Base, zkSync...
    // =========================================================================
    pub const EVM_0: &'static str = "m/44'/60'/0'/0/0";

    /// EVM path with custom address index
    #[inline]
    pub fn evm(index: u32) -> String {
        format!("m/44'/60'/0'/0/{}", index)
    }

    /// EVM path with custom account & index (multi-account)
    #[inline]
    pub fn evm_account(account: u32, index: u32) -> String {
        format!("m/44'/60'/{}'/0/{}", account, index)
    }

    // =========================================================================
    // BITCOIN (secp256k1) — Multiple standards
    // =========================================================================
    /// BIP-84: Native SegWit (bc1q...) — Recommended
    pub const BTC_NATIVE_SEGWIT_0: &'static str = "m/84'/0'/0'/0/0";

    /// BIP-49: Nested SegWit (3...)
    pub const BTC_NESTED_SEGWIT_0: &'static str = "m/49'/0'/0'/0/0";

    /// BIP-44: Legacy (1...)
    pub const BTC_LEGACY_0: &'static str = "m/44'/0'/0'/0/0";

    /// BIP-86: Taproot (bc1p...) — Latest standard
    pub const BTC_TAPROOT_0: &'static str = "m/86'/0'/0'/0/0";

    #[inline]
    pub fn btc_native_segwit(account: u32, index: u32) -> String {
        format!("m/84'/0'/{}'/0/{}", account, index)
    }

    #[inline]
    pub fn btc_taproot(account: u32, index: u32) -> String {
        format!("m/86'/0'/{}'/0/{}", account, index)
    }

    #[inline]
    pub fn btc_legacy(account: u32, index: u32) -> String {
        format!("m/44'/0'/{}'/0/{}", account, index)
    }

    // =========================================================================
    // SOLANA (ed25519) — SLIP-0010 (all levels hardened)
    // =========================================================================
    pub const SOLANA_0: &'static str = "m/44'/501'/0'/0'";

    /// Solana path with custom account index
    #[inline]
    pub fn solana(account: u32) -> String {
        format!("m/44'/501'/{}'/0'", account)
    }

    // =========================================================================
    // COSMOS SDK (secp256k1) — BIP-44
    // Cosmos Hub, Osmosis, Celestia, Injective...
    // =========================================================================
    pub const COSMOS_0: &'static str = "m/44'/118'/0'/0/0";

    #[inline]
    pub fn cosmos(index: u32) -> String {
        format!("m/44'/118'/0'/0/{}", index)
    }

    // =========================================================================
    // TRON (secp256k1) — BIP-44
    // =========================================================================
    pub const TRON_0: &'static str = "m/44'/195'/0'/0/0";

    #[inline]
    pub fn tron(index: u32) -> String {
        format!("m/44'/195'/0'/0/{}", index)
    }

    // =========================================================================
    // APTOS (ed25519) — SLIP-0010
    // =========================================================================
    pub const APTOS_0: &'static str = "m/44'/637'/0'/0'/0'";

    #[inline]
    pub fn aptos(account: u32) -> String {
        format!("m/44'/637'/{}'/0'/0'", account)
    }

    // =========================================================================
    // SUI (ed25519) — SLIP-0010
    // =========================================================================
    pub const SUI_0: &'static str = "m/44'/784'/0'/0'/0'";

    #[inline]
    pub fn sui(account: u32) -> String {
        format!("m/44'/784'/{}'/0'/0'", account)
    }

    // =========================================================================
    // NEAR (ed25519) — SLIP-0010
    // =========================================================================
    pub const NEAR_0: &'static str = "m/44'/397'/0'";

    #[inline]
    pub fn near(account: u32) -> String {
        format!("m/44'/397'/{}'", account)
    }

    // =========================================================================
    // TON (ed25519) — SLIP-0010
    // =========================================================================
    pub const TON_0: &'static str = "m/44'/607'/0'";

    #[inline]
    pub fn ton(account: u32) -> String {
        format!("m/44'/607'/{}'", account)
    }

    // =========================================================================
    // POLKADOT — TẠM CHƯA HỖ TRỢ
    // Native Substrate dùng Sr25519 (Schnorrkel) + Substrate HDKD,
    // không dùng BIP-44/SLIP-0010. Cần module key_deriver/sr25519.rs.
    // =========================================================================

    // =========================================================================
    // CUSTOM PATH BUILDER
    // =========================================================================
    /// Tạo BIP-44 path tùy chỉnh (cho secp256k1 chains)
    ///
    /// # Arguments
    /// * `purpose` - 44 (BIP-44), 84 (BIP-84 SegWit), 49 (BIP-49), 86 (BIP-86 Taproot)
    /// * `coin_type` - SLIP-44 coin type (dùng constants từ `coin_type::*`)
    /// * `account` - Account index (thường 0)
    /// * `change` - 0 = external (nhận tiền), 1 = internal (thối tiền, chỉ Bitcoin)
    /// * `index` - Address index
    #[inline]
    pub fn bip44(purpose: u32, coin_type: u32, account: u32, change: u32, index: u32) -> String {
        format!(
            "m/{}'/{}'/{}'/{}/{}",
            purpose, coin_type, account, change, index
        )
    }

    /// Tạo SLIP-0010 path tùy chỉnh (cho ed25519 chains, all hardened)
    ///
    /// # Arguments
    /// * `coin_type` - SLIP-44 coin type
    /// * `account` - Account index
    #[inline]
    pub fn slip0010(coin_type: u32, account: u32) -> String {
        format!("m/44'/{}'/{}'/0'", coin_type, account)
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evm_paths() {
        assert_eq!(DerivationPaths::EVM_0, "m/44'/60'/0'/0/0");
        assert_eq!(DerivationPaths::evm(0), "m/44'/60'/0'/0/0");
        assert_eq!(DerivationPaths::evm(5), "m/44'/60'/0'/0/5");
        assert_eq!(DerivationPaths::evm_account(1, 3), "m/44'/60'/1'/0/3");
    }

    #[test]
    fn test_bitcoin_paths() {
        assert_eq!(DerivationPaths::BTC_NATIVE_SEGWIT_0, "m/84'/0'/0'/0/0");
        assert_eq!(DerivationPaths::BTC_TAPROOT_0, "m/86'/0'/0'/0/0");
        assert_eq!(DerivationPaths::BTC_LEGACY_0, "m/44'/0'/0'/0/0");
        assert_eq!(DerivationPaths::btc_native_segwit(0, 1), "m/84'/0'/0'/0/1");
    }

    #[test]
    fn test_solana_paths() {
        assert_eq!(DerivationPaths::SOLANA_0, "m/44'/501'/0'/0'");
        assert_eq!(DerivationPaths::solana(2), "m/44'/501'/2'/0'");
    }

    #[test]
    fn test_cosmos_paths() {
        assert_eq!(DerivationPaths::COSMOS_0, "m/44'/118'/0'/0/0");
        assert_eq!(DerivationPaths::cosmos(1), "m/44'/118'/0'/0/1");
    }

    #[test]
    fn test_ed25519_chain_paths() {
        assert_eq!(DerivationPaths::APTOS_0, "m/44'/637'/0'/0'/0'");
        assert_eq!(DerivationPaths::SUI_0, "m/44'/784'/0'/0'/0'");
        assert_eq!(DerivationPaths::NEAR_0, "m/44'/397'/0'");
        assert_eq!(DerivationPaths::TON_0, "m/44'/607'/0'");
    }

    #[test]
    fn test_custom_builders() {
        assert_eq!(DerivationPaths::bip44(44, 60, 0, 0, 0), "m/44'/60'/0'/0/0");
        assert_eq!(DerivationPaths::slip0010(501, 0), "m/44'/501'/0'/0'");
    }
}
