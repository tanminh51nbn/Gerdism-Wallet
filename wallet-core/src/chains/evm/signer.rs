// wallet-core/src/chains/evm/signer.rs
//
// EVM Signer Module — Professional-Grade Offline Signing Engine
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  Supported Standards                                                    │
// │  ─────────────────                                                      │
// │  • EIP-155  — Replay Protection (chain_id in signature)                 │
// │  • EIP-191  — Personal Message Signing (eth_sign / personal_sign)       │
// │  • EIP-712  — Typed Structured Data Signing (Permit, Orders, etc.)      │
// │  • EIP-1559 — Dynamic Fee Transactions (Type 2)                         │
// │  • EIP-2930 — Access List Transactions (Type 1)                         │
// │  • EIP-4844 — Blob Transactions / Proto-Danksharding (Type 3)           │
// │  • EIP-7702 — Account Delegation (Type 4)                               │
// │                                                                         │
// │  Security                                                               │
// │  ────────                                                               │
// │  • ZeroizeOnDrop — SigningKey zeroed on Drop                            │
// │  • No Debug Leak — Custom Debug impl hides private key                  │
// │  • Constant-Time — Address comparison via fixed-size byte equality      │
// │  • Memory Safety — Rust ownership prevents accidental key copies        │
// │  • Chain-bound   — Mandatory chain_id for replay protection             │
// │                                                                         │
// │  Performance                                                            │
// │  ───────────                                                            │
// │  • Cached address — Derived once at construction time                   │
// │  • Sync variants  — Zero async overhead when runtime is unnecessary     │
// │  • Zero-copy      — References over clones wherever possible            │
// │  • Batch signing  — Amortized overhead for multi-message workloads      │
// └─────────────────────────────────────────────────────────────────────────┘

use crate::error::{CryptoError, WalletError, WalletResult};

use alloy::{
    consensus::TxEnvelope,
    eips::eip2718::Encodable2718,
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address, B256, U256},
    rpc::types::TransactionRequest,
    signers::{local::LocalSigner, Signature, Signer, SignerSync},
    sol_types::{Eip712Domain, SolStruct},
};
use k256::ecdsa::SigningKey;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use zeroize::Zeroizing;

// =============================================================================
// SIGNATURE OUTPUT — Compact representation for export / RPC
// =============================================================================
/// Compact signature representation for serialization and RPC transport.
///
/// Contains the raw `r`, `s`, `v` components plus encoded bytes.
/// Hex encoding is **lazy** — only computed when [`to_hex()`](Self::to_hex)
/// is called, avoiding unnecessary heap allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureOutput {
    /// ECDSA `r` component (32 bytes)
    pub r: B256,
    /// ECDSA `s` component (32 bytes)
    pub s: B256,
    /// Recovery id (`0` or `1` for modern EIPs, `27/28` for legacy)
    pub v: u64,
    /// Full signature bytes (65 bytes: r ∥ s ∥ v)
    pub bytes: Vec<u8>,
}

impl SignatureOutput {
    /// Build from an alloy [`Signature`].
    fn from_signature(sig: &Signature) -> Self {
        // In alloy 1.x: .r() and .s() return U256, .v() returns bool (y_parity)
        let r_u256 = sig.r();
        let s_u256 = sig.s();
        let y_parity = sig.v();

        let r = B256::from(r_u256.to_be_bytes::<32>());
        let s = B256::from(s_u256.to_be_bytes::<32>());
        let v = y_parity as u64;

        // Encode 65 bytes: r(32) || s(32) || v(1)
        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(r.as_slice());
        bytes.extend_from_slice(s.as_slice());
        bytes.push(v as u8);

        Self { r, s, v, bytes }
    }

    /// Hex-encode the signature with `0x` prefix.
    ///
    /// Lazy — only allocates when called. Use this instead of eagerly
    /// storing a hex string on every signature operation.
    #[inline]
    pub fn to_hex(&self) -> String {
        format!("0x{}", ::hex::encode(&self.bytes))
    }
}

// =============================================================================
// EVM SIGNER — Core struct
// =============================================================================
/// High-performance, secure offline EVM signer.
///
/// Wraps [`LocalSigner<SigningKey>`] with ergonomic methods covering every
/// signing standard used by modern multi-chain wallets.
///
/// # Lifecycle
///
/// ```text
/// ┌──────────┐     ┌───────────┐     ┌──────────────┐
/// │ 32-byte  │ --> │ EvmSigner │ --> │ sign_*()     │ --> raw bytes / sig
/// │ priv key │     │  (cached  │     │ verify_*()   │
/// │          │     │  address) │     │ recover_*()  │
/// └──────────┘     └───────────┘     └──────────────┘
/// ```
///
/// # Security Properties
///
/// | Property         | Mechanism                               |
/// |------------------|-----------------------------------------|
/// | Key zeroing      | `k256::SigningKey` impls `ZeroizeOnDrop`|
/// | No debug leak    | Custom `Debug` impl                     |
/// | Replay defense   | Mandatory `chain_id` (EIP-155)          |
/// | Memory safety    | Rust ownership — no implicit copies     |
pub struct EvmSigner {
    /// Inner alloy signer — owns the `SigningKey` (auto-zeroed on Drop).
    signer: LocalSigner<SigningKey>,
    /// Pre-computed address — avoids re-deriving on every call.
    address: Address,
    /// EVM chain identifier for EIP-155 replay protection.
    chain_id: u64,
}

// Custom Debug — NEVER expose private key material.
impl core::fmt::Debug for EvmSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EvmSigner")
            .field("address", &self.address)
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

// Explicit Drop — audit trail for key lifecycle.
impl Drop for EvmSigner {
    fn drop(&mut self) {
        // Inner `SigningKey` auto-zeroes via `ZeroizeOnDrop`.
        // Debug-mode log for development leak-tracing.
        #[cfg(debug_assertions)]
        eprintln!(
            "[EvmSigner] Dropped signer for address: {} (chain {})",
            self.address, self.chain_id
        );
    }
}

impl EvmSigner {
    // =========================================================================
    // CONSTRUCTORS
    // =========================================================================

    /// Create a signer from a **zeroizing private key** and chain ID.
    ///
    /// This is the **recommended** constructor — it takes ownership of the
    /// key material wrapped in [`Zeroizing`], guaranteeing the caller's
    /// buffer is zeroed when `new()` returns (even on error).
    ///
    /// # Arguments
    /// * `priv_key` — `Zeroizing<Vec<u8>>` containing exactly 32 bytes.
    /// * `chain_id` — Target chain (1 = Ethereum, 56 = BSC, 137 = Polygon, …).
    ///
    /// # Security
    /// ```text
    /// Caller: Zeroizing<Vec<u8>> ──ownership──> new() ──> SigningKey (ZeroizeOnDrop)
    ///         ↓ (dropped & zeroed)                        ↓ (zeroed on Drop)
    /// ```
    /// Both the input buffer AND the internal key are automatically zeroed.
    pub fn new(priv_key: Zeroizing<Vec<u8>>, chain_id: u64) -> WalletResult<Self> {
        Self::from_slice(&priv_key, chain_id)
        // `priv_key` is dropped here → Zeroizing zeroes the Vec's buffer
    }

    /// Create a signer from a **borrowed byte slice**.
    ///
    /// Use this when the caller manages key memory lifecycle themselves
    /// (e.g. hardware-backed keys, or keys from a pre-zeroed buffer).
    ///
    /// # ⚠ Security Note
    /// The caller is responsible for zeroing `priv_key` after this call.
    /// Prefer [`new()`](Self::new) with `Zeroizing<Vec<u8>>` for automatic zeroing.
    pub fn from_slice(priv_key: &[u8], chain_id: u64) -> WalletResult<Self> {
        let signing_key = SigningKey::from_slice(priv_key).map_err(|e| {
            WalletError::Crypto(CryptoError::InvalidKeyFormat(format!(
                "Invalid secp256k1 private key (must be 32 bytes on the curve): {}",
                e
            )))
        })?;

        let signer = LocalSigner::from(signing_key).with_chain_id(Some(chain_id));
        let address = signer.address();

        Ok(Self {
            signer,
            address,
            chain_id,
        })
    }

    /// Create a signer from a **hex-encoded** private key string.
    ///
    /// Accepts with or without `0x` prefix.
    /// The decoded bytes are wrapped in [`Zeroizing`] automatically.
    pub fn from_hex(hex_key: &str, chain_id: u64) -> WalletResult<Self> {
        let stripped = hex_key.strip_prefix("0x").unwrap_or(hex_key);
        let bytes = Zeroizing::new(::hex::decode(stripped).map_err(|e| {
            WalletError::Crypto(CryptoError::InvalidKeyFormat(format!(
                "Invalid hex string: {}",
                e
            )))
        })?);
        Self::new(bytes, chain_id)
    }

    // =========================================================================
    // GETTERS
    // =========================================================================

    /// Returns the EIP-55 checksummed Ethereum address derived from the key.
    #[inline]
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns the current chain ID.
    #[inline]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    // =========================================================================
    // CHAIN MANAGEMENT
    // =========================================================================

    /// Switch the signer to a different EVM chain.
    ///
    /// This is useful for multi-chain wallets where the same private key
    /// is used across Ethereum, BSC, Polygon, Arbitrum, etc.
    /// The address remains the same — only the EIP-155 chain_id changes.
    pub fn set_chain_id(&mut self, chain_id: u64) {
        self.chain_id = chain_id;
        self.signer = self.signer.clone().with_chain_id(Some(chain_id));
    }

    // =========================================================================
    // TRANSACTION SIGNING
    // Supports: Legacy (Type 0), EIP-2930 (Type 1), EIP-1559 (Type 2),
    //           EIP-4844 (Type 3), EIP-7702 (Type 4)
    // =========================================================================

    /// Sign a transaction offline and return the **RLP-encoded envelope** bytes.
    ///
    /// The returned bytes are ready for broadcast via `eth_sendRawTransaction`.
    ///
    /// Transaction type is **auto-detected** from the fields set on `tx`:
    ///
    /// | Fields present                        | Type            |
    /// |---------------------------------------|-----------------|
    /// | `gas_price` only                      | Legacy (Type 0) |
    /// | `gas_price` + `access_list`           | EIP-2930 (1)    |
    /// | `max_fee_per_gas` + `max_priority_…`  | EIP-1559 (2)    |
    /// | `max_fee_per_blob_gas` + `blob_…`     | EIP-4844 (3)    |
    /// | `authorization_list`                  | EIP-7702 (4)    |
    ///
    /// # Errors
    /// Returns [`CryptoError::TransactionBuildFailed`] on missing required fields
    /// or signing failure.
    pub async fn sign_transaction(&self, tx: TransactionRequest) -> WalletResult<Vec<u8>> {
        let wallet = EthereumWallet::from(self.signer.clone());

        let envelope: TxEnvelope = tx
            .build(&wallet)
            .await
            .map_err(|e| WalletError::Crypto(CryptoError::TransactionBuildFailed(e.to_string())))?;

        Ok(envelope.encoded_2718())
    }

    /// Sign a transaction and return both the raw bytes **and** the tx hash.
    ///
    /// Useful when you need the hash immediately (e.g. for tracking / UI).
    pub async fn sign_transaction_with_hash(
        &self,
        tx: TransactionRequest,
    ) -> WalletResult<(Vec<u8>, B256)> {
        let wallet = EthereumWallet::from(self.signer.clone());

        let envelope: TxEnvelope = tx
            .build(&wallet)
            .await
            .map_err(|e| WalletError::Crypto(CryptoError::TransactionBuildFailed(e.to_string())))?;

        let raw = envelope.encoded_2718();
        let tx_hash = *envelope.tx_hash();

        Ok((raw, tx_hash))
    }

    // =========================================================================
    // MESSAGE SIGNING — EIP-191 (Personal Sign)
    // =========================================================================

    /// Sign an arbitrary message per **EIP-191** (Personal Sign).
    ///
    /// The message is automatically prefixed with:
    /// `"\x19Ethereum Signed Message:\n{length}{message}"`
    ///
    /// Common use cases:
    /// - DApp login / "Sign-In with Ethereum" (SIWE)
    /// - Off-chain ownership proofs
    /// - Off-chain authorization tokens
    pub async fn sign_message(&self, message: &[u8]) -> WalletResult<Signature> {
        self.signer
            .sign_message(message)
            .await
            .map_err(|e| WalletError::Crypto(CryptoError::SigningFailed(e.to_string())))
    }

    /// Sign a message (synchronous — avoids async runtime overhead).
    pub fn sign_message_sync(&self, message: &[u8]) -> WalletResult<Signature> {
        self.signer
            .sign_message_sync(message)
            .map_err(|e| WalletError::Crypto(CryptoError::SigningFailed(e.to_string())))
    }

    /// Sign a message and return a [`SignatureOutput`] with encoded bytes + hex.
    pub fn sign_message_to_output(&self, message: &[u8]) -> WalletResult<SignatureOutput> {
        let sig = self.sign_message_sync(message)?;
        Ok(SignatureOutput::from_signature(&sig))
    }

    // =========================================================================
    // HASH SIGNING — Low-level (raw 32-byte prehash)
    // =========================================================================

    /// Sign a pre-computed 32-byte hash **directly**.
    ///
    /// # ⚠ Warning
    /// Only use this if you have already hashed the data using the correct
    /// domain-separated scheme (e.g. EIP-191 prefix, EIP-712 struct hash).
    /// Signing arbitrary hashes without proper framing is a security risk.
    pub async fn sign_hash(&self, hash: &B256) -> WalletResult<Signature> {
        self.signer
            .sign_hash(hash)
            .await
            .map_err(|e| WalletError::Crypto(CryptoError::SigningFailed(e.to_string())))
    }

    /// Sign hash (synchronous).
    pub fn sign_hash_sync(&self, hash: &B256) -> WalletResult<Signature> {
        self.signer
            .sign_hash_sync(hash)
            .map_err(|e| WalletError::Crypto(CryptoError::SigningFailed(e.to_string())))
    }

    /// Sign a hash and return a [`SignatureOutput`].
    pub fn sign_hash_to_output(&self, hash: &B256) -> WalletResult<SignatureOutput> {
        let sig = self.sign_hash_sync(hash)?;
        Ok(SignatureOutput::from_signature(&sig))
    }

    // =========================================================================
    // TYPED DATA SIGNING — EIP-712
    // =========================================================================

    /// Sign **EIP-712 typed structured data**.
    ///
    /// EIP-712 produces human-readable signature requests in wallet UIs.
    ///
    /// Common use cases:
    /// - ERC-20 Permit (gasless approvals)
    /// - DEX order signing (Uniswap, 0x, etc.)
    /// - Meta-transactions / gasless relaying
    /// - Off-chain governance voting
    ///
    /// # Arguments
    /// * `data`   — Struct implementing [`SolStruct`] (generated by `sol!` macro).
    /// * `domain` — The EIP-712 domain separator. If `None`, a minimal domain
    ///              with only `chain_id` is used.
    pub async fn sign_typed_data<T: SolStruct + Send + Sync>(
        &self,
        data: &T,
        domain: Option<&Eip712Domain>,
    ) -> WalletResult<Signature> {
        let default_domain;
        let signing_domain = match domain {
            Some(d) => d,
            None => {
                default_domain = Eip712Domain {
                    chain_id: Some(U256::from(self.chain_id)),
                    ..Default::default()
                };
                &default_domain
            }
        };

        let hash = data.eip712_signing_hash(signing_domain);

        self.signer
            .sign_hash(&hash)
            .await
            .map_err(|e| WalletError::Crypto(CryptoError::SigningFailed(e.to_string())))
    }

    /// Sign EIP-712 typed data (synchronous).
    pub fn sign_typed_data_sync<T: SolStruct>(
        &self,
        data: &T,
        domain: Option<&Eip712Domain>,
    ) -> WalletResult<Signature> {
        let default_domain;
        let signing_domain = match domain {
            Some(d) => d,
            None => {
                default_domain = Eip712Domain {
                    chain_id: Some(U256::from(self.chain_id)),
                    ..Default::default()
                };
                &default_domain
            }
        };

        let hash = data.eip712_signing_hash(signing_domain);

        self.signer
            .sign_hash_sync(&hash)
            .map_err(|e| WalletError::Crypto(CryptoError::SigningFailed(e.to_string())))
    }

    /// Sign EIP-712 typed data and return [`SignatureOutput`].
    pub fn sign_typed_data_to_output<T: SolStruct>(
        &self,
        data: &T,
        domain: Option<&Eip712Domain>,
    ) -> WalletResult<SignatureOutput> {
        let sig = self.sign_typed_data_sync(data, domain)?;
        Ok(SignatureOutput::from_signature(&sig))
    }

    /// Sign a pre-computed EIP-712 **struct hash** with the given domain.
    ///
    /// Use this when you have already computed `hashStruct(message)` yourself
    /// and only need the final signing step.
    pub fn sign_typed_data_hash_sync(
        &self,
        domain: &Eip712Domain,
        struct_hash: &B256,
    ) -> WalletResult<Signature> {
        let domain_hash = domain.hash_struct();
        let mut buf = [0u8; 66]; // \x19\x01 + domain(32) + struct(32)
        buf[0] = 0x19;
        buf[1] = 0x01;
        buf[2..34].copy_from_slice(domain_hash.as_slice());
        buf[34..66].copy_from_slice(struct_hash.as_slice());

        use alloy::primitives::keccak256;
        let final_hash = keccak256(&buf);

        self.signer
            .sign_hash_sync(&final_hash)
            .map_err(|e| WalletError::Crypto(CryptoError::SigningFailed(e.to_string())))
    }

    // =========================================================================
    // BATCH SIGNING — Adaptive: parallel (native) / sequential (WASM)
    // =========================================================================

    /// Sign multiple messages in a single batch call.
    ///
    /// - **Native** (`feature = "parallel"`): Uses [`rayon`] work-stealing
    ///   thread pool for multi-core parallelism.
    /// - **WASM** (no `parallel` feature): Falls back to sequential iteration
    ///   (safe for single-threaded browser environments).
    ///
    /// Each message is signed independently — individual failures do not
    /// abort the batch.
    ///
    /// # Performance (native w/ parallel)
    /// - 1–2 messages: Overhead ≈ negligible (rayon short-circuits small inputs)
    /// - 1000+ messages: Near-linear speedup with core count
    pub fn sign_messages_batch(&self, messages: &[&[u8]]) -> Vec<WalletResult<Signature>> {
        #[cfg(feature = "parallel")]
        {
            messages
                .par_iter()
                .map(|msg| self.sign_message_sync(msg))
                .collect()
        }
        #[cfg(not(feature = "parallel"))]
        {
            messages
                .iter()
                .map(|msg| self.sign_message_sync(msg))
                .collect()
        }
    }

    /// Sign multiple hashes in a single batch call.
    ///
    /// Uses parallel iteration on native, sequential on WASM.
    pub fn sign_hashes_batch(&self, hashes: &[B256]) -> Vec<WalletResult<Signature>> {
        #[cfg(feature = "parallel")]
        {
            hashes
                .par_iter()
                .map(|hash| self.sign_hash_sync(hash))
                .collect()
        }
        #[cfg(not(feature = "parallel"))]
        {
            hashes
                .iter()
                .map(|hash| self.sign_hash_sync(hash))
                .collect()
        }
    }

    // =========================================================================
    // SIGNATURE VERIFICATION
    // =========================================================================

    /// Verify that an EIP-191 message signature was produced by this signer.
    ///
    /// Returns `true` if the recovered address matches `self.address`.
    pub fn verify_message(&self, message: &[u8], signature: &Signature) -> bool {
        signature
            .recover_address_from_msg(message)
            .map(|recovered| recovered == self.address)
            .unwrap_or(false)
    }

    /// Verify that a prehash signature was produced by this signer.
    pub fn verify_hash(&self, hash: &B256, signature: &Signature) -> bool {
        signature
            .recover_address_from_prehash(hash)
            .map(|recovered| recovered == self.address)
            .unwrap_or(false)
    }

    // =========================================================================
    // ADDRESS RECOVERY — Static utilities
    // =========================================================================

    /// Recover the signer address from an **EIP-191** message + signature.
    ///
    /// This is a standalone utility — it does not require an `EvmSigner` instance.
    pub fn recover_address_from_message(
        message: &[u8],
        signature: &Signature,
    ) -> WalletResult<Address> {
        signature.recover_address_from_msg(message).map_err(|e| {
            WalletError::Crypto(CryptoError::VerificationFailed(format!(
                "Failed to recover address from message: {}",
                e
            )))
        })
    }

    /// Recover the signer address from a **prehash** + signature.
    pub fn recover_address_from_hash(hash: &B256, signature: &Signature) -> WalletResult<Address> {
        signature.recover_address_from_prehash(hash).map_err(|e| {
            WalletError::Crypto(CryptoError::VerificationFailed(format!(
                "Failed to recover address from hash: {}",
                e
            )))
        })
    }

    // =========================================================================
    // SIGNATURE ENCODING / DECODING — Interop utilities
    // =========================================================================

    /// Encode a [`Signature`] into a [`SignatureOutput`].
    #[inline]
    pub fn encode_signature(sig: &Signature) -> SignatureOutput {
        SignatureOutput::from_signature(sig)
    }

    /// Decode a 65-byte slice (`r[32] || s[32] || v[1]`) into a
    /// [`Signature`].
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidSignature`] if the slice is not 65 bytes.
    pub fn decode_signature(bytes: &[u8]) -> WalletResult<Signature> {
        if bytes.len() != 65 {
            return Err(WalletError::Crypto(CryptoError::InvalidSignature(format!(
                "Expected 65 bytes, got {}",
                bytes.len()
            ))));
        }

        let r = U256::from_be_slice(&bytes[0..32]);
        let s = U256::from_be_slice(&bytes[32..64]);
        let v = bytes[64];

        // Normalize v: 27/28 (legacy) → 0/1 (modern)
        let y_parity = match v {
            0 | 1 => v != 0,
            27 => false,
            28 => true,
            _ => {
                return Err(WalletError::Crypto(CryptoError::InvalidSignature(format!(
                    "Invalid recovery id: {}",
                    v
                ))));
            }
        };

        Ok(Signature::new(r, s, y_parity))
    }

    /// Decode a hex-encoded signature string (with or without `0x` prefix).
    pub fn decode_signature_hex(hex_sig: &str) -> WalletResult<Signature> {
        let stripped = hex_sig.strip_prefix("0x").unwrap_or(hex_sig);
        let bytes = ::hex::decode(stripped).map_err(|e| {
            WalletError::Crypto(CryptoError::InvalidSignature(format!(
                "Invalid hex encoding: {}",
                e
            )))
        })?;
        Self::decode_signature(&bytes)
    }
}

// =============================================================================
// UNIT TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Anvil/Hardhat default account #0 — well-known test vector
    const TEST_PRIVATE_KEY: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const TEST_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const TEST_CHAIN_ID: u64 = 31337; // Anvil local chain

    fn create_test_signer() -> EvmSigner {
        let priv_key = Zeroizing::new(hex::decode(TEST_PRIVATE_KEY).unwrap());
        EvmSigner::new(priv_key, TEST_CHAIN_ID).expect("Should create signer from valid key")
    }

    // ── Constructor Tests ───────────────────────────────────────────────

    #[test]
    fn test_new_valid_key() {
        let signer = create_test_signer();
        let expected: Address = TEST_ADDRESS.parse().unwrap();
        assert_eq!(signer.address(), expected);
        assert_eq!(signer.chain_id(), TEST_CHAIN_ID);
    }

    #[test]
    fn test_from_hex_with_prefix() {
        let signer =
            EvmSigner::from_hex(&format!("0x{}", TEST_PRIVATE_KEY), TEST_CHAIN_ID).unwrap();
        let expected: Address = TEST_ADDRESS.parse().unwrap();
        assert_eq!(signer.address(), expected);
    }

    #[test]
    fn test_from_hex_without_prefix() {
        let signer = EvmSigner::from_hex(TEST_PRIVATE_KEY, TEST_CHAIN_ID).unwrap();
        let expected: Address = TEST_ADDRESS.parse().unwrap();
        assert_eq!(signer.address(), expected);
    }

    #[test]
    fn test_from_slice() {
        let priv_key = hex::decode(TEST_PRIVATE_KEY).unwrap();
        let signer = EvmSigner::from_slice(&priv_key, TEST_CHAIN_ID).unwrap();
        let expected: Address = TEST_ADDRESS.parse().unwrap();
        assert_eq!(signer.address(), expected);
    }

    #[test]
    fn test_invalid_key_too_short() {
        let invalid = Zeroizing::new(vec![0u8; 31]);
        assert!(EvmSigner::new(invalid, 1).is_err());
    }

    #[test]
    fn test_invalid_key_too_long() {
        let invalid = Zeroizing::new(vec![0u8; 33]);
        assert!(EvmSigner::new(invalid, 1).is_err());
    }

    #[test]
    fn test_invalid_key_all_zeros() {
        let zero_key = Zeroizing::new(vec![0u8; 32]);
        assert!(EvmSigner::new(zero_key, 1).is_err());
    }

    #[test]
    fn test_invalid_hex() {
        assert!(EvmSigner::from_hex("not_hex", 1).is_err());
        assert!(EvmSigner::from_hex("0xZZZZ", 1).is_err());
    }

    // ── Chain Management Tests ──────────────────────────────────────────

    #[test]
    fn test_set_chain_id() {
        let mut signer = create_test_signer();
        assert_eq!(signer.chain_id(), TEST_CHAIN_ID);

        signer.set_chain_id(1); // Switch to Ethereum mainnet
        assert_eq!(signer.chain_id(), 1);

        // Address should NOT change when switching chains
        let expected: Address = TEST_ADDRESS.parse().unwrap();
        assert_eq!(signer.address(), expected);
    }

    // ── EIP-191 Message Signing Tests ───────────────────────────────────

    #[test]
    fn test_sign_message_sync() {
        let signer = create_test_signer();
        let message = b"Hello, Ethereum!";

        let signature = signer.sign_message_sync(message).expect("Should sign");
        assert!(signer.verify_message(message, &signature));
    }

    #[test]
    fn test_sign_message_to_output() {
        let signer = create_test_signer();
        let output = signer
            .sign_message_to_output(b"Test output")
            .expect("Should sign");

        assert_eq!(output.bytes.len(), 65);

        // Lazy hex: only computed on demand
        let hex = output.to_hex();
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 132); // "0x" + 130 hex chars
    }

    #[tokio::test]
    async fn test_sign_message_async() {
        let signer = create_test_signer();
        let message = b"Async signing test";

        let signature = signer.sign_message(message).await.expect("Should sign");
        assert!(signer.verify_message(message, &signature));
    }

    #[test]
    fn test_sign_message_empty() {
        let signer = create_test_signer();
        let sig = signer.sign_message_sync(b"").expect("Should sign empty");
        assert!(signer.verify_message(b"", &sig));
    }

    #[test]
    fn test_sign_message_unicode() {
        let signer = create_test_signer();
        let msg = "Xin chào thế giới 🌍".as_bytes();
        let sig = signer.sign_message_sync(msg).expect("Should sign unicode");
        assert!(signer.verify_message(msg, &sig));
    }

    // ── Hash Signing Tests ──────────────────────────────────────────────

    #[test]
    fn test_sign_hash_sync() {
        let signer = create_test_signer();
        let hash = B256::repeat_byte(0x42);

        let signature = signer.sign_hash_sync(&hash).expect("Should sign hash");
        assert!(signer.verify_hash(&hash, &signature));
    }

    #[test]
    fn test_sign_hash_to_output() {
        let signer = create_test_signer();
        let hash = B256::repeat_byte(0xAB);

        let output = signer
            .sign_hash_to_output(&hash)
            .expect("Should produce output");
        assert_eq!(output.bytes.len(), 65);

        // Verify the signature components match
        let decoded = EvmSigner::decode_signature(&output.bytes).unwrap();
        assert!(signer.verify_hash(&hash, &decoded));
    }

    #[tokio::test]
    async fn test_sign_hash_async() {
        let signer = create_test_signer();
        let hash = B256::repeat_byte(0xFF);

        let sig = signer.sign_hash(&hash).await.expect("Should sign");
        assert!(signer.verify_hash(&hash, &sig));
    }

    // ── Transaction Signing Tests ───────────────────────────────────────

    #[tokio::test]
    async fn test_sign_legacy_transaction() {
        let signer = create_test_signer();

        let tx = TransactionRequest::default()
            .with_to(
                "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
                    .parse()
                    .unwrap(),
            )
            .with_value(U256::from(1_000_000_000_000_000_000u128)) // 1 ETH
            .with_nonce(0)
            .with_chain_id(TEST_CHAIN_ID)
            .with_gas_limit(21000)
            .with_gas_price(1_000_000_000); // 1 Gwei

        let raw_tx = signer.sign_transaction(tx).await.expect("Should sign tx");
        assert!(!raw_tx.is_empty());

        let hex_tx = hex::encode(&raw_tx);
        // Legacy TX prefix = f8..., EIP-1559 prefix = 02...
        assert!(
            hex_tx.starts_with("f8") || hex_tx.starts_with("02"),
            "Unexpected TX prefix: {}",
            &hex_tx[..4.min(hex_tx.len())]
        );
    }

    #[tokio::test]
    async fn test_sign_eip1559_transaction() {
        let signer = create_test_signer();

        let tx = TransactionRequest::default()
            .with_to(
                "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
                    .parse()
                    .unwrap(),
            )
            .with_value(U256::from(1_000_000_000_000_000_000u128))
            .with_nonce(0)
            .with_chain_id(TEST_CHAIN_ID)
            .with_gas_limit(21000)
            .with_max_fee_per_gas(30_000_000_000u128) // 30 Gwei
            .with_max_priority_fee_per_gas(1_000_000_000u128); // 1 Gwei

        let raw_tx = signer
            .sign_transaction(tx)
            .await
            .expect("Should sign EIP-1559 tx");
        assert!(!raw_tx.is_empty());

        // EIP-1559 encoded starts with 0x02
        let hex_tx = hex::encode(&raw_tx);
        assert!(
            hex_tx.starts_with("02"),
            "EIP-1559 tx should start with 02, got: {}",
            &hex_tx[..4.min(hex_tx.len())]
        );
    }

    #[tokio::test]
    async fn test_sign_transaction_with_hash() {
        let signer = create_test_signer();

        let tx = TransactionRequest::default()
            .with_to(
                "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
                    .parse()
                    .unwrap(),
            )
            .with_value(U256::from(1_000_000_000_000_000u128))
            .with_nonce(1)
            .with_chain_id(TEST_CHAIN_ID)
            .with_gas_limit(21000)
            .with_gas_price(2_000_000_000);

        let (raw, hash) = signer
            .sign_transaction_with_hash(tx)
            .await
            .expect("Should sign with hash");

        assert!(!raw.is_empty());
        assert_ne!(hash, B256::ZERO, "Tx hash should not be zero");
    }

    // ── Batch Signing Tests ─────────────────────────────────────────────

    #[test]
    fn test_sign_messages_batch() {
        let signer = create_test_signer();
        let messages: Vec<&[u8]> = vec![b"msg1", b"msg2", b"msg3"];

        let results = signer.sign_messages_batch(&messages);
        assert_eq!(results.len(), 3);

        for (i, result) in results.iter().enumerate() {
            let sig = result.as_ref().expect("Batch sign should succeed");
            assert!(
                signer.verify_message(messages[i], sig),
                "Batch message {} verification failed",
                i
            );
        }
    }

    #[test]
    fn test_sign_hashes_batch() {
        let signer = create_test_signer();
        let hashes = vec![
            B256::repeat_byte(0x01),
            B256::repeat_byte(0x02),
            B256::repeat_byte(0x03),
        ];

        let results = signer.sign_hashes_batch(&hashes);
        assert_eq!(results.len(), 3);

        for (i, result) in results.iter().enumerate() {
            let sig = result.as_ref().expect("Batch hash sign should succeed");
            assert!(
                signer.verify_hash(&hashes[i], sig),
                "Batch hash {} verification failed",
                i
            );
        }
    }

    // ── Verification & Recovery Tests ───────────────────────────────────

    #[test]
    fn test_verify_wrong_message() {
        let signer = create_test_signer();
        let sig = signer.sign_message_sync(b"original").unwrap();
        assert!(!signer.verify_message(b"tampered", &sig));
    }

    #[test]
    fn test_verify_wrong_signer() {
        let signer1 = create_test_signer();
        let signer2 = EvmSigner::new(
            Zeroizing::new(
                hex::decode("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
                    .unwrap(),
            ),
            TEST_CHAIN_ID,
        )
        .unwrap();

        let sig = signer1.sign_message_sync(b"test").unwrap();
        // signer2 should NOT verify signer1's signature
        assert!(!signer2.verify_message(b"test", &sig));
        // But signer1 should
        assert!(signer1.verify_message(b"test", &sig));
    }

    #[test]
    fn test_recover_address_from_message() {
        let signer = create_test_signer();
        let msg = b"Recovery test";
        let sig = signer.sign_message_sync(msg).unwrap();

        let recovered = EvmSigner::recover_address_from_message(msg, &sig).unwrap();
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn test_recover_address_from_hash() {
        let signer = create_test_signer();
        let hash = B256::repeat_byte(0xDE);
        let sig = signer.sign_hash_sync(&hash).unwrap();

        let recovered = EvmSigner::recover_address_from_hash(&hash, &sig).unwrap();
        assert_eq!(recovered, signer.address());
    }

    // ── Signature Encoding / Decoding Tests ─────────────────────────────

    #[test]
    fn test_encode_decode_roundtrip() {
        let signer = create_test_signer();
        let sig = signer.sign_message_sync(b"roundtrip").unwrap();

        let output = EvmSigner::encode_signature(&sig);
        let decoded = EvmSigner::decode_signature(&output.bytes).unwrap();

        // Re-verify with decoded signature
        assert!(signer.verify_message(b"roundtrip", &decoded));
    }

    #[test]
    fn test_decode_signature_hex() {
        let signer = create_test_signer();
        let sig = signer.sign_message_sync(b"hex test").unwrap();
        let output = EvmSigner::encode_signature(&sig);

        let decoded = EvmSigner::decode_signature_hex(&output.to_hex()).unwrap();
        assert!(signer.verify_message(b"hex test", &decoded));
    }

    #[test]
    fn test_decode_invalid_length() {
        assert!(EvmSigner::decode_signature(&[0u8; 64]).is_err());
        assert!(EvmSigner::decode_signature(&[0u8; 66]).is_err());
    }

    #[test]
    fn test_decode_invalid_v() {
        let mut bytes = [0u8; 65];
        bytes[64] = 99; // Invalid v
        assert!(EvmSigner::decode_signature(&bytes).is_err());
    }

    #[test]
    fn test_decode_invalid_hex() {
        assert!(EvmSigner::decode_signature_hex("0xZZZZ").is_err());
        assert!(EvmSigner::decode_signature_hex("not hex").is_err());
    }

    // ── Security Tests ──────────────────────────────────────────────────

    #[test]
    fn test_debug_does_not_leak_private_key() {
        let signer = create_test_signer();
        let debug = format!("{:?}", signer);

        // Private key MUST NOT appear in debug output
        assert!(
            !debug.contains(TEST_PRIVATE_KEY),
            "Debug output leaked private key!"
        );
        assert!(debug.contains("EvmSigner"));
        // Address should be visible
        assert!(
            debug.to_lowercase().contains(&TEST_ADDRESS.to_lowercase()),
            "Debug should contain address"
        );
    }

    #[test]
    fn test_deterministic_signatures() {
        // Same key + same message → same signature (RFC 6979 deterministic k)
        let signer = create_test_signer();
        let msg = b"deterministic";

        let sig1 = signer.sign_message_sync(msg).unwrap();
        let sig2 = signer.sign_message_sync(msg).unwrap();
        assert_eq!(sig1, sig2, "Signatures should be deterministic (RFC 6979)");
    }

    #[test]
    fn test_different_messages_different_signatures() {
        let signer = create_test_signer();
        let sig1 = signer.sign_message_sync(b"alpha").unwrap();
        let sig2 = signer.sign_message_sync(b"bravo").unwrap();
        assert_ne!(
            sig1, sig2,
            "Different messages must produce different signatures"
        );
    }
}
