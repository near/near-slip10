#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod path;

pub use crate::path::BIP32Path;

use alloc::boxed::Box;
use core::convert::TryInto;
use core::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The BIP-32 hardened-index bit (`1 << 31`). Indices `>= HARDENED` are hardened.
pub const HARDENED: u32 = 1 << 31;

/// NEAR's BIP-44 coin type (per SLIP-0044).
pub const NEAR_COIN_TYPE: u32 = 397;

/// The default NEAR HD derivation path used by `near-cli-rs` and most NEAR wallets.
pub const NEAR_DEFAULT_HD_PATH: &str = "m/44'/397'/0'";

/// ML-DSA-65 secret key length
pub use near_slip10_mldsa_native_sys::ML_DSA_65_SECRET_KEY_LENGTH;

/// ML-DSA-65 public key length
pub use near_slip10_mldsa_native_sys::ML_DSA_65_PUBLIC_KEY_LENGTH;

/// ML-DSA-65 pubkey handle in bytes
pub const ML_DSA_65_PUBKEY_HANDLE: &[u8] = b"near:ml-dsa-65-pubkey-hash:v1";

/// Returns true if `index` is a hardened BIP-32 index (>= 2^31).
pub const fn is_hardened(index: u32) -> bool {
    index >= HARDENED
}

/// Returns the hardened form of `index`. The argument must be < 2^31; otherwise the result is the same as `index`.
pub const fn harden(index: u32) -> u32 {
    index | HARDENED
}

/// Returns the unhardened (low-31-bit) part of `index`.
pub const fn unharden(index: u32) -> u32 {
    index & !HARDENED
}

#[derive(Debug)]
pub enum Error {
    InvalidIndex,
    InvalidPublicKeyLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidIndex => "Invalid index provided".fmt(f),
            Error::InvalidPublicKeyLength => "Invalid public key length".fmt(f),
        }
    }
}

impl core::error::Error for Error {}

// Create alias for HMAC-SHA512
type HmacSha512 = Hmac<Sha512>;

/// Derives an extended private key for the curve from seed and path as outlined by SLIP-10.
pub fn derive_key_from_path(seed: &[u8], curve: Curve, path: &BIP32Path) -> Result<Key, Error> {
    let master: Result<Key, Error> = Ok(Key::new(seed, curve));

    path.0.iter().fold(master, |key, index| match key {
        Ok(k) => Ok(k.derive_child(*index)?),
        Err(e) => Err(e),
    })
}

#[derive(Clone)]
pub struct Ed25519SecretKey([u8; 32]);

impl Ed25519SecretKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the raw signing key.
    ///
    /// The returned bytes are **not** zeroized on drop - the caller takes over responsibility for
    /// wiping them.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for Ed25519SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Zeroize for Ed25519SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Ed25519SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// A marker trait to indicate that this struct will `Zeroize::zeroize` itself on `Drop`.
impl ZeroizeOnDrop for Ed25519SecretKey {}

#[derive(Clone)]
pub struct MlDsa65SecretKey(Box<[u8; ML_DSA_65_SECRET_KEY_LENGTH]>);

impl MlDsa65SecretKey {
    pub fn as_bytes(&self) -> &[u8; ML_DSA_65_SECRET_KEY_LENGTH] {
        &self.0
    }

    /// Returns the raw signing key.
    ///
    /// The returned bytes are **not** zeroized on drop - the caller takes over responsibility for
    /// wiping them.
    ///
    /// Note that ML-DSA-65 is a 4032 byte-long key, so each call to this function will produce
    /// a copy of this private key in heap.
    pub fn into_bytes(self) -> Box<[u8; ML_DSA_65_SECRET_KEY_LENGTH]> {
        self.0.clone()
    }
}

impl AsRef<[u8]> for MlDsa65SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref().as_ref()
    }
}

impl Zeroize for MlDsa65SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for MlDsa65SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// A marker trait to indicate that this struct will `Zeroize::zeroize` itself on `Drop`.
impl ZeroizeOnDrop for MlDsa65SecretKey {}

#[derive(Clone)]
pub enum PrivateKey {
    Ed25519(Ed25519SecretKey),
    MlDsa65(MlDsa65SecretKey),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsa65PublicKey(Box<[u8; ML_DSA_65_PUBLIC_KEY_LENGTH]>);

impl MlDsa65PublicKey {
    pub fn as_bytes(&self) -> &[u8; ML_DSA_65_PUBLIC_KEY_LENGTH] {
        &self.0
    }

    pub fn into_bytes(self) -> Box<[u8; ML_DSA_65_PUBLIC_KEY_LENGTH]> {
        self.0
    }

    /// Converts full 1952 bytes of MlDsa65PublicKey to public key handle in form of
    /// `SHA3-256(b"near:ml-dsa-65-pubkey-hash:v1" || raw_public_key)`
    pub fn to_public_key_handle(&self) -> [u8; 32] {
        use sha3::Digest;

        let mut digest = sha3::Sha3_256::new_with_prefix(ML_DSA_65_PUBKEY_HANDLE);
        digest.update(self.0.as_ref());
        digest.finalize().into()
    }
}

impl AsRef<[u8]> for MlDsa65PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<&[u8]> for MlDsa65PublicKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value
            .to_vec()
            .into_boxed_slice()
            .try_into()
            .map(Self)
            .map_err(|_| Error::InvalidPublicKeyLength)
    }
}

#[derive(Clone, Debug)]
pub enum PublicKey {
    Ed25519([u8; 33]),
    MlDsa65(MlDsa65PublicKey),
}

impl PublicKey {
    pub fn unwrap_as_ed25519(self) -> [u8; 33] {
        match self {
            PublicKey::Ed25519(pub_key) => pub_key,
            PublicKey::MlDsa65(_) => panic!(),
        }
    }

    pub fn unwrap_as_ml_dsa_65(self) -> MlDsa65PublicKey {
        match self {
            PublicKey::Ed25519(_) => panic!(),
            PublicKey::MlDsa65(pub_key) => pub_key,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Curve {
    Ed25519,
    MlDsa65,
}

impl Curve {
    fn seedkey(&self) -> &[u8] {
        match self {
            Curve::Ed25519 => b"ed25519 seed",
            Curve::MlDsa65 => b"ML-DSA-65 seed",
        }
    }

    fn is_valid_child_index(&self, index: u32) -> bool {
        match self {
            Curve::Ed25519 => index >= HARDENED,
            Curve::MlDsa65 => index >= HARDENED,
        }
    }

    fn private_key(&self, key: &[u8; 32]) -> PrivateKey {
        match self {
            Self::Ed25519 => PrivateKey::Ed25519(Ed25519SecretKey(*key)),
            Self::MlDsa65 => {
                let mut secret_key = [0u8; ML_DSA_65_SECRET_KEY_LENGTH];
                let mut public_key = [0u8; ML_DSA_65_PUBLIC_KEY_LENGTH];

                near_slip10_mldsa_native_sys::ml_dsa_65_keypair_from_seed(key, &mut public_key, &mut secret_key)
                    .expect(
                        "ml-dsa-65 key generation is supplied with appropriate arguments shouldn't fail",
                    );

                public_key.zeroize();

                PrivateKey::MlDsa65(MlDsa65SecretKey(Box::new(secret_key)))
            }
        }
    }

    fn public_key(&self, key: &[u8; 32]) -> PublicKey {
        match self {
            Self::Ed25519 => {
                // We don't clean-up the signing key...? Do we need to..? zeroize feature for ed
                // dalek seems to help with that
                let signing_key: SigningKey = SigningKey::from_bytes(key);
                let public: VerifyingKey = signing_key.verifying_key();
                let mut result = [0u8; 33];
                result[1..].copy_from_slice(&public.to_bytes());
                PublicKey::Ed25519(result)
            }
            Self::MlDsa65 => {
                let mut secret_key = [0u8; ML_DSA_65_SECRET_KEY_LENGTH];
                let mut public_key = [0u8; ML_DSA_65_PUBLIC_KEY_LENGTH];

                near_slip10_mldsa_native_sys::ml_dsa_65_keypair_from_seed(key, &mut public_key, &mut secret_key)
                    .expect(
                        "ml-dsa-65 key generation is supplied with appropriate arguments shouldn't fail",
                    );

                secret_key.zeroize();

                PublicKey::MlDsa65(MlDsa65PublicKey(Box::new(public_key)))
            }
        }
    }
}

/// A SLIP-10 extended private key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key {
    pub key: [u8; 32],
    pub chain_code: [u8; 32],
    #[zeroize(skip)]
    pub curve: Curve,
}

impl Key {
    /// Creates a new master private extended key for the curve from a seed.
    pub fn new(seed: &[u8], curve: Curve) -> Self {
        // Calculate I = HMAC-SHA512(Key = Curve, Data = seed)
        let mut inter = hmac_sha512(curve.seedkey(), seed);

        // Split I into two 32-byte sequences, I_L and I_R
        // Use parse256(I_L) as secret key, and I_R as chain code.
        let key: [u8; 32] = inter[..32].try_into().unwrap();
        let chain_code: [u8; 32] = inter[32..].try_into().unwrap();
        inter.zeroize();

        Self {
            key,
            chain_code,
            curve,
        }
    }

    pub fn secret_key(&self) -> PrivateKey {
        self.curve.private_key(&self.key)
    }

    /// Compute corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        self.curve.public_key(&self.key)
    }

    /// Derive a child key for the given index. For Ed25519 and MlDsa65, only hardened indices (>= 2^31) are valid.
    ///
    /// # Example
    /// ```
    /// use near_slip10::{derive_key_from_path, BIP32Path, Curve, NEAR_DEFAULT_HD_PATH};
    /// use core::str::FromStr;
    ///
    /// let seed = [0u8; 64];
    /// let path = BIP32Path::from_str(NEAR_DEFAULT_HD_PATH).unwrap();
    /// let key = derive_key_from_path(&seed, Curve::Ed25519, &path).unwrap();
    /// assert_eq!(key.key.len(), 32);
    /// ```
    pub fn derive_child(&self, index: u32) -> Result<Key, Error> {
        if !self.curve.is_valid_child_index(index) {
            return Err(Error::InvalidIndex);
        }

        let mut inter = self.get_intermediary(index);

        // Split I into two 32-byte sequences, I_L and I_R
        let key: [u8; 32] = inter[..32].try_into().unwrap();
        let chain_code: [u8; 32] = inter[32..].try_into().unwrap();
        inter.zeroize();

        // Compute the private key from I_L and k_par

        Ok(Key {
            key,
            chain_code,
            curve: self.curve,
        })
    }

    fn get_intermediary(&self, index: u32) -> [u8; 64] {
        let mut data = [0u8; 37]; // 0x00 || k_par || ser32(i)
        data[1..33].copy_from_slice(&self.key);
        data[33..].copy_from_slice(&index.to_be_bytes());

        let inter = hmac_sha512(&self.chain_code, &data);
        data.zeroize();
        inter
    }
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    // Create HMAC-SHA512 instance which implements `Mac` trait
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(feature = "mnemonic")]
pub use mnemonic_impl::{
    derive_ed25519_key_from_mnemonic, derive_key_from_mnemonic, derive_ml_dsa_65_key_from_mnemonic,
    MnemonicError,
};

#[cfg(feature = "mnemonic")]
mod mnemonic_impl {
    use crate::{derive_key_from_path, BIP32Path, Curve, Error, Key};
    use core::fmt;

    /// Derive an MlDsa65 SLIP-10 key from a BIP-39 mnemonic phrase and HD path.
    ///
    /// `passphrase` is the optional BIP-39 passphrase ("25th word"). Use `""` for none.
    ///
    /// # Example
    /// ```
    /// use near_slip10::{derive_ml_dsa_65_key_from_mnemonic, BIP32Path, NEAR_DEFAULT_HD_PATH};
    /// use core::str::FromStr;
    ///
    /// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let path = BIP32Path::from_str(NEAR_DEFAULT_HD_PATH).unwrap();
    /// let key = derive_ml_dsa_65_key_from_mnemonic(phrase, "", &path).unwrap();
    /// let pub_key = key.public_key().unwrap_as_ml_dsa_65();
    /// assert_eq!(pub_key.as_bytes().len(), 1952);
    ///
    /// ```
    pub fn derive_ml_dsa_65_key_from_mnemonic(
        phrase: &str,
        passphrase: &str,
        path: &BIP32Path,
    ) -> Result<Key, MnemonicError> {
        derive_key_from_mnemonic(phrase, passphrase, Curve::MlDsa65, path)
    }

    /// Derive an Ed25519 SLIP-10 key from a BIP-39 mnemonic phrase and HD path.
    ///
    /// `passphrase` is the optional BIP-39 passphrase ("25th word"). Use `""` for none.
    ///
    /// # Example
    /// ```
    /// use near_slip10::{derive_ed25519_key_from_mnemonic, BIP32Path, NEAR_DEFAULT_HD_PATH};
    /// use core::str::FromStr;
    ///
    /// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let path = BIP32Path::from_str(NEAR_DEFAULT_HD_PATH).unwrap();
    /// let key = derive_ed25519_key_from_mnemonic(phrase, "", &path).unwrap();
    /// assert_eq!(key.key.len(), 32);
    /// ```
    pub fn derive_ed25519_key_from_mnemonic(
        phrase: &str,
        passphrase: &str,
        path: &BIP32Path,
    ) -> Result<Key, MnemonicError> {
        derive_key_from_mnemonic(phrase, passphrase, Curve::Ed25519, path)
    }

    /// Derive a specified SLIP-10 key from a BIP-39 mnemonic phrase and HD path.
    ///
    /// `passphrase` is the optional BIP-39 passphrase ("25th word"). Use `""` for none.
    ///
    /// # Example
    /// ```
    /// use near_slip10::{derive_key_from_mnemonic, BIP32Path, Curve, NEAR_DEFAULT_HD_PATH};
    /// use core::str::FromStr;
    ///
    /// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let path = BIP32Path::from_str(NEAR_DEFAULT_HD_PATH).unwrap();
    /// let key = derive_key_from_mnemonic(phrase, "", Curve::Ed25519, &path).unwrap();
    /// assert_eq!(key.key.len(), 32);
    /// ```
    pub fn derive_key_from_mnemonic(
        phrase: &str,
        passphrase: &str,
        curve: Curve,
        path: &BIP32Path,
    ) -> Result<Key, MnemonicError> {
        let mnemonic = bip39::Mnemonic::parse(phrase).map_err(MnemonicError::InvalidMnemonic)?;
        let seed = mnemonic.to_seed(passphrase);
        derive_key_from_path(&seed, curve, path).map_err(MnemonicError::Derivation)
    }

    /// Errors from [`derive_key_from_mnemonic`].
    #[derive(Debug)]
    pub enum MnemonicError {
        /// The provided phrase is not a valid BIP-39 mnemonic.
        InvalidMnemonic(bip39::Error),
        /// SLIP-10 derivation from the seed failed.
        Derivation(Error),
    }

    impl fmt::Display for MnemonicError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                MnemonicError::InvalidMnemonic(e) => write!(f, "invalid mnemonic: {e}"),
                MnemonicError::Derivation(e) => write!(f, "key derivation failed: {e}"),
            }
        }
    }

    impl core::error::Error for MnemonicError {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            match self {
                // `bip39::Error` only implements `core::error::Error` with the `std` feature,
                // which we deliberately don't enable to keep `no_std` builds clean. The error
                // is still rendered via `Display` in our own `Display` impl above.
                MnemonicError::InvalidMnemonic(_) => None,
                MnemonicError::Derivation(e) => Some(e),
            }
        }
    }
}
