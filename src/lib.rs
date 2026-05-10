#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod path;

pub use crate::path::BIP32Path;

use alloc::vec::Vec;
use core::convert::TryInto;
use core::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;

pub(crate) const HARDENED: u32 = 1 << 31;

#[derive(Debug)]
pub enum Error {
    InvalidIndex,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidIndex => "Invalid index provided".fmt(f),
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
        Ok(k) => Ok(k.generate_child_key(*index)?),
        Err(e) => Err(e),
    })
}

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Curve {
    Ed25519,
}

impl Curve {
    fn seedkey(&self) -> &[u8] {
        match self {
            Curve::Ed25519 => b"ed25519 seed",
        }
    }

    fn validate_child_index(&self, index: u32) -> bool {
        match self {
            Curve::Ed25519 => index < HARDENED,
        }
    }

    fn public_key(&self, key: &[u8; 32]) -> [u8; 33] {
        match self {
            Curve::Ed25519 => {
                let signing_key: SigningKey = SigningKey::from_bytes(key);
                let public: VerifyingKey = signing_key.verifying_key();
                let mut result = [0u8; 33];
                result[1..].copy_from_slice(&public.to_bytes());
                result
            }
        }
    }
}

/// A SLIP-10 extended private key.
pub struct Key {
    pub key: [u8; 32],
    pub chain_code: [u8; 32],
    pub curve: Curve,
}

impl Key {
    /// Creates a new master private extended key for the curve from a seed.
    pub fn new(seed: &[u8], curve: Curve) -> Self {
        // Calculate I = HMAC-SHA512(Key = Curve, Data = seed)
        let inter = hmac_sha512(curve.seedkey(), seed);

        // Split I into two 32-byte sequences, I_L and I_R
        // Use parse256(I_L) as secret key, and I_R as chain code.
        let key: [u8; 32] = inter[..32].try_into().unwrap();
        let chain_code: [u8; 32] = inter[32..].try_into().unwrap();

        Self {
            key,
            chain_code,
            curve,
        }
    }

    /// Compute corresponding public key.
    pub fn public_key(&self) -> [u8; 33] {
        self.curve.public_key(&self.key)
    }

    fn generate_child_key(&self, index: u32) -> Result<Key, Error> {
        if self.curve.validate_child_index(index) {
            return Err(Error::InvalidIndex);
        }

        let inter = self.get_intermediary(index);

        // Split I into two 32-byte sequences, I_L and I_R
        let key: [u8; 32] = inter[..32].try_into().unwrap();
        let chain_code: [u8; 32] = inter[32..].try_into().unwrap();

        // Compute the private key from I_L and k_par

        Ok(Key {
            key,
            chain_code,
            curve: self.curve,
        })
    }

    fn get_intermediary(&self, index: u32) -> [u8; 64] {
        let mut data = Vec::new();
        if index < HARDENED {
            data.extend_from_slice(&self.curve.public_key(&self.key));
        } else {
            data.push(0u8);
            self.key.iter().for_each(|i| data.push(*i));
        }
        index.to_be_bytes().iter().for_each(|i| data.push(*i));

        hmac_sha512(&self.chain_code, &data)
    }
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    // Create HMAC-SHA512 instance which implements `Mac` trait
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
