#![cfg(feature = "mnemonic")]

use core::str::FromStr;
use hex::FromHex;
use near_slip10::{derive_key_from_mnemonic, BIP32Path, NEAR_DEFAULT_HD_PATH};

/// Standard BIP-39 test mnemonic from the BIP-39 spec.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn near_default_path_from_well_known_mnemonic() {
    let path = BIP32Path::from_str(NEAR_DEFAULT_HD_PATH).unwrap();
    let key = derive_key_from_mnemonic(TEST_MNEMONIC, "", &path).unwrap();

    // Pinned vector for the standard BIP-39 "abandon abandon ... about" mnemonic
    // with empty passphrase and NEAR's default path m/44'/397'/0'.
    // Captured from this implementation; verified to match the seed produced by
    // bip39::Mnemonic::to_seed() + SLIP-10 ed25519 derivation.
    let expected_hex = "0c158d858a52316667d03d1d04aad51b3b542cd705215810629b78c501492fba";
    assert_eq!(&key.key[..], &Vec::from_hex(expected_hex).unwrap()[..]);
}

#[test]
fn passphrase_changes_derived_key() {
    let path = BIP32Path::from_str(NEAR_DEFAULT_HD_PATH).unwrap();
    let no_pass = derive_key_from_mnemonic(TEST_MNEMONIC, "", &path).unwrap();
    let with_pass = derive_key_from_mnemonic(TEST_MNEMONIC, "TREZOR", &path).unwrap();
    assert_ne!(no_pass.key, with_pass.key);
}

#[test]
fn invalid_mnemonic_returns_error() {
    let phrase = "not a valid mnemonic phrase at all";
    let path = BIP32Path::from_str(NEAR_DEFAULT_HD_PATH).unwrap();
    assert!(derive_key_from_mnemonic(phrase, "", &path).is_err());
}
