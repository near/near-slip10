#![cfg(feature = "serde")]

use core::str::FromStr;
use near_slip10::BIP32Path;

#[test]
fn serialize_uses_string_representation() {
    let path = BIP32Path::from_str("m/44'/397'/0'").unwrap();
    let json = serde_json::to_string(&path).unwrap();
    assert_eq!(json, "\"m/44'/397'/0'\"");
}

#[test]
fn deserialize_from_string_representation() {
    let path: BIP32Path = serde_json::from_str("\"m/44'/397'/0'\"").unwrap();
    assert_eq!(path, BIP32Path::from_str("m/44'/397'/0'").unwrap());
}

#[test]
fn round_trips() {
    let path = BIP32Path::from_str("m/44'/397'/0'").unwrap();
    let json = serde_json::to_string(&path).unwrap();
    let decoded: BIP32Path = serde_json::from_str(&json).unwrap();
    assert_eq!(path, decoded);
}

#[test]
fn deserialize_invalid_string_errors() {
    let result: Result<BIP32Path, _> = serde_json::from_str("\"not-a-path\"");
    assert!(result.is_err());
}
