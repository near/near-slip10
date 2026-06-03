use core::str::FromStr;

use hex::FromHex;
use near_slip10::*;
use serde::Deserialize;

/// One SLIP-0010 spec test vector: a seed plus the expected derivations from it.
#[derive(Deserialize)]
struct TestVector {
    name: String,
    seed: String,
    derivations: Vec<Derivation>,
}

/// A single `(path -> chain code / private / public)` expectation within a vector.
#[derive(Deserialize)]
struct Derivation {
    path: String,
    chain_code: String,
    private: String,
    public: String,
}

/// Spec vectors mirroring the official SLIP-0010 ed25519 tables 1:1.
/// See https://github.com/satoshilabs/slips/blob/master/slip-0010.md
const VECTORS_JSON: &str = include_str!("data/slip10_ed25519_vectors.json");

#[test]
fn test_ed25519() {
    let vectors: Vec<TestVector> =
        serde_json::from_str(VECTORS_JSON).expect("spec vectors fixture must be valid JSON");

    // Guard against an empty/partial fixture silently passing.
    assert_eq!(vectors.len(), 2, "expected both SLIP-0010 test vectors");

    for vector in &vectors {
        let seed = Vec::from_hex(&vector.seed)
            .unwrap_or_else(|_| panic!("vector {} has invalid seed hex", vector.name));

        for d in &vector.derivations {
            let path = BIP32Path::from_str(&d.path)
                .unwrap_or_else(|_| panic!("vector {} has invalid path {}", vector.name, d.path));
            let key = derive_key_from_path(&seed, Curve::Ed25519, &path).unwrap_or_else(|e| {
                panic!(
                    "vector {} path {} failed to derive: {e}",
                    vector.name, d.path
                )
            });

            assert_eq!(
                &key.chain_code[..],
                &Vec::from_hex(&d.chain_code).unwrap()[..],
                "chain code mismatch for {} {}",
                vector.name,
                d.path
            );
            assert_eq!(
                &key.key[..],
                &Vec::from_hex(&d.private).unwrap()[..],
                "private key mismatch for {} {}",
                vector.name,
                d.path
            );
            assert_eq!(
                &key.public_key()[..],
                &Vec::from_hex(&d.public).unwrap()[..],
                "public key mismatch for {} {}",
                vector.name,
                d.path
            );
        }
    }
}
