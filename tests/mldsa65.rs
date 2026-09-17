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
    node_secret: String,
    private_key: String,
    public_key: String,
}

/// Spec vectors mirroring the NEP-649 json test vectors.
/// See https://github.com/near/NEPs/pull/649
const VECTORS_JSON: &str = include_str!("data/slip10_ml_dsa_65_vectors.json");

#[test]
fn test_mldsa65() {
    let vectors: Vec<TestVector> =
        serde_json::from_str(VECTORS_JSON).expect("spec vectors fixture must be valid JSON");

    // Guard against an empty/partial fixture silently passing.
    assert_eq!(vectors.len(), 2, "expected both SLIP-0010 test vectors");

    // Each official mldsa65 vector has exactly 6 derivation rows. Without this
    // per-vector guard, a vector with an empty `derivations` array would skip its
    // inner loop and the test would still pass vacuously.
    let mut checked_derivations = 0usize;

    for vector in &vectors {
        assert_eq!(
            vector.derivations.len(),
            6,
            "vector {} should have 6 derivation rows",
            vector.name
        );

        let seed = Vec::from_hex(&vector.seed)
            .unwrap_or_else(|_| panic!("mldsa65 vector {} hash invalid seed hex", vector.name));

        for d in &vector.derivations {
            checked_derivations += 1;

            let path = BIP32Path::from_str(&d.path)
                .unwrap_or_else(|_| panic!("vector {} has invalid path {}", vector.name, d.path));
            let key = derive_key_from_path(&seed, Curve::MlDsa65, &path).unwrap_or_else(|e| {
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
                &Vec::from_hex(&d.node_secret).unwrap()[..],
                "private key mismatch for {} {}",
                vector.name,
                d.path
            );
            assert_eq!(
                key.secret_key().unwrap_as_ml_dsa_65().as_ref(),
                &Vec::from_hex(&d.private_key).unwrap()[..],
                "private key mismatch for {} {}",
                vector.name,
                d.path
            );
            assert_eq!(
                key.public_key().unwrap_as_ml_dsa_65().as_ref(),
                &Vec::from_hex(&d.public_key).unwrap()[..],
                "public key mismatch for {} {}",
                vector.name,
                d.path
            );
        }
    }

    // Belt-and-suspenders: confirm we actually exercised every spec row (2 × 6).
    assert_eq!(
        checked_derivations, 12,
        "expected to check all 12 SLIP-0010 ed25519 derivations"
    );
}
