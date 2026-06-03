//! Bounded, non-cryptographic property tests for `near-slip10`.
//!
//! These exercise parsing/formatting round-trips and panic-freedom of the
//! public API on a wide range of inputs. They are intentionally cheap (default
//! 256 cases each) so they run as part of the normal `cargo test` suite.

use core::str::FromStr;

use near_slip10::{
    derive_key_from_path, harden, is_hardened, unharden, BIP32Path, Curve, HARDENED,
};
use proptest::prelude::*;

proptest! {
    /// (a) A `BIP32Path` built from an arbitrary index vector renders to a
    /// string that parses back into the identical path.
    #[test]
    fn path_string_round_trip(indices in prop::collection::vec(any::<u32>(), 0..=16)) {
        let path = BIP32Path::from(indices);
        let rendered = path.to_string();
        let reparsed = BIP32Path::from_str(&rendered)
            .expect("a rendered BIP32Path must parse back");
        prop_assert_eq!(reparsed, path);
    }

    /// (b) `BIP32Path::from_str` must never panic on arbitrary input — it can
    /// only return `Ok` or `Err`. Exercised with unconstrained strings.
    #[test]
    fn from_str_never_panics_on_arbitrary_strings(s in any::<String>()) {
        let _ = BIP32Path::from_str(&s);
    }

    /// (b) Same invariant, biased toward path-shaped strings so the parser's
    /// happy/error branches get meaningful coverage.
    #[test]
    fn from_str_never_panics_on_pathlike_strings(s in "[m0-9/'H]{0,40}") {
        let _ = BIP32Path::from_str(&s);
    }

    /// (c) Derivation must never panic for arbitrary seeds (including empty and
    /// odd-length seeds) over short hardened-only paths. Ed25519 only permits
    /// hardened indices, so we generate indices in the hardened range.
    #[test]
    fn derive_never_panics(
        seed in prop::collection::vec(any::<u8>(), 0..=128),
        raw_indices in prop::collection::vec(0u32..(1u32 << 31), 0..=8),
    ) {
        let hardened: Vec<u32> = raw_indices.into_iter().map(harden).collect();
        let path = BIP32Path::from(hardened);
        // Result may be Ok or Err, but must not panic.
        let _ = derive_key_from_path(&seed, Curve::Ed25519, &path);
    }

    /// (c) Empty seeds specifically must be accepted by SLIP-10's HMAC and not
    /// panic. (If this ever regresses to a panic, it is a real finding.)
    #[test]
    fn derive_empty_seed_never_panics(
        raw_indices in prop::collection::vec(0u32..(1u32 << 31), 0..=4),
    ) {
        let hardened: Vec<u32> = raw_indices.into_iter().map(harden).collect();
        let path = BIP32Path::from(hardened);
        let key = derive_key_from_path(&[], Curve::Ed25519, &path)
            .expect("empty seed should derive without error");
        prop_assert_eq!(key.key.len(), 32);
        prop_assert_eq!(key.public_key().len(), 33);
    }

    /// (d) `harden`/`unharden` round-trip for any non-hardened index, and the
    /// hardened result is recognised as hardened.
    #[test]
    fn harden_unharden_round_trip(index in 0u32..(1u32 << 31)) {
        let hardened = harden(index);
        prop_assert!(is_hardened(hardened));
        prop_assert!(hardened >= HARDENED);
        prop_assert_eq!(unharden(hardened), index);
    }
}
