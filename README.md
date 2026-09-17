# near-slip10

SLIP-0010 HD key derivation for the NEAR ecosystem: Ed25519 today, ML-DSA-65 (post-quantum) per [NEP-649](https://github.com/near/NEPs/pull/649).

[![crates.io](https://img.shields.io/crates/v/near-slip10.svg?style=flat-square)](https://crates.io/crates/near-slip10)
[![docs.rs](https://img.shields.io/docsrs/near-slip10?style=flat-square)](https://docs.rs/near-slip10)
[![CI](https://img.shields.io/github/actions/workflow/status/near/near-slip10/ci.yml?branch=master&style=flat-square)](https://github.com/near/near-slip10/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue?style=flat-square)](https://blog.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](#license)

## What this is

`near-slip10` is a maintained continuation of the original [`slip10`](https://crates.io/crates/slip10) crate, focused on [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) derivation as used by the NEAR Protocol ecosystem. It is `no_std`-compatible and powers HD key derivation in [`near-ledger-rs`](https://github.com/near/near-ledger-rs), [`near-cli-rs`](https://github.com/near/near-cli-rs), and adjacent NEAR tooling.

Two key types are derived with the same SLIP-10 machinery, selected by `Curve`:

- `Curve::Ed25519` — classic SLIP-0010 ed25519 derivation.
- `Curve::MlDsa65` — deterministic ML-DSA-65 (FIPS 204) key derivation from a BIP-39 seed, as specified by draft NEP-649. The SLIP-10 node secret is used as the 32-byte seed `ξ` for `ML-DSA.KeyGen_internal`.

## Quick start

### Ed25519

```rust
use core::str::FromStr;
use near_slip10::{derive_key_from_path, BIP32Path, Curve, NEAR_DEFAULT_HD_PATH};

fn main() -> Result<(), near_slip10::Error> {
    // Seed bytes from a BIP-39 mnemonic, e.g. via the `bip39` crate or the `mnemonic` feature.
    let seed: [u8; 64] = /* ... */;
    let path = BIP32Path::from_str(NEAR_DEFAULT_HD_PATH)?;
    let key = derive_key_from_path(&seed, Curve::Ed25519, &path)?;

    // `key.key` is the 32-byte ed25519 secret; `key.secret_key()` wraps it in a
    // zeroize-on-drop `Ed25519SecretKey`.
    // `public_key()` returns 33 bytes: a 0x00 prefix followed by the 32-byte
    // ed25519 public key, per SLIP-10 "Public key derivation".
    let public: [u8; 33] = key.public_key().unwrap_as_ed25519();
    Ok(())
}
```

### ML-DSA-65

```rust
use core::str::FromStr;
use near_slip10::{derive_key_from_path, BIP32Path, Curve, NEAR_DEFAULT_HD_PATH, PrivateKey};

fn main() -> Result<(), near_slip10::Error> {
    let seed: [u8; 64] = /* ... */;
    let path = BIP32Path::from_str(NEAR_DEFAULT_HD_PATH)?;
    let key = derive_key_from_path(&seed, Curve::MlDsa65, &path)?;

    // `key.key` is the 32-byte node secret, used as the ML-DSA keygen seed ξ.
    // `secret_key()` runs ML-DSA.KeyGen_internal(ξ) and returns the expanded
    // 4032-byte signing key, heap-allocated and zeroized on drop.
    let secret = key.secret_key().unwrap_as_ml_dsa_65();
    assert_eq!(secret.as_bytes().len(), 4032);

    // The 1952-byte encoded public key, and its NEAR on-chain handle
    // SHA3-256(b"near:ml-dsa-65-pubkey-hash:v1" || pk) as defined by NEP-645.
    let public = key.public_key().unwrap_as_ml_dsa_65();
    let handle: [u8; 32] = public.to_public_key_handle();
    Ok(())
}
```

`BIP32Path` accepts both `'` and `H` as hardened markers and round-trips through `Display` as `m/44'/397'/0'`.

## Cargo features

All features are off by default, keeping the core crate dependency-light and `no_std`.

- `mnemonic` — derive keys directly from a BIP-39 phrase via the `bip39` crate:
  `derive_key_from_mnemonic(phrase, passphrase, curve, &path)`, plus the shorthands
  `derive_ed25519_key_from_mnemonic(phrase, passphrase, &path)` and
  `derive_ml_dsa_65_key_from_mnemonic(phrase, passphrase, &path)`.
- `serde` — `Serialize`/`Deserialize` for `BIP32Path` (as its string form).

```rust
// with `features = ["mnemonic"]`
use core::str::FromStr;
use near_slip10::{derive_ed25519_key_from_mnemonic, BIP32Path, NEAR_DEFAULT_HD_PATH};

fn main() -> Result<(), near_slip10::MnemonicError> {
    // A valid 12-word BIP-39 phrase (here, the canonical all-zero test vector).
    let phrase = "abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon about";
    let path = BIP32Path::from_str(NEAR_DEFAULT_HD_PATH).unwrap();
    // `passphrase` is the optional BIP-39 "25th word"; use "" for none.
    let key = derive_ed25519_key_from_mnemonic(phrase, "", &path)?;

    // `key.key` is the 32-byte ed25519 secret.
    Ok(())
}
```

The mnemonic functions return their own `MnemonicError` (distinct from the `Error` used elsewhere), wrapping invalid-mnemonic and derivation failures.

## NEAR derivation paths

NEAR's registered BIP-44 coin type is **397** ([SLIP-0044 entry](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)).

- `m/44'/397'/0'` — the default for in-memory seed phrases and most NEAR wallets, including `near-cli-rs`.
- Some wallets (e.g. Meteor, Keystone, Ledger Live) use trailing variations under `44'/397'/...'`. When integrating with a specific wallet, check its documented path rather than assuming the default.

For programmatic path construction the crate exports `NEAR_COIN_TYPE` (`397`) and `NEAR_DEFAULT_HD_PATH` (`"m/44'/397'/0'"`), along with the `harden`/`unharden`/`is_hardened` index helpers and `Key::derive_child` for stepping through a path one index at a time.

Both curves are **hardened-only**: `derive_child` returns `Error::InvalidIndex` for any index below `2^31`, as required by SLIP-0010 for ed25519 and by NEP-649 for ML-DSA-65.

## Supported algorithms

| `Curve`   | HMAC key string    | Node secret used as             | Public key                    |
|-----------|--------------------|---------------------------------|-------------------------------|
| `Ed25519` | `"ed25519 seed"`   | ed25519 private scalar seed     | 33 bytes (`0x00` ‖ 32-byte A) |
| `MlDsa65` | `"ML-DSA-65 seed"` | ML-DSA-65 keygen seed `ξ`       | 1952 bytes                    |

The two trees are domain-separated by the HMAC key string, so an ed25519 node secret is never reused as an ML-DSA seed or vice versa.

secp256k1 support is on the roadmap.

## Build requirements

ML-DSA-65 is implemented by [`mldsa-native`](https://github.com/pq-code-package/mldsa-native), a portable C90 implementation, compiled at build time by the companion crate `near-slip10-mldsa-native-sys` (in `mldsa-native-rs/`).

- **A C compiler** is required (`cc`/`gcc`/`clang`, or MSVC on Windows). This is the same requirement as any `-sys` crate.
- **No libclang.** The Rust FFI declarations are pre-generated and committed; `bindgen` only runs when the sys crate is built with its `buildtime_bindgen` feature, which is a maintainer step.
- **`wasm32-unknown-unknown`** is supported: the C is built for wasm with the portable backend and the resulting module has no imports.
- **Building from a git checkout** needs the submodule: `git clone --recurse-submodules`, or `git submodule update --init`. Published crates already contain the C sources.

## `no_std`

Works in `no_std` environments with `alloc`. The C library depends only on `memcpy` and `memset`, which `compiler_builtins` provides on targets without a libc.

## Spec compliance

- **Ed25519**: the test suite verifies the official SLIP-0010 ed25519 test vectors (Test Vector 1, seed `000102030405060708090a0b0c0d0e0f`, and Test Vector 2, the long random seed from the spec).
- **ML-DSA-65**: derivation follows draft NEP-649; the NEP's test vectors are being added to the test suite. The underlying `mldsa-native` library is tested upstream against the NIST ACVP ML-DSA vectors.

## Security

`Key` implements `ZeroizeOnDrop`: the 32-byte node secret (the ed25519 secret, or the ML-DSA keygen seed) and the chain code are wiped from memory when the structure is dropped, and intermediate HMAC outputs are zeroized during derivation.

`Ed25519SecretKey` and `MlDsa65SecretKey`, returned by `Key::secret_key()`, also implement `ZeroizeOnDrop`. The expanded ML-DSA-65 signing key is generated directly into heap storage, so no unwiped stack copy is left behind. Their `into_bytes()` methods hand ownership of the raw bytes to the caller, who then becomes responsible for wiping them.

`mldsa-native` zeroizes its own intermediate buffers per FIPS 204 §3.6.3.

`near-slip10` itself contains no `unsafe` code (`#![forbid(unsafe_code)]`). The single `unsafe` FFI call lives in `near-slip10-mldsa-native-sys`, behind a safe function that takes fixed-size array references.

## Relationship to upstream `slip10`

This crate is a hard fork of the original [`slip10`](https://crates.io/crates/slip10) crate, rebranded as `near-slip10`. The upstream crate has been unmaintained since June 2021. We aim to keep the public surface broadly compatible while modernizing internals and dependencies.

## License

Licensed under MIT. The bundled `mldsa-native` sources are licensed under `Apache-2.0 OR ISC OR MIT`; see `mldsa-native-rs/mldsa-native/LICENSE`.
