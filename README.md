# near-slip10

SLIP-0010 ed25519 HD key derivation for the NEAR ecosystem.

[![crates.io](https://img.shields.io/crates/v/near-slip10.svg?style=flat-square)](https://crates.io/crates/near-slip10)
[![docs.rs](https://img.shields.io/docsrs/near-slip10?style=flat-square)](https://docs.rs/near-slip10)
[![CI](https://img.shields.io/github/actions/workflow/status/near/near-slip10/ci.yml?branch=master&style=flat-square)](https://github.com/near/near-slip10/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.81-blue?style=flat-square)](https://blog.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](#license)

## What this is

`near-slip10` is a maintained continuation of the original [`slip10`](https://crates.io/crates/slip10) crate, focused on ed25519 [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) derivation as used by the NEAR Protocol ecosystem. It is `no_std`-compatible and powers HD key derivation in [`near-ledger-rs`](https://github.com/near/near-ledger-rs), [`near-cli-rs`](https://github.com/near/near-cli-rs), and adjacent NEAR tooling.

## Quick start

```rust
use core::str::FromStr;
use near_slip10::{derive_key_from_path, BIP32Path, Curve};

fn main() -> Result<(), near_slip10::Error> {
    // Seed bytes from a BIP-39 mnemonic, e.g. via the `bip39` crate.
    let seed: [u8; 64] = /* ... */;
    let path = BIP32Path::from_str("m/44'/397'/0'")?;
    let key = derive_key_from_path(&seed, Curve::Ed25519, &path)?;

    // `key.key` is the 32-byte ed25519 secret.
    // `key.public_key()` returns 33 bytes: a 0x00 prefix followed by the
    // 32-byte ed25519 public key, per SLIP-10 "Public key derivation".
    Ok(())
}
```

`BIP32Path` accepts both `'` and `H` as hardened markers and round-trips through `Display` as `m/44'/397'/0'`.

## NEAR derivation paths

NEAR's registered BIP-44 coin type is **397** ([SLIP-0044 entry](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)).

- `m/44'/397'/0'` — the default for in-memory seed phrases and most NEAR wallets, including `near-cli-rs`.
- Some wallets (e.g. Meteor, Keystone, Ledger Live) use trailing variations under `44'/397'/...'`. When integrating with a specific wallet, check its documented path rather than assuming the default.

## Supported curves

- Ed25519

secp256k1 support is on the roadmap.

## `no_std`

Works in `no_std` environments with `alloc`.

## Spec compliance

The test suite verifies the official SLIP-10 ed25519 test vectors:

- Test Vector 1, seed `000102030405060708090a0b0c0d0e0f`
- Test Vector 2, the long random seed from the SLIP-0010 spec

## Security

Secret bytes (`Key.key`) are not currently zeroized on drop. This is a known gap tracked for the next minor release. Consumers handling untrusted seeds should wrap derived keys in their own zeroizing container until then.

## Relationship to upstream `slip10`

This crate is a hard fork of the original [`slip10`](https://crates.io/crates/slip10) crate, rebranded as `near-slip10`. The upstream crate has been unmaintained since June 2021. We aim to keep the public surface broadly compatible while modernizing internals and dependencies.

## License

Licensed under MIT.
