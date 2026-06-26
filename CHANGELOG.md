# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0](https://github.com/near/near-slip10/compare/v0.4.8...v0.5.0) - 2026-06-26

### Added

- serde feature for BIP32Path ([#13](https://github.com/near/near-slip10/pull/13))
- mnemonic feature with bip39 integration ([#11](https://github.com/near/near-slip10/pull/11))
- add NEAR helpers ([#10](https://github.com/near/near-slip10/pull/10))
- zeroize Key on drop ([#9](https://github.com/near/near-slip10/pull/9))

### Other

- update README for zeroize, mnemonic feature, helpers ([#17](https://github.com/near/near-slip10/pull/17))
- structured fixtures + proptest ([#15](https://github.com/near/near-slip10/pull/15))
- *(deps)* bump actions/attest-build-provenance from 1 to 4 ([#20](https://github.com/near/near-slip10/pull/20))
- *(deps)* bump actions/checkout from 6 to 7 ([#19](https://github.com/near/near-slip10/pull/19))
- cargo-hack feature powerset + checkout v6 ([#16](https://github.com/near/near-slip10/pull/16))
- repo hygiene (SECURITY.md, dependabot, PR template, cargo-deny) ([#14](https://github.com/near/near-slip10/pull/14))
- bump MSRV badge 1.81 → 1.85 ([#8](https://github.com/near/near-slip10/pull/8))
- bump hmac 0.9 → 0.13, sha2 0.9 → 0.11 ([#7](https://github.com/near/near-slip10/pull/7))
- tidy internals ([#6](https://github.com/near/near-slip10/pull/6))

## [0.4.8](https://github.com/near/near-slip10/compare/v0.4.7...v0.4.8) - 2026-05-06

### Other

- rewrite README ([#2](https://github.com/near/near-slip10/pull/2))
- trusted publishing to crates.io via release-plz + OIDC ([#3](https://github.com/near/near-slip10/pull/3))
- add GitHub Actions workflow on WarpBuild ([#1](https://github.com/near/near-slip10/pull/1))
- add CODEOWNERS ([#4](https://github.com/near/near-slip10/pull/4))
