# Changelog

## [Unreleased]

- Handle multi-byte `keytype`s [#94](https://github.com/rust-bitcoin/rust-psbt/pull/94).

## [0.3.0] - 2026-03-24

The 0.3.0 version is the last major release for `bitcoin v0.32.x`. Only security patches will be added to the v0.3.x branch.

- Bump MSRV to Rust `v1.74.0`.
- Upgrade dependencies and copied implementations.
  - `bitcoin v0.32.8`
  - `miniscript v12.3.5`
- Simplify feature flags.
  - Consolidate miniscript into a single `miniscript` feature
  - Rename `rand-std` to `rand`
  - Remove the `no-std` feature (use `default-features = false` instead).
- Add `silent-payments` feature.

## [0.2.0] - 2024-08-22

- Bump MSRV to Rust `v1.63.0` [#27](https://github.com/tcharding/rust-psbt/pull/27)
- Upgrade dependencies [#26](https://github.com/tcharding/rust-psbt/pull/26)
   - `bitcoin v0.32.0`
   - `miniscript 12.2.0`

## [0.1.1] - 2024-02-08

Add various combinations of the three bips as keywords.

## [0.1.0] - 2024-02-08

The initial non-beta release!

Includes some fixes required to enable porting `bdk` to use the `v0` module.

## [0.1.0-beta.1] - 2024-02-08

- Re-import all the PSBT v0 code from `rust-bitcoin` and `rust-miniscript`[#23](https://github.com/tcharding/rust-psbt/pull/23)
- Add initial basic integration testing against Bitcoin Core [#21](https://github.com/tcharding/rust-psbt/pull/21)
  and [#22](https://github.com/tcharding/rust-psbt/pull/22)

## [0.1.0-beta.0]- 2024-02-02

The initial beta release. The aim of this release is to make the new PSBT v2 API available for beta
testing. Currently we expose the v0 API pretty much as it is in `rust-bitcoin` and `rust-miniscript`.

Enjoy!

[Unreleased]: https://github.com/rust-bitcoin/rust-psbt/compare/psbt-v2-0.3.0...HEAD
[0.3.0]: https://github.com/rust-bitcoin/rust-psbt/compare/psbt-v2-0.2.0...psbt-v2-0.3.0
[0.2.0]: https://github.com/rust-bitcoin/rust-psbt/compare/psbt-v2-0.1.1...psbt-v2-0.2.0
[0.1.1]: https://github.com/rust-bitcoin/rust-psbt/compare/psbt-v2-0.1.0...psbt-v2-0.1.1
[0.1.0]: https://github.com/rust-bitcoin/rust-psbt/compare/0.1.0-beta.1...psbt-v2-0.1.0
[0.1.0-beta.1]: https://github.com/rust-bitcoin/rust-psbt/compare/0.1.0-beta.0...0.1.0-beta.1
[0.1.0-beta.0]: https://github.com/rust-bitcoin/rust-psbt/releases/tag/0.1.0-beta.0
