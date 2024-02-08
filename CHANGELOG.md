# 0.1.1 - 2024-02-08

Add various combinations of the three bips as keywords.

# 0.1.0 - 2024-02-08

The initial non-beta release!

Includes some fixes required to enable porting `bdk` to use the `v0` module.

# 0.1.0-beta.1 - 2024-02-08

- Re-import all the PSBT v0 code from `rust-bitcoin` and `rust-miniscript`[#23](https://github.com/tcharding/rust-psbt/pull/23)
- Add initial basic integration testing against Bitcoin Core [#21](https://github.com/tcharding/rust-psbt/pull/21)
  and [#22](https://github.com/tcharding/rust-psbt/pull/22)

# 0.1.0-beta.0 - 2024-02-02

The initial beta release. The aim of this release is to make the new PSBT v2 API available for beta
testing. Currently we expose the v0 API pretty much as it is in `rust-bitcoin` and `rust-miniscript`.

Enjoy!
