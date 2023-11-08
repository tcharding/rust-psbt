# Partially Signed Bitcoin Transactions

Implementation of the Partially Signed Bitcoin Transaction Format as defined in [BIP-174] and
PSBT version 2 as defined in [BIP-370].

## Contributing

For now we more or less just follow the contribution guidelines of 
[rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin/CONTRIBUTING.md).

### Minimum Supported Rust Version (MSRV)

This library should always compile with any combination of features on **Rust 1.63.0**.

To build with the MSRV you will likely need to pin a bunch of dependencies, see `./contrib/test.sh`
for the current list.

### Just

We support [`just`](https://just.systems/man/en/) for running dev workflow commands. Run `just` from
your shell to see list available sub-commands.

### Building the docs

We build docs with the nightly toolchain, you may wish to use the following shell alias to check
your documentation changes build correctly.

```
alias build-docs='RUSTDOCFLAGS="--cfg docsrs" cargo +nightly rustdoc --features="$FEATURES" -- -D rustdoc::broken-intra-doc-links'
```

### Githooks

To assist devs in catching errors _before_ running CI we provide some githooks. If you do not
already have locally configured githooks you can use the ones in this repository by running, in the
root directory of the repository:
```
git config --local core.hooksPath githooks/
```

Alternatively add symlinks in your `.git/hooks` directory to any of the githooks we provide.

### rustfmt

We format with `cargo +nightly fmt`, see `./rusntfmt.toml` for the current configuration.

## License

The code in this project is licensed under the [Creative Commons CC0 1.0 Universal license](LICENSE).
We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX IDs](https://spdx.dev/ids/).



[BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
[BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>
