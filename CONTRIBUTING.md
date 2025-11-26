# Contributing

We generally follow the contribution guidelines of [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/CONTRIBUTING.md).

## Development Workflow

We use [`just`](https://just.systems/man/en/) for running development workflow commands. Run `just` from your shell to see the list of available commands.

### Git Hooks

To catch errors before running CI, we provide git hooks. To use them:

```bash
git config --local core.hooksPath githooks/
```

Alternatively, add symlinks in your `.git/hooks` directory to any of the githooks we provide.

## Integration Tests with Bitcoin Core

The `bitcoind-tests/` package contains integration tests that run against real Bitcoin Core instances. A separate package is used so that bitcoind version flags don't pollute the rust-psbt crate. The package is not a member of the workspace so that it doesn't effect dependency version resolution.

### NixOS Users

The auto-downloaded Bitcoin Core binaries don't work on NixOS due to dynamic linking requirements. If you're on NixOS you could manually configure the `BITCOIND_EXE` environment variable to use a Nix-provided `bitcoind` of the correct version.
