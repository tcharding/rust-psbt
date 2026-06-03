alias ulf := update-lock-files

_default:
  @just --list

# Install workspace tools including rbmt.
[group('system')]
@tools:
  cargo install --quiet --git https://git.rust-bitcoin.org/rust-bitcoin/rust-bitcoin-maintainer-tools --rev $(cat {{justfile_directory()}}/rbmt-version) cargo-rbmt

# Install workspace toolchains.
[group('system')]
@toolchains: tools
  RBMT_LOG_LEVEL=progress cargo rbmt toolchains > /dev/null

# Setup rbmt and run with given args.
@rbmt *args: toolchains
  RBMT_LOG_LEVEL=progress cargo rbmt {{args}}

# Update lock files.
[group('ci')]
@update-lock-files: (rbmt "lock")
  cargo check --manifest-path {{justfile_directory()}}/bitcoind-tests/Cargo.toml
  cargo check --manifest-path {{justfile_directory()}}/fuzz/Cargo.toml

# Format workspace.
[group('ci')]
@fmt: (rbmt "fmt")

# Lint workspace.
[group('ci')]
@lint: (rbmt "lint")

# Bitcoin core integration tests.
[group('ci')]
integration: (rbmt "integration")

# Test bitcoind integration with a bitcoind version.
test-bitcoind version="29_0":
  cd {{justfile_directory()}}/bitcoind-tests && cargo test --features={{version}}
