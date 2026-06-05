alias ulf := update-lock-files

export RBMT_LOG_LEVEL := env_var_or_default("RBMT_LOG_LEVEL", "progress")

_default:
  @just --list

# Install workspace tools including rbmt.
[group('system')]
@tools:
  cargo install --quiet --git https://git.rust-bitcoin.org/rust-bitcoin/rust-bitcoin-maintainer-tools --rev $(cat {{justfile_directory()}}/rbmt-version) cargo-rbmt
  cargo rbmt toolchains
  cargo rbmt tools

# Setup rbmt and run with given args.
@rbmt *args: tools
  cargo rbmt {{args}}

# Update the recent and minimal lock files.
[group('ci')]
@update-lock-files: (rbmt "lock")

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
