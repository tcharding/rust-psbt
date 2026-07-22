alias ulf := update-lock-files

export RBMT_LOG_LEVEL := env("RBMT_LOG_LEVEL", "progress")

_default:
  @just --list

# Install workspace tools including rbmt.
[group('system')]
@tools:
  cargo install --quiet --locked cargo-rbmt@$(grep "^rbmt.version" {{justfile_directory()}}/Cargo.toml | cut -d'"' -f2)
  cargo rbmt toolchains
  cargo rbmt tools

# Setup rbmt and run with given args.
@rbmt *args: tools
  cargo rbmt {{args}}

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
