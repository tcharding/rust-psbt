default:
  @just --list

# Cargo check everything.
check:
  cargo check --all --all-targets --all-features

# Cargo build everything.
build:
  cargo build --all --all-targets --all-features

# Cargo test everything.
test:
  cargo test --all-targets --all-features
  cd bitcoind-tests; cargo test

# Lint everything.
lint:
  cargo clippy --all --all-targets --all-features -- --deny warnings

# Run the formatter
fmt:
  cargo +nightly fmt --all

# Check the formatting
format:
  cargo +nightly fmt --all --check
