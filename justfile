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
  cargo test --all --all-targets --all-features

# Lint everything.
lint:
  cargo clippy --all --all-targets --all-features -- --deny warnings

# Check the formatting
format:
  cargo +nightly fmt --all --check
