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
  cargo +$(cat ./nightly-version) clippy --all-targets --all-features -- --deny warnings

# Run cargo fmt
fmt:
  cargo +$(cat ./nightly-version) fmt --all

# Generate documentation.
docsrs *flags:
  RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +$(cat ./nightly-version) doc --all-features {{flags}}

# Update the recent and minimal lock files.
update-lock-files:
  contrib/update-lock-files.sh
