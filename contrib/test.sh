#!/usr/bin/env bash

set -ex

FEATURES="serde base64"
MSRV="1\.56\.1"

cargo --version
rustc --version

# Work out if we are using a nightly toolchain.
NIGHTLY=false
if cargo --version | grep nightly >/dev/null; then
    NIGHTLY=true
fi

# Make all cargo invocations verbose.
export CARGO_TERM_VERBOSE=true

# Defaults / sanity checks.
cargo build
cargo test

if [ "$DO_LINT" = true ]
then
    cargo clippy --locked --all-features --all-targets -- -D warnings
fi

# Test without any features other than std first
cargo test --locked --verbose --no-default-features --features="std"

# Then test with the default features
cargo test --verbose

if [ "$DO_NO_STD" = true ]
then
    # Build no_std, to make sure that cfg(test) doesn't hide any issues
    cargo build --locked --verbose --features="no-std" --no-default-features

    # Build std + no_std, to make sure they are not incompatible
    cargo build --locked --verbose --features="no-std"

    # Test no_std
    cargo test --locked --verbose --features="no-std" --no-default-features

    # Build all features
    cargo build --locked --verbose --features="no-std $FEATURES" --no-default-features

    # Build specific features
    for feature in ${FEATURES}
    do
        cargo build --locked --verbose --features="no-std $feature" --no-default-features
    done
fi

# Test each feature with default enabled ("std").
for feature in ${FEATURES}
do
    cargo test --locked --verbose --features="$feature"
done

# Build the docs if told to (this only works with the nightly toolchain)
if [ "$DO_DOCSRS" = true ]; then
    RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +nightly doc --all-features
fi

# Build the docs if told to (this only works with the nightly toolchain)
if [ "$DO_DOCSRS" = true ]; then
    RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +nightly doc --all-features
fi

# Build the docs with a stable toolchain, in unison with the DO_DOCSRS command
# above this checks that we feature guarded docs imports correctly.
if [ "$DO_DOCS" = true ]; then
    RUSTDOCFLAGS="-D warnings" cargo +stable doc --all-features
fi

# Run formatter if told to.
if [ "$DO_FMT" = true ]; then
    if [ "$NIGHTLY" = false ]; then
        echo "DO_FMT requires a nightly toolchain (consider using RUSTUP_TOOLCHAIN)"
        exit 1
    fi
    rustup component add rustfmt
    cargo fmt --check
fi
