#!/usr/bin/env bash

set -ex

FEATURES="std"
MSRV="1\.63\.0"

cargo --version
rustc --version

# Work out if we are using a nightly toolchain.
NIGHTLY=false
if cargo --version | grep nightly >/dev/null; then
    NIGHTLY=true
fi

# Pin dependencies require to build with MSRV.
if cargo --version | grep ${MSRV}; then
    #
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

# Test with no default features.
cargo build --locked --no-default-features
cargo test --locked --no-default-features

# Test the std feature.
cargo build --locked --no-default-features --features=std
cargo test --locked --no-default-features --features=std

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
