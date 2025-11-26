#!/usr/bin/env bash
#
# Install rbmt (Rust Bitcoin Maintainer Tools) at the pinned revision.

set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
RBMT_VERSION=$(cat "$REPO_ROOT/rbmt-version")

cargo install --quiet --git https://github.com/rust-bitcoin/rust-bitcoin-maintainer-tools \
    --rev "$RBMT_VERSION" \
    rust-bitcoin-maintainer-tools
