set quiet := true

alias ulf := update-lock-files

export RBMT_LOG_LEVEL := env("RBMT_LOG_LEVEL", "progress")

project := file_name(justfile_directory())
rbmt_version := `grep "^rbmt.version" Cargo.toml | cut -d'"' -f2`

_default:
  @just --list

# Install workspace tools including rbmt.
[group('system')]
tools:
  echo "{{project}} dev tools [cargo-rbmt@{{rbmt_version}}]"
  cargo install --quiet --locked cargo-rbmt@{{rbmt_version}}
  cargo rbmt toolchains
  cargo rbmt tools

# Setup rbmt and run with given args.
rbmt *args: tools
  cargo rbmt {{args}}

# Update lock files.
[group('ci')]
update-lock-files: (rbmt "lock")

# Check docs
[group('ci')]
docs: (rbmt "docs --lockfile maximum")

# Format workspace.
[group('ci')]
fmt: (rbmt "fmt")

# Lint workspace.
[group('ci')]
lint: (rbmt "lint")

# Test package on minimal dependency versions
[group('ci')]
test: (rbmt "test --lockfile minimal")

# Check prerelease
[group('ci')]
prerelease: (rbmt "prerelease --force")

# Bitcoin core integration tests.
[group('ci')]
integration: (rbmt "integration")

# Test bitcoind integration with a bitcoind version.
test-bitcoind version="29_0":
  cd {{justfile_directory()}}/bitcoind-tests && cargo test --features={{version}}
