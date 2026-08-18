set quiet := true

alias ulf := update-lock-files
alias ms := mutants-since
alias mi := mutants-in

export RBMT_LOG_LEVEL := env("RBMT_LOG_LEVEL", "progress")

project := file_name(justfile_directory())
rbmt_version := `grep "^rbmt.version" Cargo.toml | cut -d'"' -f2`

_default:
  @just --list

# Install workspace tools including rbmt
[group('system')]
tools:
  echo "{{project}} dev tools [cargo-rbmt@{{rbmt_version}}]"
  cargo install --quiet --locked cargo-rbmt@{{rbmt_version}}
  cargo rbmt toolchains
  cargo rbmt tools

# Run rbmt with given args
rbmt *args: tools
  cargo rbmt {{args}}

# Update lock files
update-lock-files: (rbmt "lock")

# Check docs
[group('ci')]
docs: (rbmt "docs --lockfile maximum")

# Format workspace
[group('ci')]
fmt: (rbmt "fmt")

# Lint workspace
[group('ci')]
lint: (rbmt "lint")

# Test package on minimal dependency versions
[group('ci')]
test: (rbmt "test --lockfile minimal")

# Check prerelease
[group('ci')]
prerelease: (rbmt "prerelease --force")

# Bitcoin Core integration tests
[group('ci')]
integration: (rbmt "integration")

# Check mutants in code changed since baseline
[group('mutants')]
mutants-since baseline="master": tools
  git diff {{baseline}} | cargo +$(cargo rbmt toolchains --stable) mutants --in-diff /dev/stdin

# Run mutants in a file or glob
[group('mutants')]
mutants-in glob: tools
  cargo +$(cargo rbmt toolchains --stable) mutants --file '{{glob}}'
