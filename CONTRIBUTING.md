# Contributing

- [Architecture Decisions](#architecture-decisions)
- [Development Workflow](#development-workflow)
- [Integration Tests with Bitcoin Core](#integration-tests-with-bitcoin-core)
- [Policies](#policies)

We follow the contribution guidelines of [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/CONTRIBUTING.md) unless otherwise stated here.

## Architecture Decisions

Important architectural decisions are documented as Architecture Decision Records (ADRs) in the [`docs/adr/`](docs/adr/) directory. These records explain the rationale behind major design choices and are essential reading for contributors looking to understand the project direction.

- [ADR-0001: Deprecating the V0 API](docs/adr/0001_deprecate_v0_api.md) - Plans for transitioning away from the v0 module to establish v2 as the primary API.

## Development Workflow

We use [`just`](https://just.systems/man/en/) for running development workflow commands. Run `just` from your shell to see the list of available commands.

## Integration Tests with Bitcoin Core

The `bitcoind-tests/` package contains integration tests that run against real Bitcoin Core instances. A separate package is used so that bitcoind version flags don't pollute the rust-psbt crate. The package is not a member of the workspace so that it doesn't effect dependency version resolution.

## Policies

- Use stacked attributes over `#[cfg(all(...))]` when a simple conjunction applies to the same item.

    Good:
    ```rust
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    ```
    Bad:
    ```rust
    #[cfg(all(feature = "alloc", feature = "hex"))]
    ```
