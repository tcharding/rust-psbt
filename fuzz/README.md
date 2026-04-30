# Rust PSBT Fuzzing

Fuzzing targets for the rust-psbt library.

The [`cargo-fuzz`](https://docs.rs/crate/cargo-fuzz/latest) subcommand and conventions are followed. `cargo-fuzz` requires a *nightly* toolchain for some unstable flags. The `libfuzzer-sys` dependency integrates with a C compiler, so the system is *required* to have one.
