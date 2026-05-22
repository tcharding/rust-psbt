# Deprecating the V0 API

* Status: in-progress
* Date: 2026-05-22

## Context

The `rust-psbt` crate maintains two PSBT implementations, v0 ([BIP-0174]) module which is mostly copied from `rust-bitcoin`'s `v0.32.x` branch, and a fresh full-featured v2 ([BIP-0370]) module. The v0 module's original goal was to match the legacy `rust-bitcoin` implementation, making it easier for users to switch to this new crate.

However, maintaining two modules is a significant burden (see issues [#68] and [#122]). The v0 module contains v0-specific codecs, but its v0-specific API does not offer anything over the new v2 one. Yet both versions require parallel test coverage, examples, and documentation.

We have made the call that the `v0.3.x` versions of `rust-psbt` are the last to be tied to `bitcoin` v0.32.x. Moving forward, there will be breaking changes in `rust-psbt` as it adopts newer stabilized versions of the `bitcoin` crate(s). Since we are moving on from `v0.32.x`, the original reason for the v0 module interface, what should we do with v0 going forward?

## Options

### Option 1: Keep Both Modules Indefinitely

Maximum backward compatibility, but continued maintenance burden and a large API surface. Users must choose between two APIs. v0 ([BIP-0174]) and v2 ([BIP-0370]) have fundamentally different structures (modifiable inputs/outputs, different global map fields, role-based APIs). Merging them into a single interface would require compromising one design or the other.

### Option 2: Remove v0 Entirely

Simplifies codebase, but breaks users who need to handle v0 PSBTs and loses the ability to generate v0 output. Projects like Payjoin (issue [#31]) need the ability to convert v2 to v0 for compatibility with existing protocols.

### Option 3: Gut v0 to Codec-Only

Reduce v0 to pure serialization/deserialization with no public types. Users deserialize v0 bytes into v2 for manipulation, and can serialize v2 back to v0 for output. This eliminates code duplication while maintaining backwards compatibility, and establishes v2 as the primary interface.

The *Backwards Compatibility* section from [BIP-0370] provides some insight on why this is a practical approach, with the last line emphasized.

> PSBTv2 shares the same generic format as PSBTv0 as defined in BIP 174. Parsers for PSBTv0 should be able to deserialize PSBTv2 with only changes to support the new fields.
>
> However PSBTv2 is incompatible with PSBTv0, and vice versa due to the use of the PSBT_GLOBAL_VERSION. This incompatibility is intentional so that PSBT_GLOBAL_UNSIGNED_TX could be removed in PSBTv2. **However it is possible to convert a PSBTv2 to a PSBTv0 by creating an unsigned transaction from the PSBTv2 fields.**

All v0-to-v2 and v2-to-v0 complexity should be isolated on the edges in the codec, instead of across the modules entire API (option #2) or duplicated (option #1).

## Design

We are moving forward with [Option 3: Gut v0 to Codec-Only](#option-3-gut-v0-to-codec-only).

The goal is for `v2::Psbt` to become the only first-class API of the package. As we release breaking changes of rust-psbt (e.g. `v0.4.0`), we remove the v0 module's public interface, leaving only internal codec functionality for serialization/deserialization v0 PSBTs.

It should be noted that v2-to-v0 functionality could potentially be lossy and this will have to be well documented for end users.

[#31]: https://git.rust-bitcoin.org/rust-bitcoin/rust-psbt/issues/31
[#68]: https://git.rust-bitcoin.org/rust-bitcoin/rust-psbt/issues/68
[#122]: https://git.rust-bitcoin.org/rust-bitcoin/rust-psbt/issues/122
[BIP-0174]: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
[BIP-0370]: https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki
