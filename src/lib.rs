// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions.
//!
//! Implementation of the Partially Signed Bitcoin Transaction Format as defined in [BIP-174] and
//! PSBT version 2 as defined in [BIP-370].
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>

#![no_std]
#![doc(test(attr(deny(unused))))]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

#[cfg(feature = "arbitrary")]
pub extern crate arbitrary;
pub extern crate bitcoin;
#[cfg(feature = "miniscript")]
pub extern crate miniscript;

mod consts;
mod error;
#[macro_use]
mod macros;
#[cfg(feature = "serde")]
mod serde_utils;
mod sighash_type;
mod version;

pub mod encoding;
pub mod raw;
pub mod serialize;
pub mod v0;
pub mod v2;

use bitcoin::io;

#[rustfmt::skip] // Keep public re-exports separate from private imports.
#[doc(inline)]
pub use crate::{
    error::{InconsistentKeySourcesError, FeeError, FundingUtxoError},
    sighash_type::{PsbtSighashType, InvalidSighashTypeError, ParseSighashTypeError},
    version::{Version, UnsupportedVersionError},
};

/// PSBT version 0 - the original PSBT version.
pub const V0: Version = Version::ZERO;
/// PSBT version 2 - the second PSBT version.
pub const V2: Version = Version::TWO;
