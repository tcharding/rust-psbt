// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions.
//!
//! Implementation of the Partially Signed Bitcoin Transaction Format as defined in [BIP-174] and
//! PSBT version 2 as defined in [BIP-370].
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
// Experimental features we need.
#![cfg_attr(bench, feature(test))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions
#![warn(missing_docs)]
// Instead of littering the codebase for non-fuzzing code just globally allow.
#![cfg_attr(fuzzing, allow(dead_code, unused_imports))]
// Exclude clippy lints we don't think are valuable
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134

#[cfg(not(any(feature = "std", feature = "no-std")))]
compile_error!("at least one of the `std` or `no-std` features must be enabled");

#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
extern crate core2;

#[cfg(feature = "serde")]
#[macro_use]
extern crate actual_serde as serde;

/// Re-export of the `rust-bitcoin` crate.
pub extern crate bitcoin;

mod error;
#[macro_use]
mod macros;
#[cfg(feature = "serde")]
mod serde_utils;
mod sighash_type;

pub mod raw;
pub mod serialize;
pub mod v0;

#[cfg(feature = "std")]
use std::io;

#[cfg(not(feature = "std"))]
use core2::io;

#[rustfmt::skip]                // Keep pubic re-exports separate
pub use crate::{
    error::Error,
    sighash_type::PsbtSighashType,
};

#[rustfmt::skip]
mod prelude {
    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc};

    #[cfg(all(not(feature = "std"), not(test), any(not(rust_v_1_60), target_has_atomic = "ptr")))]
    pub use alloc::sync;

    #[cfg(any(feature = "std", test))]
    pub use std::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc, sync};

    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(any(feature = "std", test))]
    pub use std::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    pub use bitcoin::hex::DisplayHex;
}
