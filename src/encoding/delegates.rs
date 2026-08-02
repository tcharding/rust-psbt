// SPDX-License-Identifier: CC0-1.0

//! Delegates to consensus encoders for PSBT types.
//!
//! This module contains [`PsbtEncode`] implementations for types
//! that have no PSBT-specific encoding logic and can delegate directly to their
//! consensus [`bitcoin_consensus_encoding::Encode`] implementations.

use bitcoin::Sequence;
use bitcoin_consensus_encoding::Encode;

use super::PsbtEncode;

/// Marker trait for types that delegate consensus encoding to PSBT.
///
/// Types implementing this trait have no PSBT-specific encoding logic and can
/// delegate directly to their consensus encoder via the blanket [`PsbtEncode`]
/// implementation.
trait PsbtDelegate: Encode {}

/// Blanket implementation for types that delegate to consensus encoding.
///
/// Any type implementing [`PsbtDelegate`] automatically implements [`PsbtEncode`]
/// by delegating to its consensus encoder.
impl<T: PsbtDelegate> PsbtEncode for T {
    type Encoder<'e>
        = <T as Encode>::Encoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> { self.encoder() }
}

/// [`Sequence`] uses its consensus encoding for PSBT.
impl PsbtDelegate for Sequence {}
