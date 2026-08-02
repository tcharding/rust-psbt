// SPDX-License-Identifier: CC0-1.0

//! Delegates to consensus encoders for PSBT types.
//!
//! This module contains [`PsbtEncode`] implementations for types
//! that have no PSBT-specific encoding logic and can delegate directly to their
//! consensus [`bitcoin_consensus_encoding::Encode`] implementations.

use bitcoin::Sequence;
use bitcoin_consensus_encoding::Encode;

use super::PsbtEncode;

bitcoin_consensus_encoding::encoder_newtype! {
    /// A wrapper encoder for [`Sequence`] that delegates to its consensus encoding.
    pub struct SequenceEncoder<'e>(<Sequence as Encode>::Encoder<'e>);
}

impl PsbtEncode for Sequence {
    type Encoder<'e>
        = SequenceEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> SequenceEncoder<'_> { SequenceEncoder::new(self.encoder()) }
}
