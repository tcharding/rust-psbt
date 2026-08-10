// SPDX-License-Identifier: CC0-1.0

//! PSBT encoding using the sans-I/O Encoder trait.
//!
//! This module provides PSBT-specific encoding that leverages the
//! [`bitcoin_consensus_encoding::Encoder`] trait for a sans-I/O approach. Unlike consensus
//! encoding, PSBT encoding is specific to the PSBT key-value map format and related structures.

pub mod delegates;
pub mod native;

use alloc::string::String;
use alloc::vec::Vec;

use bitcoin_consensus_encoding::{
    CompactSizeEncoder, DecodeError, Decoder, DecoderStatus, Encoder, Encoder2, EncoderStatus,
    IterEncoder, VecDecoderError, VecDecoderWith,
};

/// Types that can be PSBT-decoded.
///
/// This trait mirrors the structure of [`bitcoin_consensus_encoding::Decode`],
/// but for PSBT-specific decoding semantics (not consensus decoding).
pub trait PsbtDecode: Sized {
    /// The decoder associated with this type.
    type Decoder: Decoder<Output = Self> + Default;

    /// Constructs a PSBT decoder for this type.
    fn psbt_decoder() -> Self::Decoder { Self::Decoder::default() }
}

/// Decodes a PSBT-decodable value from a byte slice.
pub fn decode_from_slice<T: PsbtDecode>(
    bytes: &[u8],
) -> Result<T, DecodeError<<T::Decoder as Decoder>::Error>> {
    bitcoin_consensus_encoding::decode_from_slice_with_decoder::<T::Decoder>(bytes)
}

/// Decodes a PSBT-decodable value from a byte slice, allowing trailing bytes.
pub fn decode_from_slice_unbounded<T: PsbtDecode>(
    bytes: &mut &[u8],
) -> Result<T, <T::Decoder as Decoder>::Error> {
    bitcoin_consensus_encoding::decode_from_slice_unbounded_with_decoder::<T::Decoder>(bytes)
}

/// Decodes a PSBT-decodable value from a buffered reader.
#[cfg(feature = "std")]
pub fn decode_from_reader<T: PsbtDecode, R: std::io::BufRead>(
    reader: R,
) -> Result<T, bitcoin_consensus_encoding::ReadError<<T::Decoder as Decoder>::Error>> {
    bitcoin_consensus_encoding::decode_from_read_with_decoder::<T::Decoder, R>(reader)
}

/// Types that can be PSBT-encoded.
///
/// This trait mirrors the structure of [`bitcoin_consensus_encoding::Encode`],
/// but for PSBT-specific encoding semantics (not consensus encoding).
pub trait PsbtEncode {
    /// The encoder associated with this type.
    type Encoder<'e>: Encoder
    where
        Self: 'e;

    /// Constructs a PSBT encoder for this value.
    fn psbt_encoder(&self) -> Self::Encoder<'_>;
}

/// Encodes a PSBT-encodable value to a vector.
pub fn encode_to_vec<T: PsbtEncode + ?Sized>(value: &T) -> Vec<u8> {
    let mut encoder = value.psbt_encoder();
    bitcoin_consensus_encoding::drain_to_vec(&mut encoder)
}

/// Encodes a PSBT-encodable value to a writer.
#[cfg(feature = "std")]
pub fn encode_to_writer<W: std::io::Write, T: PsbtEncode + ?Sized>(
    writer: &mut W,
    value: &T,
) -> std::io::Result<()> {
    let mut encoder = value.psbt_encoder();
    bitcoin_consensus_encoding::drain_to_writer(&mut encoder, writer)
}

/// Encodes a PSBT-encodable value to a hex string.
pub fn encode_to_hex<T: PsbtEncode + ?Sized>(
    value: &T,
    case: bitcoin_consensus_encoding::hex::Case,
) -> String {
    let encoder = value.psbt_encoder();
    bitcoin_consensus_encoding::drain_to_hex(encoder, case)
}

/// An iterator bridge which maps PSBT encodable items to their encoders.
struct Encoders<'e, T: PsbtEncode> {
    iter: core::slice::Iter<'e, T>,
}

impl<'e, T: PsbtEncode> Iterator for Encoders<'e, T> {
    type Item = T::Encoder<'e>;

    fn next(&mut self) -> Option<T::Encoder<'e>> {
        // A closure is required since the MSRV (1.74.0) cannot infer the `Self: 'e` GAT
        // bound when the method is passed as a bare function item.
        #[allow(clippy::redundant_closure_for_method_calls)]
        self.iter.next().map(|item| item.psbt_encoder())
    }
}

/// An encoder for a slice of PSBT-encodable types without a length prefix.
pub struct SliceEncoder<'e, T: PsbtEncode>(IterEncoder<Encoders<'e, T>>);

impl<'e, T: PsbtEncode> SliceEncoder<'e, T> {
    /// Constructs an encoder which encodes the slice without adding a length prefix.
    ///
    /// To encode with a length prefix, use [`PrefixedSliceEncoder`] instead.
    pub fn without_length_prefix(sl: &'e [T]) -> Self {
        Self(IterEncoder::new(Encoders { iter: sl.iter() }))
    }
}

impl<'e, T: PsbtEncode> Encoder for SliceEncoder<'e, T> {
    fn current_chunk(&self) -> &[u8] { self.0.current_chunk() }

    fn advance(&mut self) -> EncoderStatus { self.0.advance() }
}

/// An encoder for a slice of PSBT-encodable types with a compact size length prefix.
pub struct PrefixedSliceEncoder<'e, T: PsbtEncode>(
    Encoder2<CompactSizeEncoder, SliceEncoder<'e, T>>,
);

impl<'e, T: PsbtEncode> PrefixedSliceEncoder<'e, T> {
    /// Constructs an encoder which encodes the slice, adding a compact size length prefix.
    pub fn new(sl: &'e [T]) -> Self {
        Self(Encoder2::new(
            CompactSizeEncoder::new(sl.len()),
            SliceEncoder::without_length_prefix(sl),
        ))
    }
}

impl<'e, T: PsbtEncode> Encoder for PrefixedSliceEncoder<'e, T> {
    fn current_chunk(&self) -> &[u8] { self.0.current_chunk() }
    fn advance(&mut self) -> EncoderStatus { self.0.advance() }
}

/// A decoder for a vector of PSBT-decodable types with a compact-size length prefix.
///
/// Mirrors [`bitcoin_consensus_encoding::VecDecoder`] but bound to [`PsbtDecode`] instead
/// of [`bitcoin_consensus_encoding::Decode`].
pub struct VecDecoder<T: PsbtDecode>(VecDecoderWith<T::Decoder>);

impl<T: PsbtDecode> VecDecoder<T> {
    /// Constructs a new decoder with the default limit of 4,000,000 elements.
    pub const fn new() -> Self { Self(VecDecoderWith::new()) }

    /// Constructs a new decoder with a custom element limit.
    pub const fn new_with_limit(limit: usize) -> Self {
        Self(VecDecoderWith::new_with_limit(limit))
    }
}

impl<T: PsbtDecode> Default for VecDecoder<T> {
    fn default() -> Self { Self::new() }
}

impl<T: PsbtDecode> Decoder for VecDecoder<T> {
    type Output = Vec<T>;
    type Error = VecDecoderError<<T::Decoder as Decoder>::Error>;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Vec<T>, Self::Error> { self.0.end() }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}
