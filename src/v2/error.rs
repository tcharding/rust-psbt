// SPDX-License-Identifier: CC0-1.0

//! PSBT v0 errors.

use core::fmt;

use bitcoin::{sighash, FeeRate, Transaction};

use crate::error::{write_err, FundingUtxoError};
use crate::raw;
use crate::v2::map::{global, input, output};
use crate::v2::Psbt;

/// Error while deserializing a PSBT.
///
/// This error is returned when deserializing a complete PSBT, not for deserializing parts
/// of it or individual data types.
#[derive(Debug)]
#[non_exhaustive]
pub enum DeserializePsbtError {
    /// Invalid magic bytes, expected the ASCII for "psbt" serialized in most significant byte order.
    // TODO: Consider adding the invalid bytes.
    InvalidMagic,
    /// The separator for a PSBT must be `0xff`.
    // TODO: Consider adding the invalid separator byte.
    InvalidSeparator,
    /// Signals that there are no more key-value pairs in a key-value map.
    NoMorePairs,
    /// Error decoding the global map.
    DecodeGlobal(global::DecodeError),
    /// Error decoding an input map.
    DecodeInput(input::DecodeError),
    /// Error decoding an output map.
    DecodeOutput(output::DecodeError),
}

impl fmt::Display for DeserializePsbtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { todo!() }
}

#[cfg(feature = "std")]
impl std::error::Error for DeserializePsbtError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { todo!() }
}

impl From<global::DecodeError> for DeserializePsbtError {
    fn from(e: global::DecodeError) -> Self { Self::DecodeGlobal(e) }
}

impl From<input::DecodeError> for DeserializePsbtError {
    fn from(e: input::DecodeError) -> Self { Self::DecodeInput(e) }
}

impl From<output::DecodeError> for DeserializePsbtError {
    fn from(e: output::DecodeError) -> Self { Self::DecodeOutput(e) }
}

/// Error inserting a key-value pair.
#[derive(Debug)]
pub enum InsertPairError {
    /// Known keys must be according to spec.
    InvalidKey(raw::Key),
    /// The pre-image must hash to the correponding psbt hash
    InvalidHashPreimage {
        /// The hash-type causing this error.
        hash_type: HashType,
        /// The hash pre-image.
        preimage: Box<[u8]>,
        /// The hash (should equal hash of the preimage).
        hash: Box<[u8]>,
    },
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(raw::Key),
    /// Key must be excluded from this version of PSBT (see consts.rs for u8 values).
    // TODO: Improve debugging, this u8 is obsure.
    ExcludedKey(u8),
    /// Error deserializing raw value.
    // TODO: This should be a more specific error.
    Deserialize(crate::Error),
}

/// Enum for marking invalid preimage error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum HashType {
    /// The ripemd hash algorithm.
    Ripemd,
    /// The sha-256 hash algorithm.
    Sha256,
    /// The hash-160 hash algorithm.
    Hash160,
    /// The Hash-256 hash algorithm.
    Hash256,
}

impl fmt::Display for InsertPairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { todo!() }
}

#[cfg(feature = "std")]
impl std::error::Error for InsertPairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { todo!() }
}

impl From<crate::Error> for InsertPairError {
    fn from(e: crate::Error) -> Self { Self::Deserialize(e) }
}

/// Input index out of bounds (actual index, maximum index allowed).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndexOutOfBoundsError {
    /// The index is out of bounds for the `psbt.inputs` vector.
    Inputs {
        /// Attempted index access.
        index: usize,
        /// Length of the PBST inputs vector.
        length: usize,
    },
    /// The index greater than the `psbt.global.input_count`.
    Count {
        /// Attempted index access.
        index: usize,
        /// Global input count.
        count: usize,
    },
}

impl fmt::Display for IndexOutOfBoundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IndexOutOfBoundsError::*;

        match *self {
            Inputs { ref index, ref length } => write!(
                f,
                "index {} is out-of-bounds for PSBT inputs vector length {}",
                index, length
            ),
            Count { ref index, ref count } =>
                write!(f, "index {} is greater global.input_count {}", index, count),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IndexOutOfBoundsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use IndexOutOfBoundsError::*;

        match *self {
            Inputs { .. } | Count { .. } => None,
        }
    }
}

/// This error is returned when extracting a [`Transaction`] from a PSBT..
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractTxError {
    /// The [`FeeRate`] is too high
    AbsurdFeeRate {
        /// The [`FeeRate`]
        fee_rate: FeeRate,
        /// The extracted [`Transaction`] (use this to ignore the error)
        tx: Transaction,
    },
    /// One or more of the inputs lacks value information (witness_utxo or non_witness_utxo)
    MissingInputValue {
        /// The extracted [`Transaction`] (use this to ignore the error)
        tx: Transaction,
    },
    /// Input value is less than Output Value, and the [`Transaction`] would be invalid.
    SendingTooMuch {
        /// The original `Psbt` is returned untouched.
        psbt: Psbt,
    },
}

impl fmt::Display for ExtractTxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ExtractTxError::*;

        match *self {
            AbsurdFeeRate { fee_rate, .. } =>
                write!(f, "An absurdly high fee rate of {}", fee_rate),
            MissingInputValue { .. } => write!(
                f,
                "One of the inputs lacked value information (witness_utxo or non_witness_utxo)"
            ),
            SendingTooMuch { .. } => write!(
                f,
                "Transaction would be invalid due to output value being greater than input value."
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExtractTxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ExtractTxError::*;

        match *self {
            AbsurdFeeRate { .. } | MissingInputValue { .. } | SendingTooMuch { .. } => None,
        }
    }
}

/// Errors encountered while calculating the sighash message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignError {
    /// Input index out of bounds.
    IndexOutOfBounds(IndexOutOfBoundsError),
    /// Invalid Sighash type.
    InvalidSighashType,
    /// Missing input utxo.
    MissingInputUtxo,
    /// Missing Redeem script.
    MissingRedeemScript,
    /// Missing spending utxo.
    FundingUtxo(FundingUtxoError),
    /// Missing witness script.
    MissingWitnessScript,
    /// Signing algorithm and key type does not match.
    MismatchedAlgoKey,
    /// Attempted to ECDSA sign an non-ECDSA input.
    NotEcdsa,
    /// The `scriptPubkey` is not a P2WPKH script.
    NotWpkh,
    /// Sighash computation error.
    SighashComputation(sighash::Error),
    /// Unable to determine the output type.
    UnknownOutputType,
    /// Unable to find key.
    KeyNotFound,
    /// Attempt to sign an input with the wrong signing algorithm.
    WrongSigningAlgorithm,
    /// Signing request currently unsupported.
    Unsupported,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SignError::*;

        match *self {
            IndexOutOfBounds(ref e) => write_err!(f, "index out of bounds"; e),
            InvalidSighashType => write!(f, "invalid sighash type"),
            MissingInputUtxo => write!(f, "missing input utxo in PBST"),
            MissingRedeemScript => write!(f, "missing redeem script"),
            FundingUtxo(ref e) => write_err!(f, "input funding utxo error"; e),
            MissingWitnessScript => write!(f, "missing witness script"),
            MismatchedAlgoKey => write!(f, "signing algorithm and key type does not match"),
            NotEcdsa => write!(f, "attempted to ECDSA sign an non-ECDSA input"),
            NotWpkh => write!(f, "the scriptPubkey is not a P2WPKH script"),
            SighashComputation(ref e) => write!(f, "sighash: {}", e),
            UnknownOutputType => write!(f, "unable to determine the output type"),
            KeyNotFound => write!(f, "unable to find key"),
            WrongSigningAlgorithm =>
                write!(f, "attempt to sign an input with the wrong signing algorithm"),
            Unsupported => write!(f, "signing request currently unsupported"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SignError::*;

        match *self {
            SighashComputation(ref e) => Some(e),
            IndexOutOfBounds(ref e) => Some(e),
            FundingUtxo(ref e) => Some(e),
            InvalidSighashType
            | MissingInputUtxo
            | MissingRedeemScript
            | MissingWitnessScript
            | MismatchedAlgoKey
            | NotEcdsa
            | NotWpkh
            | UnknownOutputType
            | KeyNotFound
            | WrongSigningAlgorithm
            | Unsupported => None,
        }
    }
}

impl From<sighash::Error> for SignError {
    fn from(e: sighash::Error) -> Self { Self::SighashComputation(e) }
}

impl From<IndexOutOfBoundsError> for SignError {
    fn from(e: IndexOutOfBoundsError) -> Self { Self::IndexOutOfBounds(e) }
}

impl From<FundingUtxoError> for SignError {
    fn from(e: FundingUtxoError) -> Self { Self::FundingUtxo(e) }
}

/// Error when passing an un-modifiable PSBT to a `Constructor`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PsbtNotModifiableError {
    /// The outputs modifiable flag is not set.
    Outputs(OutputsNotModifiableError),
    /// The inputs modifiable flag is not set.
    Inputs(InputsNotModifiableError),
}

impl fmt::Display for PsbtNotModifiableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PsbtNotModifiableError::*;

        match *self {
            Outputs(ref e) => write_err!(f, "outputs not modifiable"; e),
            Inputs(ref e) => write_err!(f, "inputs not modifiable"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PsbtNotModifiableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use PsbtNotModifiableError::*;

        match *self {
            Outputs(ref e) => Some(e),
            Inputs(ref e) => Some(e),
        }
    }
}

impl From<InputsNotModifiableError> for PsbtNotModifiableError {
    fn from(e: InputsNotModifiableError) -> Self { Self::Inputs(e) }
}

impl From<OutputsNotModifiableError> for PsbtNotModifiableError {
    fn from(e: OutputsNotModifiableError) -> Self { Self::Outputs(e) }
}

/// Error when passing an PSBT with inputs not modifiable to an input adding `Constructor`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InputsNotModifiableError;

impl fmt::Display for InputsNotModifiableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PSBT does not have the inputs modifiable flag set")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InputsNotModifiableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Error when passing an PSBT with outputs not modifiable to an output adding `Constructor`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OutputsNotModifiableError;

impl fmt::Display for OutputsNotModifiableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PSBT does not have the outputs modifiable flag set")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OutputsNotModifiableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// The input is not 100% unsigned.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotUnsignedError {
    /// Input has already been finalized.
    Finalized,
    /// Input already has signature data.
    SigData,
}

impl fmt::Display for NotUnsignedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use NotUnsignedError::*;

        match *self {
            Finalized => f.write_str("input has already been finalized"),
            SigData => f.write_str("input already has signature data"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NotUnsignedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Unable to determine lock time, multiple inputs have conflicting locking requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DetermineLockTimeError;

impl fmt::Display for DetermineLockTimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "unable to determine lock time, multiple inputs have conflicting locking requirements",
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DetermineLockTimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}
