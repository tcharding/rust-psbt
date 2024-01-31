// SPDX-License-Identifier: CC0-1.0

//! PSBT v0 errors.

use core::fmt;

use bitcoin::sighash::{self, EcdsaSighashType, NonStandardSighashTypeError};
use bitcoin::PublicKey;

use crate::error::{write_err, FundingUtxoError};
use crate::v2::map::{global, input, output};

/// Error while deserializing a PSBT.
///
/// This error is returned when deserializing a complete PSBT, not for deserializing parts
/// of it or individual data types.
#[derive(Debug)]
#[non_exhaustive]
pub enum DeserializeError {
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

impl fmt::Display for DeserializeError {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result { todo!() }
}

#[cfg(feature = "std")]
impl std::error::Error for DeserializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { todo!() }
}

impl From<global::DecodeError> for DeserializeError {
    fn from(e: global::DecodeError) -> Self { Self::DecodeGlobal(e) }
}

impl From<input::DecodeError> for DeserializeError {
    fn from(e: input::DecodeError) -> Self { Self::DecodeInput(e) }
}

impl From<output::DecodeError> for DeserializeError {
    fn from(e: output::DecodeError) -> Self { Self::DecodeOutput(e) }
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
impl std::error::Error for InputsNotModifiableError {}

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

// TODO: Consider creating a type that has input_index and E and simplify all these similar error types?
/// Error checking the partials sigs have correct sighash types.
#[derive(Debug)]
pub enum PartialSigsSighashTypeError {
    /// Non-standard sighash type found in `input.sighash_type` field.
    NonStandardInputSighashType {
        /// The input index with the non-standard sighash type.
        input_index: usize,
        /// The non-standard sighash type error.
        error: NonStandardSighashTypeError,
    },
    /// Non-standard sighash type found in `input.partial_sigs`.
    NonStandardPartialSigsSighashType {
        /// The input index with the non-standard sighash type.
        input_index: usize,
        /// The non-standard sighash type error.
        error: NonStandardSighashTypeError,
    },
    /// Wrong sighash flag in partial signature.
    WrongSighashFlag {
        /// The input index with the wrong sighash flag.
        input_index: usize,
        /// The sighash type we got.
        got: EcdsaSighashType,
        /// The sighash type we require.
        required: EcdsaSighashType,
        /// The associated pubkey (key into the `input.partial_sigs` map).
        pubkey: PublicKey,
    },
}

impl fmt::Display for PartialSigsSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PartialSigsSighashTypeError::*;

        match *self {
            NonStandardInputSighashType { input_index, ref error } =>
                write_err!(f, "non-standard sighash type for input {} in sighash_type field", input_index; error),
            NonStandardPartialSigsSighashType { input_index, ref error } =>
                write_err!(f, "non-standard sighash type for input {} in partial_sigs", input_index; error),
            WrongSighashFlag { input_index, got, required, pubkey } => write!(
                f,
                "wrong sighash flag for input {} (got: {}, required: {}) pubkey: {}",
                input_index, got, required, pubkey
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PartialSigsSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use PartialSigsSighashTypeError::*;

        // TODO: Is this correct for a struct error fields?
        match *self {
            NonStandardInputSighashType { input_index: _, ref error } => Some(error),
            NonStandardPartialSigsSighashType { input_index: _, ref error } => Some(error),
            WrongSighashFlag { .. } => None,
        }
    }
}
