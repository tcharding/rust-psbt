// SPDX-License-Identifier: CC0-1.0

//! PSBT v0 errors.

use core::fmt;

use bitcoin::sighash::{self, EcdsaSighashType, NonStandardSighashTypeError};
use bitcoin::{transaction, PublicKey, Txid};

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
    InvalidMagic([u8; 4]),
    /// The separator for a PSBT must be `0xff`.
    InvalidSeparator(Option<u8>),
    /// Signals that there are no more key-value pairs in a key-value map.
    NoMorePairs,
    /// Error decoding the global map.
    DecodeGlobal(global::DecodeError),
    /// Error decoding an input map.
    DecodeInput(input::DecodeError),
    /// Error decoding an output map.
    DecodeOutput(output::DecodeError),
    /// Non-witness UTXO (which is a complete transaction) has a txid that
    /// does not match the transaction input.
    IncorrectNonWitnessUtxo {
        /// The index of the input in question.
        index: usize,
        /// The txid of the input being spent.
        previous_txid: Txid,
        /// The txid of the non-witness UTXO.
        non_witness_utxo_txid: Txid,
    },
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic(ref magic) => write!(f, "invalid magic bytes: {:?}", magic),
            Self::InvalidSeparator(Some(separator)) => {
                write!(f, "invalid separator byte: 0x{:02x}", separator)
            }
            Self::InvalidSeparator(None) => write!(f, "invalid separator byte: missing"),
            Self::NoMorePairs => f.write_str("no more key-value pairs"),
            Self::DecodeGlobal(e) => write!(f, "error decoding global map: {}", e),
            Self::DecodeInput(e) => write!(f, "error decoding input map: {}", e),
            Self::DecodeOutput(e) => write!(f, "error decoding output map: {}", e),
            Self::IncorrectNonWitnessUtxo { index, previous_txid, non_witness_utxo_txid } => {
                write!(
                    f,
                    "non-witness utxo txid is {}, which does not match input {}'s previous txid {}",
                    non_witness_utxo_txid, index, previous_txid
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DeserializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DecodeGlobal(e) => Some(e),
            Self::DecodeInput(e) => Some(e),
            Self::DecodeOutput(e) => Some(e),
            Self::InvalidMagic(_) | Self::InvalidSeparator(_) | Self::NoMorePairs => None,
            Self::IncorrectNonWitnessUtxo { .. } => None,
        }
    }
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
        match self {
            Self::Inputs { ref index, ref length } => write!(
                f,
                "index {} is out-of-bounds for PSBT inputs vector length {}",
                index, length
            ),
            Self::Count { ref index, ref count } =>
                write!(f, "index {} is greater global.input_count {}", index, count),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IndexOutOfBoundsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inputs { .. } | Self::Count { .. } => None,
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
    /// Attempted to ECDSA sign a non-ECDSA input.
    NotEcdsa,
    /// The `scriptPubkey` is not a P2WPKH script.
    NotWpkh,
    /// Sighash computation error (segwit v0 input).
    SegwitV0Sighash(transaction::InputsIndexError),
    /// Sighash computation error (p2wpkh input).
    P2wpkhSighash(sighash::P2wpkhError),
    /// Sighash computation error (taproot input).
    TaprootError(sighash::TaprootError),
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
        match self {
            Self::IndexOutOfBounds(ref e) => write_err!(f, "index out of bounds"; e),
            Self::InvalidSighashType => write!(f, "invalid sighash type"),
            Self::MissingInputUtxo => write!(f, "missing input utxo in PSBT"),
            Self::MissingRedeemScript => write!(f, "missing redeem script"),
            Self::FundingUtxo(ref e) => write_err!(f, "input funding utxo error"; e),
            Self::MissingWitnessScript => write!(f, "missing witness script"),
            Self::MismatchedAlgoKey => write!(f, "signing algorithm and key type does not match"),
            Self::NotEcdsa => write!(f, "attempted to ECDSA sign a non-ECDSA input"),
            Self::NotWpkh => write!(f, "the scriptPubkey is not a P2WPKH script"),
            Self::SegwitV0Sighash(ref e) => write_err!(f, "segwit v0 sighash"; e),
            Self::P2wpkhSighash(ref e) => write_err!(f, "p2wpkh sighash"; e),
            Self::TaprootError(ref e) => write_err!(f, "taproot sighash"; e),
            Self::UnknownOutputType => write!(f, "unable to determine the output type"),
            Self::KeyNotFound => write!(f, "unable to find key"),
            Self::WrongSigningAlgorithm =>
                write!(f, "attempt to sign an input with the wrong signing algorithm"),
            Self::Unsupported => write!(f, "signing request currently unsupported"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SegwitV0Sighash(ref e) => Some(e),
            Self::P2wpkhSighash(ref e) => Some(e),
            Self::TaprootError(ref e) => Some(e),
            Self::IndexOutOfBounds(ref e) => Some(e),
            Self::FundingUtxo(ref e) => Some(e),
            Self::InvalidSighashType
            | Self::MissingInputUtxo
            | Self::MissingRedeemScript
            | Self::MissingWitnessScript
            | Self::MismatchedAlgoKey
            | Self::NotEcdsa
            | Self::NotWpkh
            | Self::UnknownOutputType
            | Self::KeyNotFound
            | Self::WrongSigningAlgorithm
            | Self::Unsupported => None,
        }
    }
}

impl From<sighash::P2wpkhError> for SignError {
    fn from(e: sighash::P2wpkhError) -> Self { Self::P2wpkhSighash(e) }
}

impl From<IndexOutOfBoundsError> for SignError {
    fn from(e: IndexOutOfBoundsError) -> Self { Self::IndexOutOfBounds(e) }
}

impl From<sighash::TaprootError> for SignError {
    fn from(e: sighash::TaprootError) -> Self { Self::TaprootError(e) }
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
        match self {
            Self::Outputs(ref e) => write_err!(f, "outputs not modifiable"; e),
            Self::Inputs(ref e) => write_err!(f, "inputs not modifiable"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PsbtNotModifiableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Outputs(ref e) => Some(e),
            Self::Inputs(ref e) => Some(e),
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
        match self {
            Self::Finalized => f.write_str("input has already been finalized"),
            Self::SigData => f.write_str("input already has signature data"),
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
        match self {
            Self::NonStandardInputSighashType { input_index, ref error } =>
                write_err!(f, "non-standard sighash type for input {} in sighash_type field", input_index; error),
            Self::NonStandardPartialSigsSighashType { input_index, ref error } =>
                write_err!(f, "non-standard sighash type for input {} in partial_sigs", input_index; error),
            Self::WrongSighashFlag { input_index, got, required, pubkey } => write!(
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
        // TODO: Is this correct for a struct error fields?
        match self {
            Self::NonStandardInputSighashType { input_index: _, ref error } => Some(error),
            Self::NonStandardPartialSigsSighashType { input_index: _, ref error } => Some(error),
            Self::WrongSighashFlag { .. } => None,
        }
    }
}
