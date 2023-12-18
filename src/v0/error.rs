// SPDX-License-Identifier: CC0-1.0

//! PSBT v0 errors.

use core::fmt;

use bitcoin::{sighash, FeeRate, Transaction};

use crate::error::{write_err, InconsistentKeySourcesError};
use crate::v0::Psbt;

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
    /// The index is out of bounds for the `psbt.unsigned_tx.input` vector.
    TxInput {
        /// Attempted index access.
        index: usize,
        /// Length of the PBST's unsigned transaction input vector.
        length: usize,
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
            TxInput { ref index, ref length } => write!(
                f,
                "index {} is out-of-bounds for PSBT unsigned tx input vector length {}",
                index, length
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IndexOutOfBoundsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use IndexOutOfBoundsError::*;

        match *self {
            Inputs { .. } | TxInput { .. } => None,
        }
    }
}

/// This error is returned when extracting a [`Transaction`] from a [`Psbt`].
///
/// [`Psbt`]: crate::vo::Psbt
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

/// Errors encountered while doing the signer checks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignerChecksError {
    /// Witness input will produce a non-witness signature.
    NonWitnessSig,
    /// Non-witness input has a mismatch between the txid and prevout txid.
    NonWitnessUtxoTxidMismatch,
    /// Input has both witness and non-witness utxos.
    WitnessAndNonWitnessUtxo,
    /// Redeem script hash did not match the hash in the script_pubkey.
    RedeemScriptMismatch,
    /// Missing witness_utxo.
    MissingTxOut,
    /// Native segwit p2wsh script_pubkey did not match witness script hash.
    WitnessScriptMismatchWsh,
    /// Nested segwit p2wsh script_pubkey did not match redeem script hash.
    WitnessScriptMismatchShWsh,
}

impl fmt::Display for SignerChecksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SignerChecksError::*;

        match *self {
            NonWitnessSig => write!(f, "witness input will produce a non-witness signature"),
            NonWitnessUtxoTxidMismatch =>
                write!(f, "non-witness input has a mismatch between the txid and prevout txid"),
            WitnessAndNonWitnessUtxo => write!(f, "input has both witness and non-witness utxos"),
            RedeemScriptMismatch =>
                write!(f, "redeem script hash did not match the hash in the script_pubkey"),
            MissingTxOut => write!(f, "missing witness_utxo"),
            WitnessScriptMismatchWsh =>
                write!(f, "native segwit p2wsh script_pubkey did not match witness script hash"),
            WitnessScriptMismatchShWsh =>
                write!(f, "nested segwit p2wsh script_pubkey did not match redeem script hash"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignerChecksError {
    // TODO: Match explicitly.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
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
    MissingSpendUtxo,
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
            MissingSpendUtxo => write!(f, "missing spend utxo in PSBT"),
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
            InvalidSighashType
            | MissingInputUtxo
            | MissingRedeemScript
            | MissingSpendUtxo
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
    fn from(e: sighash::Error) -> Self { SignError::SighashComputation(e) }
}

impl From<IndexOutOfBoundsError> for SignError {
    fn from(e: IndexOutOfBoundsError) -> Self { SignError::IndexOutOfBounds(e) }
}

/// Error combining two PSBTs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CombineError {
    /// Attempting to combine with a PSBT describing a different unsigned transaction.
    UnexpectedUnsignedTx {
        /// Expected transaction.
        expected: Transaction,
        /// Actual transaction.
        actual: Transaction,
    },
    /// Global extended public key has inconsistent key sources.
    InconsistentKeySources(InconsistentKeySourcesError),
}

impl fmt::Display for CombineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CombineError::*;

        match *self {
            UnexpectedUnsignedTx { ref expected, ref actual } =>
                write!(f, "combine, transaction differs from actual {:?} {:?}", expected, actual),
            InconsistentKeySources(ref e) =>
                write_err!(f, "combine with inconsistent key sources"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CombineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use CombineError::*;

        match *self {
            UnexpectedUnsignedTx { .. } => None,
            InconsistentKeySources(ref e) => Some(e),
        }
    }
}

impl From<InconsistentKeySourcesError> for CombineError {
    fn from(e: InconsistentKeySourcesError) -> Self { Self::InconsistentKeySources(e) }
}
