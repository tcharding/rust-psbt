// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use crate::bitcoin::{sighash, ScriptBuf};
use crate::miniscript::{self, descriptor, interpreter};
use crate::prelude::*;
#[cfg(doc)]
use crate::v0::Psbt;

/// Error type for entire Psbt
#[derive(Debug)]
pub enum Error {
    /// Input Error type
    InputError(InputError, usize),
    /// Wrong Input Count
    WrongInputCount {
        /// Input count in tx
        in_tx: usize,
        /// Input count in psbt
        in_map: usize,
    },
    /// Psbt Input index out of bounds
    InputIdxOutofBounds {
        /// Inputs in pbst
        psbt_inp: usize,
        /// requested index
        index: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InputError(ref inp_err, index) => write!(f, "{} at index {}", inp_err, index),
            Error::WrongInputCount { in_tx, in_map } => {
                write!(f, "PSBT had {} inputs in transaction but {} inputs in map", in_tx, in_map)
            }
            Error::InputIdxOutofBounds { psbt_inp, index } => write!(
                f,
                "psbt input index {} out of bounds: psbt.inputs.len() {}",
                index, psbt_inp
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        use self::Error::*;

        match self {
            InputError(e, _) => Some(e),
            WrongInputCount { .. } | InputIdxOutofBounds { .. } => None,
        }
    }
}

/// Error type for Pbst Input
#[derive(Debug)]
pub enum InputError {
    /// Get the secp Errors directly
    SecpErr(bitcoin::secp256k1::Error),
    /// Key errors
    KeyErr(bitcoin::key::Error),
    /// Could not satisfy taproot descriptor
    /// This error is returned when both script path and key paths could not be
    /// satisfied. We cannot return a detailed error because we try all miniscripts
    /// in script spend path, we cannot know which miniscript failed.
    CouldNotSatisfyTr,
    /// Error doing an interpreter-check on a finalized psbt
    Interpreter(interpreter::Error),
    /// Redeem script does not match the p2sh hash
    InvalidRedeemScript {
        /// Redeem script
        redeem: ScriptBuf,
        /// Expected p2sh Script
        p2sh_expected: ScriptBuf,
    },
    /// Witness script does not match the p2wsh hash
    InvalidWitnessScript {
        /// Witness Script
        witness_script: ScriptBuf,
        /// Expected p2wsh script
        p2wsh_expected: ScriptBuf,
    },
    /// Invalid sig
    InvalidSignature {
        /// The bitcoin public key
        pubkey: bitcoin::PublicKey,
        /// The (incorrect) signature
        sig: Vec<u8>,
    },
    /// Pass through the underlying errors in miniscript
    MiniscriptError(miniscript::Error),
    /// Missing redeem script for p2sh
    MissingRedeemScript,
    /// Missing witness
    MissingWitness,
    /// used for public key corresponding to pkh/wpkh
    MissingPubkey,
    /// Missing witness script for segwit descriptors
    MissingWitnessScript,
    ///Missing both the witness and non-witness utxo
    MissingUtxo,
    /// Non empty Witness script for p2sh
    NonEmptyWitnessScript,
    /// Non empty Redeem script
    NonEmptyRedeemScript,
    /// Non Standard sighash type
    NonStandardSighashType(sighash::NonStandardSighashTypeError),
    /// Sighash did not match
    WrongSighashFlag {
        /// required sighash type
        required: sighash::EcdsaSighashType,
        /// the sighash type we got
        got: sighash::EcdsaSighashType,
        /// the corresponding publickey
        pubkey: bitcoin::PublicKey,
    },
}

#[cfg(feature = "std")]
impl std::error::Error for InputError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        use self::InputError::*;

        match self {
            CouldNotSatisfyTr
            | InvalidRedeemScript { .. }
            | InvalidWitnessScript { .. }
            | InvalidSignature { .. }
            | MissingRedeemScript
            | MissingWitness
            | MissingPubkey
            | MissingWitnessScript
            | MissingUtxo
            | NonEmptyWitnessScript
            | NonEmptyRedeemScript
            | NonStandardSighashType(_)
            | WrongSighashFlag { .. } => None,
            SecpErr(e) => Some(e),
            KeyErr(e) => Some(e),
            Interpreter(e) => Some(e),
            MiniscriptError(e) => Some(e),
        }
    }
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            InputError::InvalidSignature { ref pubkey, ref sig } => {
                write!(f, "PSBT: bad signature {} for key {:?}", pubkey, sig)
            }
            InputError::KeyErr(ref e) => write!(f, "Key Err: {}", e),
            InputError::Interpreter(ref e) => write!(f, "Interpreter: {}", e),
            InputError::SecpErr(ref e) => write!(f, "Secp Err: {}", e),
            InputError::InvalidRedeemScript { ref redeem, ref p2sh_expected } => write!(
                f,
                "Redeem script {} does not match the p2sh script {}",
                redeem, p2sh_expected
            ),
            InputError::InvalidWitnessScript { ref witness_script, ref p2wsh_expected } => write!(
                f,
                "Witness script {} does not match the p2wsh script {}",
                witness_script, p2wsh_expected
            ),
            InputError::MiniscriptError(ref e) => write!(f, "Miniscript Error: {}", e),
            InputError::MissingWitness => write!(f, "PSBT is missing witness"),
            InputError::MissingRedeemScript => write!(f, "PSBT is Redeem script"),
            InputError::MissingUtxo => {
                write!(f, "PSBT is missing both witness and non-witness UTXO")
            }
            InputError::MissingWitnessScript => write!(f, "PSBT is missing witness script"),
            InputError::MissingPubkey => write!(f, "Missing pubkey for a pkh/wpkh"),
            InputError::NonEmptyRedeemScript => {
                write!(f, "PSBT has non-empty redeem script at for legacy transactions")
            }
            InputError::NonEmptyWitnessScript => {
                write!(f, "PSBT has non-empty witness script at for legacy input")
            }
            InputError::WrongSighashFlag { required, got, pubkey } => write!(
                f,
                "PSBT: signature with key {:?} had \
                 sighashflag {:?} rather than required {:?}",
                pubkey, got, required
            ),
            InputError::CouldNotSatisfyTr => write!(f, "Could not satisfy Tr descriptor"),
            InputError::NonStandardSighashType(ref e) =>
                write!(f, "Non-standard sighash type {}", e),
        }
    }
}

#[doc(hidden)]
impl From<crate::miniscript::Error> for InputError {
    fn from(e: crate::miniscript::Error) -> InputError { InputError::MiniscriptError(e) }
}

#[doc(hidden)]
impl From<bitcoin::secp256k1::Error> for InputError {
    fn from(e: bitcoin::secp256k1::Error) -> InputError { InputError::SecpErr(e) }
}

#[doc(hidden)]
impl From<bitcoin::key::Error> for InputError {
    fn from(e: bitcoin::key::Error) -> InputError { InputError::KeyErr(e) }
}

/// Return error type for [`Psbt::update_input_with_descriptor`]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UtxoUpdateError {
    /// Index out of bounds
    IndexOutOfBounds(usize, usize),
    /// The unsigned transaction didn't have an input at that index
    MissingInputUtxo,
    /// Derivation error
    DerivationError(descriptor::ConversionError),
    /// The PSBT's `witness_utxo` and/or `non_witness_utxo` were invalid or missing
    UtxoCheck,
    /// The PSBT's `witness_utxo` and/or `non_witness_utxo` had a script_pubkey that did not match
    /// the descriptor
    MismatchedScriptPubkey,
}

impl fmt::Display for UtxoUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UtxoUpdateError::IndexOutOfBounds(ind, len) => {
                write!(f, "index {}, psbt input len: {}", ind, len)
            }
            UtxoUpdateError::MissingInputUtxo => {
                write!(f, "Missing input in unsigned transaction")
            }
            UtxoUpdateError::DerivationError(e) => write!(f, "Key derivation error {}", e),
            UtxoUpdateError::UtxoCheck => write!(
                f,
                "The input's witness_utxo and/or non_witness_utxo were invalid or missing"
            ),
            UtxoUpdateError::MismatchedScriptPubkey => {
                write!(f, "The input's witness_utxo and/or non_witness_utxo had a script pubkey that didn't match the descriptor")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UtxoUpdateError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        use self::UtxoUpdateError::*;

        match self {
            IndexOutOfBounds(_, _) | MissingInputUtxo | UtxoCheck | MismatchedScriptPubkey => None,
            DerivationError(e) => Some(e),
        }
    }
}

/// Return error type for [`Psbt::update_output_with_descriptor`]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OutputUpdateError {
    /// Index out of bounds
    IndexOutOfBounds(usize, usize),
    /// The raw unsigned transaction didn't have an output at that index
    MissingTxOut,
    /// Derivation error
    DerivationError(descriptor::ConversionError),
    /// The output's script_pubkey did not match the descriptor
    MismatchedScriptPubkey,
}

impl fmt::Display for OutputUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputUpdateError::IndexOutOfBounds(ind, len) => {
                write!(f, "index {}, psbt output len: {}", ind, len)
            }
            OutputUpdateError::MissingTxOut => {
                write!(f, "Missing txout in the unsigned transaction")
            }
            OutputUpdateError::DerivationError(e) => write!(f, "Key derivation error {}", e),
            OutputUpdateError::MismatchedScriptPubkey => {
                write!(f, "The output's script pubkey didn't match the descriptor")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OutputUpdateError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        use self::OutputUpdateError::*;

        match self {
            IndexOutOfBounds(_, _) | MissingTxOut | MismatchedScriptPubkey => None,
            DerivationError(e) => Some(e),
        }
    }
}

/// Return error type for [`Psbt::sighash_msg`]
#[derive(Debug, PartialEq, Eq)]
pub enum SighashError {
    /// Index out of bounds
    IndexOutOfBounds(usize, usize),
    /// Missing input utxo
    MissingInputUtxo,
    /// Missing Prevouts
    MissingSpendUtxos,
    /// Invalid Sighash type
    InvalidSighashType,
    /// Sighash computation error
    /// Only happens when single does not have corresponding output as psbts
    /// already have information to compute the sighash
    SighashComputationError(sighash::Error),
    /// Missing Witness script
    MissingWitnessScript,
    /// Missing Redeem script,
    MissingRedeemScript,
}

impl fmt::Display for SighashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SighashError::IndexOutOfBounds(ind, len) => {
                write!(f, "index {}, psbt input len: {}", ind, len)
            }
            SighashError::MissingInputUtxo => write!(f, "Missing input utxo in pbst"),
            SighashError::MissingSpendUtxos => write!(f, "Missing Psbt spend utxos"),
            SighashError::InvalidSighashType => write!(f, "Invalid Sighash type"),
            SighashError::SighashComputationError(e) => {
                write!(f, "Sighash computation error : {}", e)
            }
            SighashError::MissingWitnessScript => write!(f, "Missing Witness Script"),
            SighashError::MissingRedeemScript => write!(f, "Missing Redeem Script"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SighashError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        use self::SighashError::*;

        match self {
            IndexOutOfBounds(_, _)
            | MissingInputUtxo
            | MissingSpendUtxos
            | InvalidSighashType
            | MissingWitnessScript
            | MissingRedeemScript => None,
            SighashComputationError(e) => Some(e),
        }
    }
}

impl From<sighash::Error> for SighashError {
    fn from(e: sighash::Error) -> Self { SighashError::SighashComputationError(e) }
}
