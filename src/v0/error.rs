// SPDX-License-Identifier: CC0-1.0

//! PSBT v0 errors.

use core::fmt;

use bitcoin::bip32::Xpub;
use bitcoin::consensus::encode as consensus;
use bitcoin::{hashes, secp256k1, taproot};
use bitcoin::{sighash, FeeRate, Transaction};

use crate::prelude::*;
use crate::io;
use crate::error::write_err;
use crate::v0::{raw, Psbt};

/// Enum for marking psbt hash error.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum PsbtHash {
    Ripemd,
    Sha256,
    Hash160,
    Hash256,
}

/// Ways that a Partially Signed Transaction might fail.
// TODO: This general error needs splitting up into specific error types.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Magic bytes for a PSBT must be the ASCII for "psbt" serialized in most
    /// significant byte order.
    InvalidMagic,
    /// Missing both the witness and non-witness utxo.
    MissingUtxo,
    /// The separator for a PSBT must be `0xff`.
    InvalidSeparator,
    /// Returned when output index is out of bounds in relation to the output in non-witness UTXO.
    PsbtUtxoOutOfbounds,
    /// Known keys must be according to spec.
    InvalidKey(raw::Key),
    /// Non-proprietary key type found when proprietary key was expected
    InvalidProprietaryKey,
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(raw::Key),
    /// The scriptSigs for the unsigned transaction must be empty.
    UnsignedTxHasScriptSigs,
    /// The scriptWitnesses for the unsigned transaction must be empty.
    UnsignedTxHasScriptWitnesses,
    /// A PSBT must have an unsigned transaction.
    MustHaveUnsignedTx,
    /// Signals that there are no more key-value pairs in a key-value map.
    NoMorePairs,
    /// Attempting to combine with a PSBT describing a different unsigned
    /// transaction.
    UnexpectedUnsignedTx {
        /// Expected
        expected: Box<Transaction>,
        /// Actual
        actual: Box<Transaction>,
    },
    /// Unable to parse as a standard sighash type.
    NonStandardSighashType(u32),
    /// Invalid hash when parsing slice.
    InvalidHash(hashes::FromSliceError),
    /// The pre-image must hash to the correponding psbt hash
    InvalidPreimageHashPair {
        /// Hash-type
        hash_type: PsbtHash,
        /// Pre-image
        preimage: Box<[u8]>,
        /// Hash value
        hash: Box<[u8]>,
    },
    /// Conflicting data during combine procedure:
    /// global extended public key has inconsistent key sources
    CombineInconsistentKeySources(Box<Xpub>),
    /// Serialization error in bitcoin consensus-encoded structures
    ConsensusEncoding(consensus::Error),
    /// Negative fee
    NegativeFee,
    /// Integer overflow in fee calculation
    FeeOverflow,
    /// Parsing error indicating invalid public keys
    InvalidPublicKey(bitcoin::key::Error),
    /// Parsing error indicating invalid secp256k1 public keys
    InvalidSecp256k1PublicKey(secp256k1::Error),
    /// Parsing error indicating invalid xonly public keys
    InvalidXOnlyPublicKey,
    /// Parsing error indicating invalid ECDSA signatures
    InvalidEcdsaSignature(bitcoin::ecdsa::Error),
    /// Parsing error indicating invalid taproot signatures
    InvalidTaprootSignature(bitcoin::taproot::SigFromSliceError),
    /// Parsing error indicating invalid control block
    InvalidControlBlock,
    /// Parsing error indicating invalid leaf version
    InvalidLeafVersion,
    /// Parsing error indicating a taproot error
    Taproot(&'static str),
    /// Taproot tree deserilaization error
    TapTree(taproot::IncompleteBuilderError),
    /// Error related to an xpub key
    XPubKey(&'static str),
    /// Error related to PSBT version
    Version(&'static str),
    /// PSBT data is not consumed entirely
    PartialDataConsumption,
    /// I/O error.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            InvalidMagic => f.write_str("invalid magic"),
            MissingUtxo => f.write_str("UTXO information is not present in PSBT"),
            InvalidSeparator => f.write_str("invalid separator"),
            PsbtUtxoOutOfbounds =>
                f.write_str("output index is out of bounds of non witness script output array"),
            InvalidKey(ref rkey) => write!(f, "invalid key: {}", rkey),
            InvalidProprietaryKey =>
                write!(f, "non-proprietary key type found when proprietary key was expected"),
            DuplicateKey(ref rkey) => write!(f, "duplicate key: {}", rkey),
            UnsignedTxHasScriptSigs => f.write_str("the unsigned transaction has script sigs"),
            UnsignedTxHasScriptWitnesses =>
                f.write_str("the unsigned transaction has script witnesses"),
            MustHaveUnsignedTx =>
                f.write_str("partially signed transactions must have an unsigned transaction"),
            NoMorePairs => f.write_str("no more key-value pairs for this psbt map"),
            UnexpectedUnsignedTx { expected: ref e, actual: ref a } => write!(
                f,
                "different unsigned transaction: expected {}, actual {}",
                e.txid(),
                a.txid()
            ),
            NonStandardSighashType(ref sht) => write!(f, "non-standard sighash type: {}", sht),
            InvalidHash(ref e) => write_err!(f, "invalid hash when parsing slice"; e),
            InvalidPreimageHashPair { ref preimage, ref hash, ref hash_type } => {
                // directly using debug forms of psbthash enums
                write!(f, "Preimage {:?} does not match {:?} hash {:?}", preimage, hash_type, hash)
            }
            CombineInconsistentKeySources(ref s) => {
                write!(f, "combine conflict: {}", s)
            }
            ConsensusEncoding(ref e) => write_err!(f, "bitcoin consensus encoding error"; e),
            NegativeFee => f.write_str("PSBT has a negative fee which is not allowed"),
            FeeOverflow => f.write_str("integer overflow in fee calculation"),
            InvalidPublicKey(ref e) => write_err!(f, "invalid public key"; e),
            InvalidSecp256k1PublicKey(ref e) => write_err!(f, "invalid secp256k1 public key"; e),
            InvalidXOnlyPublicKey => f.write_str("invalid xonly public key"),
            InvalidEcdsaSignature(ref e) => write_err!(f, "invalid ECDSA signature"; e),
            InvalidTaprootSignature(ref e) => write_err!(f, "invalid taproot signature"; e),
            InvalidControlBlock => f.write_str("invalid control block"),
            InvalidLeafVersion => f.write_str("invalid leaf version"),
            Taproot(s) => write!(f, "taproot error -  {}", s),
            TapTree(ref e) => write_err!(f, "taproot tree error"; e),
            XPubKey(s) => write!(f, "xpub key error -  {}", s),
            Version(s) => write!(f, "version error {}", s),
            PartialDataConsumption =>
                f.write_str("data not consumed entirely when explicitly deserializing"),
            Io(ref e) => write_err!(f, "I/O error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            InvalidHash(ref e) => Some(e),
            ConsensusEncoding(ref e) => Some(e),
            Io(ref e) => Some(e),
            InvalidMagic
            | MissingUtxo
            | InvalidSeparator
            | PsbtUtxoOutOfbounds
            | InvalidKey(_)
            | InvalidProprietaryKey
            | DuplicateKey(_)
            | UnsignedTxHasScriptSigs
            | UnsignedTxHasScriptWitnesses
            | MustHaveUnsignedTx
            | NoMorePairs
            | UnexpectedUnsignedTx { .. }
            | NonStandardSighashType(_)
            | InvalidPreimageHashPair { .. }
            | CombineInconsistentKeySources(_)
            | NegativeFee
            | FeeOverflow
            | InvalidPublicKey(_)
            | InvalidSecp256k1PublicKey(_)
            | InvalidXOnlyPublicKey
            | InvalidEcdsaSignature(_)
            | InvalidTaprootSignature(_)
            | InvalidControlBlock
            | InvalidLeafVersion
            | Taproot(_)
            | TapTree(_)
            | XPubKey(_)
            | Version(_)
            | PartialDataConsumption => None,
        }
    }
}

impl From<hashes::FromSliceError> for Error {
    fn from(e: hashes::FromSliceError) -> Error { Error::InvalidHash(e) }
}

impl From<consensus::Error> for Error {
    fn from(e: consensus::Error) -> Self { Error::ConsensusEncoding(e) }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::Io(e) }
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
