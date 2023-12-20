// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use bitcoin::bip32::Xpub;
// TODO: This should be exposed like this in rust-bitcoin.
use bitcoin::consensus::encode as consensus;
use bitcoin::transaction::Transaction;
use bitcoin::{absolute, hashes, secp256k1, taproot};

use crate::prelude::*;
use crate::{raw, version, v0};

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
    /// Not enough data to deserialize object.
    NotEnoughData,
    /// Magic bytes for a PSBT must be the ASCII for "psbt" serialized in most
    /// significant byte order.
    InvalidMagic,
    /// The separator for a PSBT must be `0xff`.
    InvalidSeparator,
    /// Known keys must be according to spec.
    InvalidKey(raw::Key),
    /// Non-proprietary key type found when proprietary key was expected
    InvalidProprietaryKey,
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(raw::Key),
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
    /// Couldn't converting parsed u32 to a lock time.
    LockTime(absolute::Error),
    /// Found a keypair type that is explicitly excluded.
    ExcludedKey(u8),
    /// Unsupported PSBT version.
    UnsupportedVersion(version::UnsupportedVersionError),
    /// Error doing unsigned transaction checks (v0 only).
    // TODO: Consider splitting error into v0 an v2 specific types.
    UnsignedTxChecks(v0::UnsignedTxChecksError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            NotEnoughData => f.write_str("not enough data to deserialize object"),
            InvalidMagic => f.write_str("invalid magic"),
            InvalidSeparator => f.write_str("invalid separator"),
            InvalidKey(ref rkey) => write!(f, "invalid key: {}", rkey),
            InvalidProprietaryKey =>
                write!(f, "non-proprietary key type found when proprietary key was expected"),
            DuplicateKey(ref rkey) => write!(f, "duplicate key: {}", rkey),
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
            LockTime(ref e) => write_err!(f, "parsed locktime invalid"; e),
            ExcludedKey(t) =>
                write!(f, "found a keypair type that is explicitly excluded: {:x}", t),
            UnsupportedVersion(ref e) => write_err!(f, "unsupported version"; e),
            UnsignedTxChecks(ref e) => write_err!(f, "error doing unsigned transaction checks (v0 only)"; e),
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
            LockTime(ref e) => Some(e),
            UnsupportedVersion(ref e) => Some(e),
            UnsignedTxChecks(ref e) => Some(e),
            NotEnoughData
            | InvalidMagic
            | InvalidSeparator
            | InvalidKey(_)
            | InvalidProprietaryKey
            | DuplicateKey(_)
            | MustHaveUnsignedTx
            | NoMorePairs
            | UnexpectedUnsignedTx { .. }
            | NonStandardSighashType(_)
            | InvalidPreimageHashPair { .. }
            | CombineInconsistentKeySources(_)
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
            | PartialDataConsumption
            | ExcludedKey(_) => None,
        }
    }
}

impl From<hashes::FromSliceError> for Error {
    fn from(e: hashes::FromSliceError) -> Error { Error::InvalidHash(e) }
}

impl From<consensus::Error> for Error {
    fn from(e: consensus::Error) -> Self { Error::ConsensusEncoding(e) }
}

impl From<absolute::Error> for Error {
    fn from(e: absolute::Error) -> Self { Error::LockTime(e) }
}

impl From<version::UnsupportedVersionError> for Error {
    fn from(e: version::UnsupportedVersionError) -> Self { Error::UnsupportedVersion(e) }
}

impl From<v0::UnsignedTxChecksError> for Error {
    fn from(e: v0::UnsignedTxChecksError) -> Self { Error::UnsignedTxChecks(e) }
}

/// Error combining two PSBTs, global extended public key has inconsistent key sources.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InconsistentKeySourcesError(pub Xpub);

impl fmt::Display for InconsistentKeySourcesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "combining PSBT, key-source conflict for xpub {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InconsistentKeySourcesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// An error while calculating the fee.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FeeError {
    /// Funding utxo error for input.
    FundingUtxo(FundingUtxoError),
    /// Integer overflow in fee calculation adding input.
    InputOverflow,
    /// Integer overflow in fee calculation adding output.
    OutputOverflow,
    /// Negative fee.
    Negative,
}

impl fmt::Display for FeeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FeeError::*;

        match *self {
            FundingUtxo(ref e) => write_err!(f, "funding utxo error for input"; e),
            InputOverflow => f.write_str("integer overflow in fee calculation adding input"),
            OutputOverflow => f.write_str("integer overflow in fee calculation adding output"),
            Negative => f.write_str("PSBT has a negative fee which is not allowed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FeeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use FeeError::*;

        match *self {
            FundingUtxo(ref e) => Some(e),
            InputOverflow | OutputOverflow | Negative => None,
        }
    }
}

impl From<FundingUtxoError> for FeeError {
    fn from(e: FundingUtxoError) -> Self { Self::FundingUtxo(e) }
}

/// An error getting the funding transaction for this input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FundingUtxoError {
    /// The vout is out of bounds for non-witness transaction.
    OutOfBounds {
        /// The vout used as list index.
        vout: usize,
        /// The length of the utxo list.
        len: usize,
    },
    /// No funding utxo found.
    MissingUtxo,
}

impl fmt::Display for FundingUtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FundingUtxoError::*;

        match *self {
            OutOfBounds { vout, len } =>
                write!(f, "vout {} out of bounds for tx list len: {}", vout, len),
            MissingUtxo => write!(f, "no funding utxo found"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FundingUtxoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use FundingUtxoError::*;

        match *self {
            OutOfBounds { .. } | MissingUtxo => None,
        }
    }
}

/// Formats error.
///
/// If `std` feature is OFF appends error source (delimited by `: `). We do this because
/// `e.source()` is only available in std builds, without this macro the error source is lost for
/// no-std builds.
macro_rules! write_err {
    ($writer:expr, $string:literal $(, $args:expr)*; $source:expr) => {
        {
            #[cfg(feature = "std")]
            {
                let _ = &$source;   // Prevents clippy warnings.
                write!($writer, $string $(, $args)*)
            }
            #[cfg(not(feature = "std"))]
            {
                write!($writer, concat!($string, ": {}") $(, $args)*, $source)
            }
        }
    }
}
pub(crate) use write_err;
