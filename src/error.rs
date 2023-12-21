// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use bitcoin::bip32::Xpub;

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
