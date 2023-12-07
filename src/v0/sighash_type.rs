// SPDX-License-Identifier: CC0-1.0

use core::fmt;
use core::str::FromStr;

use bitcoin::sighash::{self, EcdsaSighashType, NonStandardSighashTypeError, TapSighashType};

use crate::error::write_err;
use crate::prelude::*;

/// A Signature hash type for the corresponding input. As of taproot upgrade, the signature hash
/// type can be either [`EcdsaSighashType`] or [`TapSighashType`] but it is not possible to know
/// directly which signature hash type the user is dealing with. Therefore, the user is responsible
/// for converting to/from [`PsbtSighashType`] from/to the desired signature hash type they need.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct PsbtSighashType {
    pub(crate) inner: u32,
}

impl fmt::Display for PsbtSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.taproot_hash_ty() {
            Err(_) => write!(f, "{:#x}", self.inner),
            Ok(taproot_hash_ty) => fmt::Display::fmt(&taproot_hash_ty, f),
        }
    }
}

impl FromStr for PsbtSighashType {
    type Err = SighashTypeParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // We accept strings of form: "SIGHASH_ALL" etc.
        //
        // NB: some of Taproot sighash types are non-standard for pre-taproot
        // inputs. We also do not support SIGHASH_RESERVED in verbatim form
        // ("0xFF" string should be used instead).
        if let Ok(ty) = TapSighashType::from_str(s) {
            return Ok(ty.into());
        }

        // We accept non-standard sighash values.
        if let Ok(inner) = u32::from_str_radix(s.trim_start_matches("0x"), 16) {
            return Ok(PsbtSighashType { inner });
        }

        Err(SighashTypeParseError { unrecognized: s.to_owned() })
    }
}
impl From<EcdsaSighashType> for PsbtSighashType {
    fn from(ecdsa_hash_ty: EcdsaSighashType) -> Self {
        PsbtSighashType { inner: ecdsa_hash_ty as u32 }
    }
}

impl From<TapSighashType> for PsbtSighashType {
    fn from(taproot_hash_ty: TapSighashType) -> Self {
        PsbtSighashType { inner: taproot_hash_ty as u32 }
    }
}

impl PsbtSighashType {
    /// Returns the [`EcdsaSighashType`] if the [`PsbtSighashType`] can be
    /// converted to one.
    pub fn ecdsa_hash_ty(self) -> Result<EcdsaSighashType, NonStandardSighashTypeError> {
        EcdsaSighashType::from_standard(self.inner)
    }

    /// Returns the [`TapSighashType`] if the [`PsbtSighashType`] can be
    /// converted to one.
    pub fn taproot_hash_ty(self) -> Result<TapSighashType, InvalidSighashTypeError> {
        if self.inner > 0xffu32 {
            return Err(InvalidSighashTypeError::Invalid(self.inner));
        }

        let ty = TapSighashType::from_consensus_u8(self.inner as u8)?;
        Ok(ty)
    }

    /// Creates a [`PsbtSighashType`] from a raw `u32`.
    ///
    /// Allows construction of a non-standard or non-valid sighash flag
    /// ([`EcdsaSighashType`], [`TapSighashType`] respectively).
    pub fn from_u32(n: u32) -> PsbtSighashType { PsbtSighashType { inner: n } }

    /// Converts [`PsbtSighashType`] to a raw `u32` sighash flag.
    ///
    /// No guarantees are made as to the standardness or validity of the returned value.
    pub fn to_u32(self) -> u32 { self.inner }
}

/// Error returned for failure during parsing one of the sighash types.
///
/// This is currently returned for unrecognized sighash strings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SighashTypeParseError {
    /// The unrecognized string we attempted to parse.
    pub unrecognized: String,
}

impl fmt::Display for SighashTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unrecognized SIGHASH string '{}'", self.unrecognized)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SighashTypeParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Integer is not a consensus valid sighash type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidSighashTypeError {
    /// TODO:
    Bitcoin(sighash::InvalidSighashTypeError),
    /// TODO:
    Invalid(u32),
}

impl fmt::Display for InvalidSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InvalidSighashTypeError::*;

        match *self {
            Bitcoin(ref e) => write_err!(f, "bitcoin"; e),
            Invalid(invalid) => write!(f, "invalid sighash type {}", invalid),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InvalidSighashTypeError::*;

        match *self {
            Bitcoin(ref e) => Some(e),
            Invalid(_) => None,
        }
    }
}

impl From<sighash::InvalidSighashTypeError> for InvalidSighashTypeError {
    fn from(e: sighash::InvalidSighashTypeError) -> Self { Self::Bitcoin(e) }
}
