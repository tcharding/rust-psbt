// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;
use core::fmt;

use bitcoin::consensus::encode as consensus;

use crate::prelude::Vec;
use crate::serialize::{self, Deserialize, Serialize};

/// The PSBT version.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Version(u32);

impl Version {
    /// The original PSBT format [BIP-174].
    ///
    /// [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
    pub const ZERO: Self = Self(0);

    /// The second PSBT version [BIP-370].
    ///
    /// [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>
    pub const TWO: Self = Self(2);
}

impl Version {
    /// Returns the version number as a `u32`.
    pub fn to_u32(self) -> u32 { self.0 }
}

impl From<Version> for u32 {
    fn from(v: Version) -> u32 { v.to_u32() }
}

impl TryFrom<u32> for Version {
    type Error = UnsupportedVersionError;

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        match n {
            0 => Ok(Version::ZERO),
            2 => Ok(Version::TWO),
            n => Err(UnsupportedVersionError(n)),
        }
    }
}

impl Serialize for Version {
    fn serialize(&self) -> Vec<u8> { consensus::serialize(&self.to_u32()) }
}

impl Deserialize for Version {
    fn deserialize(bytes: &[u8]) -> Result<Self, serialize::Error> {
        let n: u32 = consensus::deserialize(bytes)?;
        let version = Version::try_from(n)?;
        Ok(version)
    }
}

/// Unsupported PSBT version.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnsupportedVersionError(u32);

impl fmt::Display for UnsupportedVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported version, we only support v0 and v2: {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnsupportedVersionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}
