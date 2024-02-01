// SPDX-License-Identifier: CC0-1.0

//! Implementation of the Extractor role as defined in [BIP-174].
//!
//! # Extractor Role
//!
//! > The Transaction Extractor does not need to know how to interpret scripts in order
//! > to extract the network serialized transaction.
//!
//! It is only possible to extract a transaction from a PSBT _after_ it has been finalized. However
//! the Extractor role may be fulfilled by a separate entity to the Finalizer hence this is a
//! separate module and does not require the "miniscript" feature be enabled.
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

use core::fmt;

use bitcoin::{FeeRate, Transaction, Txid};

use crate::error::{write_err, FeeError};
use crate::v2::{DetermineLockTimeError, Psbt};

/// Implements the BIP-370 Finalized role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Extractor(Psbt);

impl Extractor {
    /// Creates an `Extractor`.
    ///
    /// An extractor can only accept a PSBT that has been finalized.
    pub fn new(psbt: Psbt) -> Result<Self, ExtractError> {
        if psbt.inputs.iter().any(|input| !input.is_finalized()) {
            return Err(ExtractError::PsbtNotFinalized);
        }
        let _ = psbt.determine_lock_time()?;

        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid {
        self.0.id().expect("Extractor guarantees lock time can be determined")
    }
}

impl Extractor {
    /// The default `max_fee_rate` value used for extracting transactions with [`Self::extract_tx`].
    ///
    /// As of 2023, even the biggest overpayers during the highest fee markets only paid around
    /// 1000 sats/vByte. 25k sats/vByte is obviously a mistake at this point.
    pub const DEFAULT_MAX_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(25_000);

    /// An alias for [`Self::extract_tx_fee_rate_limit`].
    pub fn extract_tx(&self) -> Result<Transaction, ExtractTxFeeRateError> {
        self.internal_extract_tx_with_fee_rate_limit(Self::DEFAULT_MAX_FEE_RATE)
    }

    /// Extracts the [`Transaction`] from a [`Psbt`] by filling in the available signature information.
    ///
    /// ## Errors
    ///
    /// `ExtractTxError` variants will contain either the [`Psbt`] itself or the [`Transaction`]
    /// that was extracted. These can be extracted from the Errors in order to recover.
    /// See the error documentation for info on the variants. In general, it covers large fees.
    pub fn extract_tx_fee_rate_limit(&self) -> Result<Transaction, ExtractTxFeeRateError> {
        self.internal_extract_tx_with_fee_rate_limit(Self::DEFAULT_MAX_FEE_RATE)
    }

    /// Extracts the [`Transaction`] from a [`Psbt`] by filling in the available signature information.
    pub fn extract_tx_with_fee_rate_limit(
        &self,
        max_fee_rate: FeeRate,
    ) -> Result<Transaction, ExtractTxFeeRateError> {
        self.internal_extract_tx_with_fee_rate_limit(max_fee_rate)
    }

    /// Perform [`Self::extract_tx_fee_rate_limit`] without the fee rate check.
    ///
    /// This can result in a transaction with absurdly high fees. Use with caution.
    pub fn extract_tx_unchecked_fee_rate(&self) -> Result<Transaction, ExtractTxError> {
        self.internal_extract_tx()
    }

    #[inline]
    fn internal_extract_tx_with_fee_rate_limit(
        &self,
        max_fee_rate: FeeRate,
    ) -> Result<Transaction, ExtractTxFeeRateError> {
        let fee = self.0.fee()?;
        let tx = self.internal_extract_tx()?;

        // Now that the extracted Transaction is made, decide how to return it.
        let fee_rate =
            FeeRate::from_sat_per_kwu(fee.to_sat().saturating_mul(1000) / tx.weight().to_wu());
        // Prefer to return an AbsurdFeeRate error when both trigger.
        if fee_rate > max_fee_rate {
            return Err(ExtractTxFeeRateError::FeeTooHigh { fee: fee_rate, max: max_fee_rate });
        }

        Ok(tx)
    }

    /// Extracts a finalized transaction from the [`Psbt`].
    ///
    /// Uses `miniscript` to do interpreter checks.
    #[inline]
    fn internal_extract_tx(&self) -> Result<Transaction, ExtractTxError> {
        if !self.0.is_finalized() {
            return Err(ExtractTxError::Unfinalized);
        }

        let lock_time = self.0.determine_lock_time()?;

        let tx = Transaction {
            version: self.0.global.tx_version,
            lock_time,
            input: self.0.inputs.iter().map(|input| input.signed_tx_in()).collect(),
            output: self.0.outputs.iter().map(|ouput| ouput.tx_out()).collect(),
        };

        Ok(tx)
    }
}

/// Error constructing an `Extractor`.
#[derive(Debug)]
pub enum ExtractError {
    /// Attempted to extract tx from an unfinalized PSBT.
    PsbtNotFinalized,
    /// Finalizer must be able to determine the lock time.
    DetermineLockTime(DetermineLockTimeError),
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ExtractError::*;

        match *self {
            PsbtNotFinalized => write!(f, "attempted to extract tx from an unfinalized PSBT"),
            DetermineLockTime(ref e) =>
                write_err!(f, "extractor must be able to determine the lock time"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExtractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ExtractError::*;

        match *self {
            DetermineLockTime(ref e) => Some(e),
            PsbtNotFinalized => None,
        }
    }
}

impl From<DetermineLockTimeError> for ExtractError {
    fn from(e: DetermineLockTimeError) -> Self { Self::DetermineLockTime(e) }
}

/// Error caused by fee calculation when extracting a [`Transaction`] from a PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractTxFeeRateError {
    /// Error calculating the fee rate.
    Fee(FeeError),
    /// The calculated fee rate exceeds max.
    FeeTooHigh {
        /// Calculated fee.
        fee: FeeRate,
        /// Maximum allowable fee.
        max: FeeRate,
    },
    /// Error extracting the transaction.
    ExtractTx(ExtractTxError),
}

impl fmt::Display for ExtractTxFeeRateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ExtractTxFeeRateError::*;

        match *self {
            Fee(ref e) => write_err!(f, "fee calculation"; e),
            FeeTooHigh { fee, max } => write!(f, "fee {} is greater than max {}", fee, max),
            ExtractTx(ref e) => write_err!(f, "extract"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExtractTxFeeRateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ExtractTxFeeRateError::*;

        match *self {
            Fee(ref e) => Some(e),
            ExtractTx(ref e) => Some(e),
            FeeTooHigh { .. } => None,
        }
    }
}

impl From<FeeError> for ExtractTxFeeRateError {
    fn from(e: FeeError) -> Self { Self::Fee(e) }
}

impl From<ExtractTxError> for ExtractTxFeeRateError {
    fn from(e: ExtractTxError) -> Self { Self::ExtractTx(e) }
}

/// Error extracting a [`Transaction`] from a PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractTxError {
    /// Attempted to extract transaction from an unfinalized PSBT.
    Unfinalized,
    /// Failed to determine lock time.
    DetermineLockTime(DetermineLockTimeError),
}

impl fmt::Display for ExtractTxError {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result { todo!() }
}

#[cfg(feature = "std")]
impl std::error::Error for ExtractTxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { todo!() }
}

impl From<DetermineLockTimeError> for ExtractTxError {
    fn from(e: DetermineLockTimeError) -> Self { Self::DetermineLockTime(e) }
}
