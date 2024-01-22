// SPDX-License-Identifier: CC0-1.0

//! WIP: Partial implementation of the Extractor role as defined in [BIP-174].
//!
//! See also `crate::v0::miniscript::extractor.rs`.
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

use bitcoin::{FeeRate, Transaction};

use crate::error::FeeError;
use crate::v0::error::ExtractTxError;
use crate::v0::Psbt;

impl Psbt {
    /// The default `max_fee_rate` value used for extracting transactions with [`extract_tx`]
    ///
    /// As of 2023, even the biggest overpayers during the highest fee markets only paid around
    /// 1000 sats/vByte. 25k sats/vByte is obviously a mistake at this point.
    ///
    /// [`extract_tx`]: Psbt::extract_tx
    pub const DEFAULT_MAX_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(25_000);

    /// An alias for [`extract_tx_fee_rate_limit`].
    ///
    /// [`extract_tx_fee_rate_limit`]: Psbt::extract_tx_fee_rate_limit
    pub fn extract_tx(self) -> Result<Transaction, ExtractTxError> {
        self.internal_extract_tx_with_fee_rate_limit(Self::DEFAULT_MAX_FEE_RATE)
    }

    /// Extracts the [`Transaction`] from a [`Psbt`] by filling in the available signature information.
    ///
    /// ## Errors
    ///
    /// `ExtractTxError` variants will contain either the [`Psbt`] itself or the [`Transaction`]
    /// that was extracted. These can be extracted from the Errors in order to recover.
    /// See the error documentation for info on the variants. In general, it covers large fees.
    pub fn extract_tx_fee_rate_limit(self) -> Result<Transaction, ExtractTxError> {
        self.internal_extract_tx_with_fee_rate_limit(Self::DEFAULT_MAX_FEE_RATE)
    }

    /// Extracts the [`Transaction`] from a [`Psbt`] by filling in the available signature information.
    ///
    /// ## Errors
    ///
    /// See [`extract_tx`].
    ///
    /// [`extract_tx`]: Psbt::extract_tx
    pub fn extract_tx_with_fee_rate_limit(
        self,
        max_fee_rate: FeeRate,
    ) -> Result<Transaction, ExtractTxError> {
        self.internal_extract_tx_with_fee_rate_limit(max_fee_rate)
    }

    /// Perform [`extract_tx_fee_rate_limit`] without the fee rate check.
    ///
    /// This can result in a transaction with absurdly high fees. Use with caution.
    ///
    /// [`extract_tx_fee_rate_limit`]: Psbt::extract_tx_fee_rate_limit
    pub fn extract_tx_unchecked_fee_rate(self) -> Transaction { self.internal_extract_tx() }

    // TODO: This is incomplete, it does not do the checks specified in the bip.
    #[inline]
    fn internal_extract_tx(self) -> Transaction {
        // The Transaction Extractor must only accept a PSBT. It checks whether all inputs have
        // complete scriptSigs and scriptWitnesses by checking for the presence of 0x07 Finalized
        // scriptSig and 0x08 Finalized scriptWitness typed records. If they do, the Transaction
        // Extractor should construct complete scriptSigs and scriptWitnesses and encode them into
        // network serialized transactions. Otherwise the Extractor must not modify the PSBT. The
        // Extractor should produce a fully valid, network serialized transaction if all inputs are
        // complete.

        // The Transaction Extractor does not need to know how to interpret scripts in order to
        // extract the network serialized transaction. However it may be able to in order to
        // validate the network serialized transaction at the same time.

        // A single entity is likely to be both a Transaction Extractor and an Input Finalizer.

        let mut tx: Transaction = self.global.unsigned_tx;

        for (vin, psbtin) in tx.input.iter_mut().zip(self.inputs.into_iter()) {
            vin.script_sig = psbtin.final_script_sig.unwrap_or_default();
            vin.witness = psbtin.final_script_witness.unwrap_or_default();
        }

        tx
    }

    #[inline]
    fn internal_extract_tx_with_fee_rate_limit(
        self,
        max_fee_rate: FeeRate,
    ) -> Result<Transaction, ExtractTxError> {
        use FeeError::*;

        let fee = match self.fee() {
            Ok(fee) => fee,
            Err(FundingUtxo(_)) =>
                return Err(ExtractTxError::MissingInputValue { tx: self.internal_extract_tx() }),
            Err(Negative) => return Err(ExtractTxError::SendingTooMuch { psbt: self }),
            Err(InputOverflow) | Err(OutputOverflow) =>
                return Err(ExtractTxError::AbsurdFeeRate {
                    fee_rate: FeeRate::MAX,
                    tx: self.internal_extract_tx(),
                }),
        };

        // Note: Move prevents usage of &self from now on.
        let tx = self.internal_extract_tx();

        // Now that the extracted Transaction is made, decide how to return it.
        let fee_rate =
            FeeRate::from_sat_per_kwu(fee.to_sat().saturating_mul(1000) / tx.weight().to_wu());
        // Prefer to return an AbsurdFeeRate error when both trigger.
        if fee_rate > max_fee_rate {
            return Err(ExtractTxError::AbsurdFeeRate { fee_rate, tx });
        }

        Ok(tx)
    }
}
