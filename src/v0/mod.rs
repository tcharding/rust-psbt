// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions Version 0.
//!
//! This module is code imported directly from [`rust-bitcoin`] and [`rust-miniscript`].
//!
//! More specifically `v0.31.1` and `v11.0.0` respectively:
//!
//! - `rust-bitcoin` commit: `cfa018c9 Bump version to 0.31.1`
//! - `rust-mininscript` comit: `7ebdd2f Merge rust-bitcoin/rust-miniscript#629: Tracking PR for release v11.0.0`
//!
//! To port code that currently uses those crate you should be able to change:
//!
//! - `use bitcoin::psbt::Foo` to `use psbt_v2::v0::bitcoin::Foo`
//! - `use miniscript::psbt::Foo` to `use psbt_v2::v0::miniscript::Foo`
//!
//! Only bare minimal changes to make it build were made.
//!
//! [`rust-bitcoin`]: <https://github.com/rust-bitcoin/rust-miniscript>
//! [`rust-miniscript`]: <https://github.com/rust-bitcoin/rust-bitcoin>

/// Import of the [`bitcoin::psbt`] module.
///
/// [`bitcoin::psbt`]: <https://docs.rs/bitcoin/0.31.1/bitcoin/psbt/index.html>
pub mod bitcoin;

/// Import of the `miniscript::psbt` module.
///
/// [`miniscript::psbt`]: <https://docs.rs/miniscript/latest/miniscript/psbt/index.html>
#[cfg(feature = "miniscript")]
pub mod miniscript;

use core::fmt;

use ::bitcoin::ScriptBuf;

use crate::v0::bitcoin::OutputType;

#[rustfmt::skip]                // Keep public exports separate.
#[doc(inline)]
pub use self::bitcoin::{Psbt, Input, Output};

// New stuff not found from `rust-bitcoin` or `rust-miniscript`
impl Psbt {
    /// Returns `Ok` if PSBT is
    ///
    /// From BIP-174:
    ///
    /// For a Signer to only produce valid signatures for what it expects to sign, it must check that the following conditions are true:
    ///
    /// - If a non-witness UTXO is provided, its hash must match the hash specified in the prevout
    /// - If a witness UTXO is provided, no non-witness signature may be created
    /// - If a redeemScript is provided, the scriptPubKey must be for that redeemScript
    /// - If a witnessScript is provided, the scriptPubKey or the redeemScript must be for that witnessScript
    /// - If a sighash type is provided, the signer must check that the sighash is acceptable. If unacceptable, they must fail.
    /// - If a sighash type is not provided, the signer should sign using SIGHASH_ALL, but may use any sighash type they wish.
    pub fn signer_checks(&self) -> Result<(), SignerChecksError> {
        let unsigned_tx = &self.unsigned_tx;
        for (i, input) in self.inputs.iter().enumerate() {
            if input.witness_utxo.is_some() {
                match self.output_type(i) {
                    Ok(OutputType::Bare) => return Err(SignerChecksError::NonWitnessSig),
                    Ok(_) => {}
                    Err(_) => {} // TODO: Is this correct?
                }
            }

            if let Some(ref tx) = input.non_witness_utxo {
                if tx.txid() != unsigned_tx.input[i].previous_output.txid {
                    return Err(SignerChecksError::NonWitnessUtxoTxidMismatch);
                }
            }

            if let Some(ref redeem_script) = input.redeem_script {
                match input.witness_utxo {
                    Some(ref tx_out) => {
                        let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());
                        if tx_out.script_pubkey != script_pubkey {
                            return Err(SignerChecksError::RedeemScriptMismatch);
                        }
                    }
                    None => return Err(SignerChecksError::MissingTxOut),
                }
            }

            if let Some(ref witness_script) = input.witness_script {
                match input.witness_utxo {
                    Some(ref utxo) => {
                        let script_pubkey = &utxo.script_pubkey;
                        if script_pubkey.is_p2wsh() {
                            if ScriptBuf::new_p2wsh(&witness_script.wscript_hash())
                                != *script_pubkey
                            {
                                return Err(SignerChecksError::WitnessScriptMismatchWsh);
                            }
                        } else if script_pubkey.is_p2sh() {
                            if let Some(ref redeem_script) = input.redeem_script {
                                if ScriptBuf::new_p2wsh(&redeem_script.wscript_hash())
                                    != *script_pubkey
                                {
                                    return Err(SignerChecksError::WitnessScriptMismatchShWsh);
                                }
                            }
                        } else {
                            // BIP does not specifically say there should not be a witness script here?
                        }
                    }
                    None => return Err(SignerChecksError::MissingTxOut),
                }
            }

            if let Some(_sighash_type) = input.sighash_type {
                // TODO: Check that sighash is accetable, what does that mean?
                {}
            }
        }
        Ok(())
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
