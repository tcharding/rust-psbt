// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions Version 0.
//!
//! This module is code copied from [`rust-bitcoin`] and [`rust-miniscript`],
//! specifically `v0.32.8` and `v12.3.5` respectively. Only bare minimal changes
//! to make it build were made.
//!
//! [`rust-bitcoin`]: <https://github.com/rust-bitcoin/rust-bitcoin>
//! [`rust-miniscript`]: <https://github.com/rust-bitcoin/rust-miniscript>

/// Import of the [`bitcoin::psbt`] module.
///
/// [`bitcoin::psbt`]: <https://docs.rs/bitcoin/0.32.2/bitcoin/psbt/index.html>
pub mod bitcoin;

/// Import of the [`miniscript::psbt`] module.
///
/// [`miniscript::psbt`]: <https://docs.rs/miniscript/12.2.0/miniscript/psbt/index.html>
#[cfg(feature = "miniscript")]
pub mod miniscript;

use ::bitcoin::{ScriptBuf, TapSighashType};

use self::bitcoin::{OutputType, SignError};
use crate::PsbtSighashType;
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
    /// - If a witnessScript is provided the redeemScript must be for that witnessScript
    /// - If a witnessScript is provided, the scriptPubKey must be for that witnessScript
    /// - If a sighash type is provided, the signer must check that the sighash is acceptable. If unacceptable, they must fail.
    /// - If a sighash type is not provided, the signer should sign using SIGHASH_ALL, but may use any sighash type they wish.
    pub fn signer_checks(&self, index: usize) -> Result<(), SignError> {
        self.check_index_is_within_bounds(index)?;
        let input = &self.inputs[index];
        let tx_input = &self.unsigned_tx.input[index];
        let prevout_type = self.output_type(index);
        let prevout = self.spend_utxo(index).map_err(|_| SignError::MissingTxOut)?;
        if input.witness_utxo.is_some() {
            if let Ok(OutputType::Bare) = prevout_type {
                return Err(SignError::NonWitnessSig);
            }
        }

        if let Some(ref tx) = input.non_witness_utxo {
            if tx.compute_txid() != tx_input.previous_output.txid {
                return Err(SignError::NonWitnessUtxoTxidMismatch);
            }
        }

        if let Some(ref redeem_script) = input.redeem_script {
            let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());
            if prevout.script_pubkey != script_pubkey {
                return Err(SignError::RedeemScriptMismatch);
            }
        }

        if let Some(ref witness_script) = input.witness_script {
            match prevout_type {
                Ok(OutputType::Wsh)
                    if ScriptBuf::new_p2wsh(&witness_script.wscript_hash())
                        != *prevout.script_pubkey =>
                {
                    return Err(SignError::WitnessScriptMismatchWsh);
                }
                Ok(OutputType::ShWsh) =>
                    if let Some(ref redeem_script) = input.redeem_script {
                        if ScriptBuf::new_p2wsh(&witness_script.wscript_hash()) != *redeem_script
                            || ScriptBuf::new_p2sh(&redeem_script.script_hash())
                                != *prevout.script_pubkey
                        {
                            return Err(SignError::WitnessScriptMismatchShWsh);
                        }
                    },
                _ => (),
            }
        }

        // Use provided sighash or DEFAULT for taproot output and ALL for non-taproot outputs
        let expected_sighash_type = match (input.sighash_type, prevout_type) {
            (None, Ok(OutputType::Tr)) => PsbtSighashType::from(TapSighashType::Default),
            (None, _) => PsbtSighashType::ALL,
            (Some(sighash_type), _) => sighash_type,
        };

        let sighash_mismatches = |sighash: PsbtSighashType| sighash != expected_sighash_type;

        let has_mismatch = input
            .tap_key_sig
            .is_some_and(|sig| sighash_mismatches(PsbtSighashType::from(sig.sighash_type)))
            || input
                .tap_script_sigs
                .values()
                .any(|sig| sighash_mismatches(PsbtSighashType::from(sig.sighash_type)))
            || input
                .partial_sigs
                .values()
                .any(|sig| sighash_mismatches(PsbtSighashType::from(sig.sighash_type)));

        if has_mismatch {
            return Err(SignError::SighashMismatch);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use ::bitcoin::locktime::absolute;
    use ::bitcoin::script::Builder;
    use ::bitcoin::{
        transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };

    use super::*;
    use crate::v0::bitcoin::Input;

    fn single_input_psbt() -> Psbt {
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new() }],
        };
        Psbt::from_unsigned_tx(tx).unwrap()
    }

    #[test]
    fn signer_checks_p2sh_p2wsh_valid() {
        let witness_script = Builder::new().push_opcode(::bitcoin::opcodes::OP_TRUE).into_script();
        let redeem_script = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());

        let mut psbt = single_input_psbt();
        psbt.inputs[0] = Input {
            witness_utxo: Some(TxOut { value: Amount::from_sat(1_000), script_pubkey }),
            redeem_script: Some(redeem_script),
            witness_script: Some(witness_script),
            ..Default::default()
        };

        assert_eq!(psbt.signer_checks(0), Ok(()));
    }

    #[test]
    fn signer_checks_p2sh_p2wsh_wrong_witness_script_rejected() {
        let real_witness_script =
            Builder::new().push_opcode(::bitcoin::opcodes::OP_TRUE).into_script();
        let wrong_witness_script =
            Builder::new().push_opcode(::bitcoin::opcodes::OP_FALSE).into_script();

        let redeem_script = ScriptBuf::new_p2wsh(&real_witness_script.wscript_hash());
        let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());

        let mut psbt = single_input_psbt();
        psbt.inputs[0] = Input {
            witness_utxo: Some(TxOut { value: Amount::from_sat(1_000), script_pubkey }),
            redeem_script: Some(redeem_script),
            witness_script: Some(wrong_witness_script),
            ..Default::default()
        };

        assert_eq!(psbt.signer_checks(0), Err(SignError::WitnessScriptMismatchShWsh));
    }
}
