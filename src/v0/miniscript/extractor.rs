// SPDX-License-Identifier: CC0-1.0

//! WIP: Partial implementation of the Extractor role as defined in [BIP-174].
//!
//! See also `crate::v0::extractor.rs`.
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

use crate::bitcoin::secp256k1::{Secp256k1, Verification};
use crate::bitcoin::Transaction;
use crate::v0::miniscript::error::{Error, InputError};
use crate::v0::Psbt;

impl Psbt {
    /// Psbt extractor as defined in BIP174 that takes in a psbt reference
    /// and outputs a extracted bitcoin::Transaction
    /// Also does the interpreter sanity check
    /// Will error if the final ScriptSig or final Witness are missing
    /// or the interpreter check fails.
    pub fn extract<C: Verification>(&self, secp: &Secp256k1<C>) -> Result<Transaction, Error> {
        self.sanity_check()?;

        let mut ret = self.global.unsigned_tx.clone();
        for (n, input) in self.inputs.iter().enumerate() {
            if input.final_script_sig.is_none() && input.final_script_witness.is_none() {
                return Err(Error::InputError(InputError::MissingWitness, n));
            }

            if let Some(witness) = input.final_script_witness.as_ref() {
                ret.input[n].witness = witness.clone();
            }
            if let Some(script_sig) = input.final_script_sig.as_ref() {
                ret.input[n].script_sig = script_sig.clone();
            }
        }
        self.interpreter_check(secp)?;
        Ok(ret)
    }
}
