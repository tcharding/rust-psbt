// SPDX-License-Identifier: CC0-1.0

//! Implementation of the Finalizer role as defined in [BIP-174].
//!
//! # Finalizer Role
//!
//! > For each input, the Input Finalizer determines if the input has enough data to pass validation.
//!
//! Determining if a PSBT has enough data to satisfy the spending conditions of all its inputs
//! requires usage of `rust-miniscript`.
//!
//! # Extractor Role
//!
//! > The Transaction Extractor does not need to know how to interpret scripts in order
//! > to extract the network serialized transaction.
//!
//! The Extractor role does not technically require `rust-miniscript` but since a PSBT must be  

//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

mod finalize;
mod satisfy;

use core::fmt;

use bitcoin::consensus::encode::VarInt;
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::sighash::Prevouts;
use bitcoin::{Script, Sequence, Transaction, TxOut, Witness};
use miniscript::miniscript::satisfy::Placeholder;
use miniscript::{interpreter, Interpreter, MiniscriptKey};

use crate::error::write_err;
use crate::prelude::*;
use crate::v2::map::input::Input;
use crate::v2::{DetermineLockTimeError, Psbt};

#[rustfmt::skip]                // Keep public exports separate.
pub use self::finalize::{InputError, Finalizer, FinalizeError, FinalizeInputError};

impl Psbt {
    // TODO: Should this be on a Role? Finalizer/Extractor? Then we can remove the debug_assert
    /// Interprets all PSBT inputs and checks whether the script is correctly interpreted according
    /// to the context.
    ///
    /// The psbt must have included final script sig and final witness. In other words, this checks
    /// whether the finalized psbt interprets correctly
    pub fn interpreter_check<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<(), InterpreterCheckError> {
        debug_assert!(self.is_finalized());

        let unsigned_tx = self.unsigned_tx()?; // Used to verify signatures.

        let utxos: Vec<&TxOut> = self
            .iter_funding_utxos()
            .map(|res| res.expect("finalized PSBT has funding utxos"))
            .collect();
        let utxos = &Prevouts::All(&utxos);
        for (index, input) in self.inputs.iter().enumerate() {
            self.interpreter_check_input(
                secp,
                &unsigned_tx,
                index,
                input,
                utxos,
                input.final_script_witness.as_ref().expect("checked in is_finalized"),
                input.final_script_sig.as_ref().expect("checked in is_finalized"),
            )?;
        }
        Ok(())
    }

    /// Runs the miniscript interpreter on a single psbt input.
    #[allow(clippy::too_many_arguments)] // TODO: Remove this.
    fn interpreter_check_input<C: Verification, T: Borrow<TxOut>>(
        &self,
        secp: &Secp256k1<C>,
        unsigned_tx: &Transaction,
        index: usize,
        input: &Input,
        utxos: &Prevouts<T>,
        witness: &Witness,
        script_sig: &Script,
    ) -> Result<(), InterpreterCheckInputError> {
        use InterpreterCheckInputError::*;

        let spk = &input.funding_utxo().expect("have funding utxo").script_pubkey;

        // TODO: Check that this is correct?
        let cltv = input.lock_time();
        // TODO: is this usage of MAX correct?
        let csv = input.sequence.unwrap_or(Sequence::MAX);

        let interpreter = Interpreter::from_txdata(spk, script_sig, witness, csv, cltv)
            .map_err(|error| Constructor { input_index: index, error })?;

        let iter = interpreter.iter(secp, unsigned_tx, index, utxos);
        // TODO: Ok to just return the first satisfaction error?
        if let Some(error) = iter.filter_map(Result::err).next() {
            return Err(Satisfaction { input_index: index, error });
        };

        Ok(())
    }
}

pub(crate) trait ItemSize {
    fn size(&self) -> usize;
}

impl<Pk: MiniscriptKey> ItemSize for Placeholder<Pk> {
    fn size(&self) -> usize {
        match self {
            Placeholder::Pubkey(_, size) => *size,
            Placeholder::PubkeyHash(_, size) => *size,
            Placeholder::EcdsaSigPk(_) | Placeholder::EcdsaSigPkHash(_) => 73,
            Placeholder::SchnorrSigPk(_, _, size) | Placeholder::SchnorrSigPkHash(_, _, size) =>
                size + 1, // +1 for the OP_PUSH
            Placeholder::HashDissatisfaction
            | Placeholder::Sha256Preimage(_)
            | Placeholder::Hash256Preimage(_)
            | Placeholder::Ripemd160Preimage(_)
            | Placeholder::Hash160Preimage(_) => 33,
            Placeholder::PushOne => 2, // On legacy this should be 1 ?
            Placeholder::PushZero => 1,
            Placeholder::TapScript(s) => s.len(),
            Placeholder::TapControlBlock(cb) => cb.serialize().len(),
        }
    }
}

impl ItemSize for Vec<u8> {
    fn size(&self) -> usize { self.len() }
}

// Helper function to calculate witness size
pub(crate) fn witness_size<T: ItemSize>(wit: &[T]) -> usize {
    wit.iter().map(T::size).sum::<usize>() + varint_len(wit.len())
}

pub(crate) fn varint_len(n: usize) -> usize { VarInt(n as u64).size() }

/// Error type for Pbst Input
#[derive(Debug)]
pub enum InterpreterCheckError {
    /// Failed to determine lock time for unsigned transaction.
    DetermineLockTime(DetermineLockTimeError),
    /// Interpreter check failed for an input.
    InterpreterCheckInput(InterpreterCheckInputError),
}

impl fmt::Display for InterpreterCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InterpreterCheckError::*;

        match *self {
            DetermineLockTime(ref e) => write_err!(f, "interpreter check determine locktime"; e),
            InterpreterCheckInput(ref e) => write_err!(f, "interpreter check failed for input"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InterpreterCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InterpreterCheckError::*;

        match *self {
            DetermineLockTime(ref e) => Some(e),
            InterpreterCheckInput(ref e) => Some(e),
        }
    }
}

impl From<DetermineLockTimeError> for InterpreterCheckError {
    fn from(e: DetermineLockTimeError) -> Self { Self::DetermineLockTime(e) }
}

impl From<InterpreterCheckInputError> for InterpreterCheckError {
    fn from(e: InterpreterCheckInputError) -> Self { Self::InterpreterCheckInput(e) }
}

/// Error type for Pbst Input
#[derive(Debug)]
pub enum InterpreterCheckInputError {
    /// Failed to construct a [`miniscript::Interpreter`].
    Constructor {
        /// Index of the input causing this error.
        input_index: usize,
        /// The interpreter error returned from `rust-miniscript`.
        error: interpreter::Error,
    },
    /// Interpreter satisfaction failed for input.
    Satisfaction {
        /// Index of the input causing this error.
        input_index: usize,
        /// The interpreter error returned from `rust-miniscript`.
        error: interpreter::Error,
    },
}

impl fmt::Display for InterpreterCheckInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InterpreterCheckInputError::*;

        match *self {
            Constructor { input_index, ref error } =>
                write_err!(f, "Interpreter constructor failed for input {}", input_index; error),
            Satisfaction { input_index, ref error } =>
                write_err!(f, "Interpreter satisfaction failed for input {}", input_index; error),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InterpreterCheckInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InterpreterCheckInputError::*;

        match *self {
            Constructor { input_index: _, ref error } => Some(error),
            Satisfaction { input_index: _, ref error } => Some(error),
        }
    }
}
