// SPDX-License-Identifier: CC0-1.0

//! PSBT Version 2.
//!
//! A second version of the Partially Signed Bitcoin Transaction format implemented by
//! [`crate::v0::Psbt`] and described in [BIP-174].
//!
//! Allows for inputs and outputs to be added to the PSBT after creation.
//!
//! # Roles
//!
//! BIP-174 describes various roles, these are implemented in this module as follows:
//!
//! - The **Creator** role Use the [`Creator`] type - or if creator and constructor are a single entity just use the `Constructor`.
//! - The **Constructor**: Use the [`Constructor`] type.
//! - The **Updater** role: Use the [`Updater`] type and then update additional fields of the [`Psbt`] directly.
//! - The **Signer** role: Use the [`Signer`] type.
//! - The **Finalizer** role: Use the `Finalizer` type (requires "miniscript" feature).
//! - The **Extractor** role: Use the [`Extractor`] type.
//!
//! To combine PSBTs use either `psbt.combine_with(other)` or `v2::combine(this, that)`.
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>

mod error;
mod extract;
mod map;
#[cfg(feature = "miniscript")]
mod miniscript;

use core::fmt;
use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use bitcoin::bip32::{self, KeySource, Xpriv};
use bitcoin::hashes::Hash;
use bitcoin::key::{PrivateKey, PublicKey};
use bitcoin::locktime::absolute;
use bitcoin::secp256k1::{Message, Secp256k1, Signing};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{ecdsa, transaction, Amount, Sequence, Transaction, TxOut, Txid};

use crate::error::{write_err, FeeError, FundingUtxoError};
use crate::prelude::*;
use crate::v2::map::Map;

#[rustfmt::skip]                // Keep public exports separate.
#[doc(inline)]
pub use self::{
    error::{
        DeserializeError, DetermineLockTimeError, IndexOutOfBoundsError, InputsNotModifiableError,
        NotUnsignedError, OutputsNotModifiableError, PartialSigsSighashTypeError,
        PsbtNotModifiableError, SignError,
    },
    extract::{Extractor, ExtractError, ExtractTxError, ExtractTxFeeRateError},
    map::{
        // We do not re-export any of the input/output/global error types, use form `input::DecodeError`.
        global::{self, Global},
        input::{self, Input, InputBuilder},
        output::{self, Output, OutputBuilder},
    },
};
#[cfg(feature = "base64")]
pub use self::display_from_str::ParsePsbtError;
#[cfg(feature = "miniscript")]
pub use self::miniscript::{
    FinalizeError, FinalizeInputError, Finalizer, InputError, InterpreterCheckError,
    InterpreterCheckInputError,
};

/// Combines these two PSBTs as described by BIP-174 (i.e. combine is the same for BIP-370).
///
/// This function is commutative `combine(this, that) = combine(that, this)`.
pub fn combine(this: Psbt, that: Psbt) -> Result<Psbt, CombineError> { this.combine_with(that) }
// TODO: Consider adding an iterator API that combines a list of PSBTs.

/// Implements the BIP-370 Creator role.
///
/// The `Creator` type is only directly needed if one of the following holds:
///
/// - The creator and constructor are separate entities.
/// - You need to set the fallback lock time.
/// - You need to set the sighash single flag.
///
/// If not use the [`Constructor`]  to carry out both roles e.g., `Constructor::<Modifiable>::default()`.
///
/// See `examples/v2-separate-creator-constructor.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Creator(Psbt);

impl Creator {
    /// Creates a new PSBT Creator.
    pub fn new() -> Self {
        let psbt = Psbt {
            global: Global::default(),
            inputs: Default::default(),
            outputs: Default::default(),
        };
        Creator(psbt)
    }

    /// Sets the fallback lock time.
    pub fn fallback_lock_time(mut self, fallback: absolute::LockTime) -> Self {
        self.0.global.fallback_lock_time = Some(fallback);
        self
    }

    /// Sets the "has sighash single" flag in then transaction modifiable flags.
    pub fn sighash_single(mut self) -> Self {
        self.0.global.set_sighash_single_flag();
        self
    }

    /// Sets the inputs modifiable bit in the transaction modifiable flags.
    pub fn inputs_modifiable(mut self) -> Self {
        self.0.global.set_inputs_modifiable_flag();
        self
    }

    /// Sets the outputs modifiable bit in the transaction modifiable flags.
    pub fn outputs_modifiable(mut self) -> Self {
        self.0.global.set_outputs_modifiable_flag();
        self
    }

    /// Sets the transaction version.
    ///
    /// You likely do not need this, it is provided for completeness.
    ///
    /// The default is [`transaction::Version::TWO`].
    pub fn transaction_version(mut self, version: transaction::Version) -> Self {
        self.0.global.tx_version = version;
        self
    }

    /// Builds a [`Constructor`] that can add inputs and outputs.
    ///
    /// # Examples
    ///
    /// ```
    /// use psbt_v2::v2::{Creator, Constructor, Modifiable};
    ///
    /// // Creator role separate from Constructor role.
    /// let psbt = Creator::new()
    ///     .inputs_modifiable()
    ///     .outputs_modifiable()
    ///     .psbt();
    /// let _constructor = Constructor::<Modifiable>::new(psbt);
    ///
    /// // However, since a single entity is likely to be both a Creator and Constructor.
    /// let _constructor = Creator::new().constructor_modifiable();
    ///
    /// // Or the more terse:
    /// let _constructor = Constructor::<Modifiable>::default();
    /// ```
    pub fn constructor_modifiable(self) -> Constructor<Modifiable> {
        let mut psbt = self.0;
        psbt.global.set_inputs_modifiable_flag();
        psbt.global.set_outputs_modifiable_flag();
        Constructor(psbt, PhantomData)
    }

    /// Builds a [`Constructor`] that can only add inputs.
    ///
    /// # Examples
    ///
    /// ```
    /// use psbt_v2::v2::{Creator, Constructor, InputsOnlyModifiable};
    ///
    /// // Creator role separate from Constructor role.
    /// let psbt = Creator::new()
    ///     .inputs_modifiable()
    ///     .psbt();
    /// let _constructor = Constructor::<InputsOnlyModifiable>::new(psbt);
    ///
    /// // However, since a single entity is likely to be both a Creator and Constructor.
    /// let _constructor = Creator::new().constructor_inputs_only_modifiable();
    ///
    /// // Or the more terse:
    /// let _constructor = Constructor::<InputsOnlyModifiable>::default();
    /// ```
    pub fn constructor_inputs_only_modifiable(self) -> Constructor<InputsOnlyModifiable> {
        let mut psbt = self.0;
        psbt.global.set_inputs_modifiable_flag();
        psbt.global.clear_outputs_modifiable_flag();
        Constructor(psbt, PhantomData)
    }

    /// Builds a [`Constructor`] that can only add outputs.
    ///
    /// # Examples
    ///
    /// ```
    /// use psbt_v2::v2::{Creator, Constructor, OutputsOnlyModifiable};
    ///
    /// // Creator role separate from Constructor role.
    /// let psbt = Creator::new()
    ///     .inputs_modifiable()
    ///     .psbt();
    /// let _constructor = Constructor::<OutputsOnlyModifiable>::new(psbt);
    ///
    /// // However, since a single entity is likely to be both a Creator and Constructor.
    /// let _constructor = Creator::new().constructor_outputs_only_modifiable();
    ///
    /// // Or the more terse:
    /// let _constructor = Constructor::<OutputsOnlyModifiable>::default();
    /// ```
    pub fn constructor_outputs_only_modifiable(self) -> Constructor<OutputsOnlyModifiable> {
        let mut psbt = self.0;
        psbt.global.clear_inputs_modifiable_flag();
        psbt.global.set_outputs_modifiable_flag();
        Constructor(psbt, PhantomData)
    }

    /// Returns the created [`Psbt`].
    ///
    /// This is only required if the Creator and Constructor are separate entities. If the Creator
    /// is also acting as the Constructor use one of the `Self::constructor_foo` functions.
    pub fn psbt(self) -> Psbt { self.0 }
}

impl Default for Creator {
    fn default() -> Self { Self::new() }
}

/// Marker for a `Constructor` with both inputs and outputs modifiable.
pub enum Modifiable {}
/// Marker for a `Constructor` with inputs modifiable.
pub enum InputsOnlyModifiable {}
/// Marker for a `Constructor` with outputs modifiable.
pub enum OutputsOnlyModifiable {}

mod sealed {
    pub trait Mod {}
    impl Mod for super::Modifiable {}
    impl Mod for super::InputsOnlyModifiable {}
    impl Mod for super::OutputsOnlyModifiable {}
}

/// Marker for if either inputs or outputs are modifiable, or both.
pub trait Mod: sealed::Mod + Sync + Send + Sized + Unpin {}

impl Mod for Modifiable {}
impl Mod for InputsOnlyModifiable {}
impl Mod for OutputsOnlyModifiable {}

/// Implements the BIP-370 Constructor role.
///
/// Uses the builder pattern, and generics to make adding inputs and outputs infallible.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Constructor<T>(Psbt, PhantomData<T>);

impl<T: Mod> Constructor<T> {
    /// Marks that the `Psbt` can not have any more inputs added to it.
    pub fn no_more_inputs(mut self) -> Self {
        self.0.global.clear_inputs_modifiable_flag();
        self
    }

    /// Marks that the `Psbt` can not have any more outputs added to it.
    pub fn no_more_outputs(mut self) -> Self {
        self.0.global.clear_outputs_modifiable_flag();
        self
    }

    /// Returns a PSBT [`Updater`] once construction is completed.
    pub fn updater(self) -> Result<Updater, DetermineLockTimeError> {
        self.no_more_inputs().no_more_outputs().psbt().map(Updater)
    }

    /// Returns the [`Psbt`] in its current state.
    ///
    /// This function can be used either to get the [`Psbt`] to pass to another constructor or to
    /// get the [`Psbt`] ready for update if `no_more_inputs` and `no_more_outputs` have already
    /// explicitly been called.
    pub fn psbt(self) -> Result<Psbt, DetermineLockTimeError> {
        let _ = self.0.determine_lock_time()?;
        Ok(self.0)
    }
}

impl Constructor<Modifiable> {
    /// Creates a new Constructor.
    ///
    /// This function should only be needed if the PSBT Creator and Constructor roles are being
    /// performed by separate entities, if not use one of the builder functions on the [`Creator`]
    /// e.g., `constructor_modifiable()`.
    pub fn new(psbt: Psbt) -> Result<Self, PsbtNotModifiableError> {
        if !psbt.global.is_inputs_modifiable() {
            Err(InputsNotModifiableError.into())
        } else if !psbt.global.is_outputs_modifiable() {
            Err(OutputsNotModifiableError.into())
        } else {
            Ok(Self(psbt, PhantomData))
        }
    }

    /// Adds an input to the PSBT.
    pub fn input(mut self, input: Input) -> Self {
        self.0.inputs.push(input);
        self.0.global.input_count += 1;
        self
    }

    /// Adds an output to the PSBT.
    pub fn output(mut self, output: Output) -> Self {
        self.0.outputs.push(output);
        self.0.global.output_count += 1;
        self
    }
}
// Useful if the Creator and Constructor are a single entity.
impl Default for Constructor<Modifiable> {
    fn default() -> Self { Creator::new().constructor_modifiable() }
}

impl Constructor<InputsOnlyModifiable> {
    /// Creates a new Constructor.
    ///
    /// This function should only be needed if the PSBT Creator and Constructor roles are being
    /// performed by separate entities, if not use one of the builder functions on the [`Creator`]
    /// e.g., `constructor_modifiable()`.
    pub fn new(psbt: Psbt) -> Result<Self, InputsNotModifiableError> {
        if psbt.global.is_inputs_modifiable() {
            Ok(Self(psbt, PhantomData))
        } else {
            Err(InputsNotModifiableError)
        }
    }

    /// Adds an input to the PSBT.
    pub fn input(mut self, input: Input) -> Self {
        self.0.inputs.push(input);
        self.0.global.input_count += 1;
        self
    }
}

// Useful if the Creator and Constructor are a single entity.
impl Default for Constructor<InputsOnlyModifiable> {
    fn default() -> Self { Creator::new().constructor_inputs_only_modifiable() }
}

impl Constructor<OutputsOnlyModifiable> {
    /// Creates a new Constructor.
    ///
    /// This function should only be needed if the PSBT Creator and Constructor roles are being
    /// performed by separate entities, if not use one of the builder functions on the [`Creator`]
    /// e.g., `constructor_modifiable()`.
    pub fn new(psbt: Psbt) -> Result<Self, OutputsNotModifiableError> {
        if psbt.global.is_outputs_modifiable() {
            Ok(Self(psbt, PhantomData))
        } else {
            Err(OutputsNotModifiableError)
        }
    }

    /// Adds an output to the PSBT.
    pub fn output(mut self, output: Output) -> Self {
        self.0.outputs.push(output);
        self.0.global.output_count += 1;
        self
    }
}

// Useful if the Creator and Constructor are a single entity.
impl Default for Constructor<OutputsOnlyModifiable> {
    fn default() -> Self { Creator::new().constructor_outputs_only_modifiable() }
}

/// Implements the BIP-370 Updater role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Updater(Psbt);

impl Updater {
    /// Creates an `Updater`.
    ///
    /// An updater can only update a PSBT that has a valid combination of lock times.
    pub fn new(psbt: Psbt) -> Result<Self, DetermineLockTimeError> {
        let _ = psbt.determine_lock_time()?;
        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid {
        self.0.id().expect("Updater guarantees lock time can be determined")
    }

    /// Updater role, update the sequence number for input at `index`.
    pub fn set_sequence(
        mut self,
        n: Sequence,
        input_index: usize,
    ) -> Result<Updater, IndexOutOfBoundsError> {
        let input = self.0.checked_input_mut(input_index)?;
        input.sequence = Some(n);
        Ok(self)
    }

    // /// Converts the inner PSBT v2 to a PSBT v0.
    // pub fn into_psbt_v0(self) -> v0::Psbt {
    //     let unsigned_tx =
    //         self.0.unsigned_tx().expect("Updater guarantees lock time can be determined");
    //     let psbt = self.psbt();

    //     let global = psbt.global.into_v0(unsigned_tx);
    //     let inputs = psbt.inputs.into_iter().map(|input| input.into_v0()).collect();
    //     let outputs = psbt.outputs.into_iter().map(|output| output.into_v0()).collect();

    //     v0::Psbt { global, inputs, outputs }
    // }

    /// Returns the inner [`Psbt`].
    pub fn psbt(self) -> Psbt { self.0 }
}

impl TryFrom<Psbt> for Updater {
    type Error = DetermineLockTimeError;

    fn try_from(psbt: Psbt) -> Result<Self, Self::Error> { Self::new(psbt) }
}

/// Implements the BIP-370 Signer role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Signer(Psbt);

impl Signer {
    /// Creates a `Signer`.
    ///
    /// An updater can only update a PSBT that has a valid combination of lock times.
    pub fn new(psbt: Psbt) -> Result<Self, DetermineLockTimeError> {
        let _ = psbt.determine_lock_time()?;
        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Result<Txid, DetermineLockTimeError> { self.0.id() }

    /// Creates an unsigned transaction from the inner [`Psbt`].
    pub fn unsigned_tx(&self) -> Transaction {
        self.0.unsigned_tx().expect("Signer guarantees lock time can be determined")
    }

    /// Attempts to create _all_ the required signatures for this PSBT using `k`.
    ///
    /// **NOTE**: Taproot inputs are, as yet, not supported by this function. We currently only
    /// attempt to sign ECDSA inputs.
    ///
    /// If you just want to sign an input with one specific key consider using `sighash_ecdsa`. This
    /// function does not support scripts that contain `OP_CODESEPARATOR`.
    ///
    /// # Returns
    ///
    /// Either Ok(SigningKeys) or Err((SigningKeys, SigningErrors)), where
    /// - SigningKeys: A map of input index -> pubkey associated with secret key used to sign.
    /// - SigningKeys: A map of input index -> the error encountered while attempting to sign.
    ///
    /// If an error is returned some signatures may already have been added to the PSBT. Since
    /// `partial_sigs` is a [`BTreeMap`] it is safe to retry, previous sigs will be overwritten.
    pub fn sign<C, K>(
        self,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> Result<(Psbt, SigningKeys), (SigningKeys, SigningErrors)>
    where
        C: Signing,
        K: GetKey,
    {
        let tx = self.unsigned_tx();
        let mut psbt = self.psbt();

        psbt.sign(tx, k, secp).map(|signing_keys| (psbt, signing_keys))
    }

    /// Sets the PSBT_GLOBAL_TX_MODIFIABLE as required after signing an ECDSA input.
    ///
    /// > For PSBTv2s, a signer must update the PSBT_GLOBAL_TX_MODIFIABLE field after signing
    /// > inputs so that it accurately reflects the state of the PSBT.
    pub fn ecdsa_clear_tx_modifiable(&mut self, ty: EcdsaSighashType) {
        self.0.clear_tx_modifiable(ty as u8)
    }

    /// Returns the inner [`Psbt`].
    pub fn psbt(self) -> Psbt { self.0 }
}

/// A Partially Signed Transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Psbt {
    /// The global map.
    pub global: Global,
    /// The corresponding key-value map for each input in the unsigned transaction.
    pub inputs: Vec<Input>,
    /// The corresponding key-value map for each output in the unsigned transaction.
    pub outputs: Vec<Output>,
}

impl Psbt {
    // TODO: Add inherent methods to get each of the role types.

    /// Returns this PSBT's unique identification.
    fn id(&self) -> Result<Txid, DetermineLockTimeError> {
        let mut tx = self.unsigned_tx()?;
        // Updaters may change the sequence so to calculate ID we set it to zero.
        tx.input.iter_mut().for_each(|input| input.sequence = Sequence::ZERO);

        Ok(tx.txid())
    }

    /// Creates an unsigned transaction from the inner [`Psbt`].
    ///
    /// Quidado! this transaction should not be used to determine the ID of
    /// the [`Pbst`], use `Self::id()` instead.
    fn unsigned_tx(&self) -> Result<Transaction, DetermineLockTimeError> {
        let lock_time = self.determine_lock_time()?;

        Ok(Transaction {
            version: self.global.tx_version,
            lock_time,
            input: self.inputs.iter().map(|input| input.unsigned_tx_in()).collect(),
            output: self.outputs.iter().map(|ouput| ouput.tx_out()).collect(),
        })
    }

    /// Determines the lock time as specified in [BIP-370] if it is possible to do so.
    ///
    /// [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#determining-lock-time>
    pub fn determine_lock_time(&self) -> Result<absolute::LockTime, DetermineLockTimeError> {
        let require_time_based_lock_time =
            self.inputs.iter().any(|input| input.requires_time_based_lock_time());
        let require_height_based_lock_time =
            self.inputs.iter().any(|input| input.requires_height_based_lock_time());

        if require_time_based_lock_time && require_height_based_lock_time {
            return Err(DetermineLockTimeError);
        }

        let have_lock_time = self.inputs.iter().any(|input| input.has_lock_time());

        let lock = if have_lock_time {
            let all_inputs_satisfied_with_height_based_lock_time =
                self.inputs.iter().all(|input| input.is_satisfied_with_height_based_lock_time());

            // > The lock time chosen is then the maximum value of the chosen type of lock time.
            if all_inputs_satisfied_with_height_based_lock_time {
                // We either have only height based or we have both, in which case we must use height based.
                let height = self
                    .inputs
                    .iter()
                    .map(|input| input.min_height)
                    .max()
                    .expect("we know we have at least one non-none min_height field")
                    .expect("so we know that max is non-none");
                absolute::LockTime::from(height)
            } else {
                let time = self
                    .inputs
                    .iter()
                    .map(|input| input.min_time)
                    .max()
                    .expect("we know we have at least one non-none min_height field")
                    .expect("so we know that max is non-none");
                absolute::LockTime::from(time)
            }
        } else {
            // > If none of the inputs have a PSBT_IN_REQUIRED_TIME_LOCKTIME and
            // > PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, then PSBT_GLOBAL_FALLBACK_LOCKTIME must be used.
            // > If PSBT_GLOBAL_FALLBACK_LOCKTIME is not provided, then it is assumed to be 0.
            self.global.fallback_lock_time.unwrap_or(absolute::LockTime::ZERO)
        };

        Ok(lock)
    }

    /// Returns true if all inputs for this PSBT have been finalized.
    pub fn is_finalized(&self) -> bool { self.inputs.iter().all(|input| input.is_finalized()) }

    /// Serialize a value as bytes in hex.
    pub fn serialize_hex(&self) -> String { self.serialize().to_lower_hex_string() }

    /// Serialize as raw binary data
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        //  <magic>
        buf.extend_from_slice(b"psbt");

        buf.push(0xff_u8);

        buf.extend(self.global.serialize_map());

        for i in &self.inputs {
            buf.extend(i.serialize_map());
        }

        for i in &self.outputs {
            buf.extend(i.serialize_map());
        }

        buf
    }

    /// Deserialize a value from raw binary data.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        use DeserializeError::*;

        const MAGIC_BYTES: &[u8] = b"psbt";
        if bytes.get(0..MAGIC_BYTES.len()) != Some(MAGIC_BYTES) {
            return Err(InvalidMagic);
        }

        const PSBT_SERPARATOR: u8 = 0xff_u8;
        if bytes.get(MAGIC_BYTES.len()) != Some(&PSBT_SERPARATOR) {
            return Err(InvalidSeparator);
        }

        let mut d = bytes.get(5..).ok_or(NoMorePairs)?;

        let global = Global::decode(&mut d)?;

        let inputs: Vec<Input> = {
            let inputs_len: usize = global.input_count;
            let mut inputs: Vec<Input> = Vec::with_capacity(inputs_len);

            for _ in 0..inputs_len {
                inputs.push(Input::decode(&mut d)?);
            }

            inputs
        };

        let outputs: Vec<Output> = {
            let outputs_len: usize = global.output_count;
            let mut outputs: Vec<Output> = Vec::with_capacity(outputs_len);

            for _ in 0..outputs_len {
                outputs.push(Output::decode(&mut d)?)
            }

            outputs
        };

        Ok(Psbt { global, inputs, outputs })
    }

    /// Returns an iterator for the funding UTXOs of the psbt
    ///
    /// For each PSBT input that contains UTXO information `Ok` is returned containing that information.
    /// The order of returned items is same as the order of inputs.
    ///
    /// ## Errors
    ///
    /// The function returns error when UTXO information is not present or is invalid.
    pub fn iter_funding_utxos(&self) -> impl Iterator<Item = Result<&TxOut, FundingUtxoError>> {
        self.inputs.iter().map(|input| input.funding_utxo())
    }

    /// Combines this [`Psbt`] with `other` PSBT as described by BIP-174.
    ///
    /// BIP-370 does not include any additional requirements for the Combiner role.
    ///
    /// This function is commutative `A.combine_with(B) = B.combine_with(A)`.
    ///
    /// See [`combine()`] for a non-consuming version of this function.
    pub fn combine_with(mut self, other: Self) -> Result<Psbt, CombineError> {
        self.global.combine(other.global)?;

        for (self_input, other_input) in self.inputs.iter_mut().zip(other.inputs.into_iter()) {
            self_input.combine(other_input)?;
        }

        for (self_output, other_output) in self.outputs.iter_mut().zip(other.outputs.into_iter()) {
            self_output.combine(other_output)?;
        }

        Ok(self)
    }

    /// Sets the PSBT_GLOBAL_TX_MODIFIABLE as required after signing.
    // TODO: Consider using consts instead of magic numbers.
    fn clear_tx_modifiable(&mut self, sighash_type: u8) {
        let ty = sighash_type;
        // If the Signer added a signature that does not use SIGHASH_ANYONECANPAY,
        // the Input Modifiable flag must be set to False.
        if !(ty == 0x81 || ty == 0x82 || ty == 0x83) {
            self.global.clear_inputs_modifiable_flag();
        }

        // If the Signer added a signature that does not use SIGHASH_NONE,
        // the Outputs Modifiable flag must be set to False.
        if !(ty == 0x02 || ty == 0x82) {
            self.global.clear_outputs_modifiable_flag();
        }

        // If the Signer added a signature that uses SIGHASH_SINGLE,
        // the Has SIGHASH_SINGLE flag must be set to True.
        if ty == 0x03 || ty == 0x83 {
            self.global.set_sighash_single_flag();
        }
    }

    /// Attempts to create _all_ the required signatures for this PSBT using `k`.
    ///
    /// **NOTE**: Taproot inputs are, as yet, not supported by this function. We currently only
    /// attempt to sign ECDSA inputs.
    ///
    /// If you just want to sign an input with one specific key consider using `sighash_ecdsa`. This
    /// function does not support scripts that contain `OP_CODESEPARATOR`.
    ///
    /// # Returns
    ///
    /// Either Ok(SigningKeys) or Err((SigningKeys, SigningErrors)), where
    /// - SigningKeys: A map of input index -> pubkey associated with secret key used to sign.
    /// - SigningKeys: A map of input index -> the error encountered while attempting to sign.
    ///
    /// If an error is returned some signatures may already have been added to the PSBT. Since
    /// `partial_sigs` is a [`BTreeMap`] it is safe to retry, previous sigs will be overwritten.
    fn sign<C, K>(
        &mut self,
        tx: Transaction,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> Result<SigningKeys, (SigningKeys, SigningErrors)>
    where
        C: Signing,
        K: GetKey,
    {
        let mut cache = SighashCache::new(&tx);

        let mut used = BTreeMap::new();
        let mut errors = BTreeMap::new();

        for i in 0..self.global.input_count {
            if let Ok(SigningAlgorithm::Ecdsa) = self.signing_algorithm(i) {
                match self.bip32_sign_ecdsa(k, i, &mut cache, secp) {
                    Ok(v) => {
                        used.insert(i, v);
                    }
                    Err(e) => {
                        errors.insert(i, e);
                    }
                }
            };
        }
        if errors.is_empty() {
            Ok(used)
        } else {
            Err((used, errors))
        }
    }

    /// Attempts to create all signatures required by this PSBT's `bip32_derivation` field, adding
    /// them to `partial_sigs`.
    ///
    /// # Returns
    ///
    /// - Ok: A list of the public keys used in signing.
    /// - Err: Error encountered trying to calculate the sighash AND we had the signing key.
    fn bip32_sign_ecdsa<C, K, T>(
        &mut self,
        k: &K,
        input_index: usize,
        cache: &mut SighashCache<T>,
        secp: &Secp256k1<C>,
    ) -> Result<Vec<PublicKey>, SignError>
    where
        C: Signing,
        T: Borrow<Transaction>,
        K: GetKey,
    {
        let msg_sighash_ty_res = self.sighash_ecdsa(input_index, cache);
        let sighash_ty = msg_sighash_ty_res.clone().ok().map(|(_msg, sighash_ty)| sighash_ty);

        let input = &mut self.inputs[input_index]; // Index checked in call to `sighash_ecdsa`.
        let mut used = vec![]; // List of pubkeys used to sign the input.

        for (pk, key_source) in input.bip32_derivations.iter() {
            let sk = if let Ok(Some(sk)) = k.get_key(KeyRequest::Bip32(key_source.clone()), secp) {
                sk
            } else if let Ok(Some(sk)) = k.get_key(KeyRequest::Pubkey(PublicKey::new(*pk)), secp) {
                sk
            } else {
                continue;
            };

            // Only return the error if we have a secret key to sign this input.
            let (msg, sighash_ty) = match msg_sighash_ty_res {
                Err(e) => return Err(e),
                Ok((msg, sighash_ty)) => (msg, sighash_ty),
            };

            let sig =
                ecdsa::Signature { sig: secp.sign_ecdsa(&msg, &sk.inner), hash_ty: sighash_ty };

            let pk = sk.public_key(secp);

            input.partial_sigs.insert(pk, sig);
            used.push(pk);
        }

        let ty = sighash_ty.expect("at this stage we know its ok");
        self.clear_tx_modifiable(ty as u8);

        Ok(used)
    }

    /// Returns the sighash message to sign an ECDSA input along with the sighash type.
    ///
    /// Uses the [`EcdsaSighashType`] from this input if one is specified. If no sighash type is
    /// specified uses [`EcdsaSighashType::All`]. This function does not support scripts that
    /// contain `OP_CODESEPARATOR`.
    pub fn sighash_ecdsa<T: Borrow<Transaction>>(
        &self,
        input_index: usize,
        cache: &mut SighashCache<T>,
    ) -> Result<(Message, EcdsaSighashType), SignError> {
        use OutputType::*;

        if self.signing_algorithm(input_index)? != SigningAlgorithm::Ecdsa {
            return Err(SignError::WrongSigningAlgorithm);
        }

        let input = self.checked_input(input_index)?;
        let utxo = input.funding_utxo()?;
        let spk = &utxo.script_pubkey; // scriptPubkey for input spend utxo.

        let hash_ty = input.ecdsa_hash_ty().map_err(|_| SignError::InvalidSighashType)?; // Only support standard sighash types.

        match self.output_type(input_index)? {
            Bare => {
                let sighash = cache.legacy_signature_hash(input_index, spk, hash_ty.to_u32())?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            Sh => {
                let script_code =
                    input.redeem_script.as_ref().ok_or(SignError::MissingRedeemScript)?;
                let sighash =
                    cache.legacy_signature_hash(input_index, script_code, hash_ty.to_u32())?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            Wpkh => {
                let sighash = cache.p2wpkh_signature_hash(input_index, spk, utxo.value, hash_ty)?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            ShWpkh => {
                let redeem_script = input.redeem_script.as_ref().expect("checked above");
                let sighash =
                    cache.p2wpkh_signature_hash(input_index, redeem_script, utxo.value, hash_ty)?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            Wsh | ShWsh => {
                let witness_script =
                    input.witness_script.as_ref().ok_or(SignError::MissingWitnessScript)?;
                let sighash =
                    cache.p2wsh_signature_hash(input_index, witness_script, utxo.value, hash_ty)?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            Tr => {
                // This PSBT signing API is WIP, taproot to come shortly.
                Err(SignError::Unsupported)
            }
        }
    }

    /// Gets a reference to the input at `input_index` after checking that it is a valid index.
    fn checked_input(&self, index: usize) -> Result<&Input, IndexOutOfBoundsError> {
        self.check_input_index(index)?;
        Ok(&self.inputs[index])
    }

    /// Gets a mutable reference to the input at `input_index` after checking that it is a valid index.
    fn checked_input_mut(&mut self, index: usize) -> Result<&mut Input, IndexOutOfBoundsError> {
        self.check_input_index(index)?;
        Ok(&mut self.inputs[index])
    }
    /// Checks that `index` is valid for this PSBT.
    fn check_input_index(&self, index: usize) -> Result<(), IndexOutOfBoundsError> {
        if index >= self.inputs.len() {
            return Err(IndexOutOfBoundsError::Inputs { index, length: self.inputs.len() });
        }
        if index >= self.global.input_count {
            return Err(IndexOutOfBoundsError::Count { index, count: self.global.input_count });
        }
        Ok(())
    }

    /// Returns the algorithm used to sign this PSBT's input at `input_index`.
    fn signing_algorithm(&self, input_index: usize) -> Result<SigningAlgorithm, SignError> {
        let output_type = self.output_type(input_index)?;
        Ok(output_type.signing_algorithm())
    }

    /// Returns the [`OutputType`] of the spend utxo for this PBST's input at `input_index`.
    fn output_type(&self, input_index: usize) -> Result<OutputType, SignError> {
        let input = self.checked_input(input_index)?;
        let utxo = input.funding_utxo()?;
        let spk = utxo.script_pubkey.clone();

        // Anything that is not segwit and is not p2sh is `Bare`.
        if !(spk.is_witness_program() || spk.is_p2sh()) {
            return Ok(OutputType::Bare);
        }

        if spk.is_p2wpkh() {
            return Ok(OutputType::Wpkh);
        }

        if spk.is_p2wsh() {
            return Ok(OutputType::Wsh);
        }

        if spk.is_p2sh() {
            if input.redeem_script.as_ref().map(|s| s.is_p2wpkh()).unwrap_or(false) {
                return Ok(OutputType::ShWpkh);
            }
            if input.redeem_script.as_ref().map(|x| x.is_p2wsh()).unwrap_or(false) {
                return Ok(OutputType::ShWsh);
            }
            return Ok(OutputType::Sh);
        }

        if spk.is_p2tr() {
            return Ok(OutputType::Tr);
        }

        // Something is wrong with the input scriptPubkey or we do not know how to sign
        // because there has been a new softfork that we do not yet support.
        Err(SignError::UnknownOutputType)
    }

    /// Calculates transaction fee.
    ///
    /// 'Fee' being the amount that will be paid for mining a transaction with the current inputs
    /// and outputs i.e., the difference in value of the total inputs and the total outputs.
    pub fn fee(&self) -> Result<Amount, FeeError> {
        use FeeError::*;

        // For the inputs we have to get the value from the input UTXOs.
        let mut input_value: u64 = 0;
        for input in self.iter_funding_utxos() {
            input_value = input_value.checked_add(input?.value.to_sat()).ok_or(InputOverflow)?;
        }
        // For the outputs we have the value directly in the `Output`.
        let mut output_value: u64 = 0;
        for output in &self.outputs {
            output_value =
                output_value.checked_add(output.amount.to_sat()).ok_or(OutputOverflow)?;
        }

        input_value.checked_sub(output_value).map(Amount::from_sat).ok_or(Negative)
    }

    /// Checks the sighash types of input partial sigs (ECDSA).
    ///
    /// This can be used at anytime but is primarily used during PSBT finalizing.
    #[cfg(feature = "miniscript")]
    pub(crate) fn check_partial_sigs_sighash_type(
        &self,
    ) -> Result<(), PartialSigsSighashTypeError> {
        use PartialSigsSighashTypeError::*;

        for (input_index, input) in self.inputs.iter().enumerate() {
            let target_ecdsa_sighash_ty = match input.sighash_type {
                Some(psbt_hash_ty) => psbt_hash_ty
                    .ecdsa_hash_ty()
                    .map_err(|error| NonStandardInputSighashType { input_index, error })?,
                None => EcdsaSighashType::All,
            };

            for (key, ecdsa_sig) in &input.partial_sigs {
                let flag = EcdsaSighashType::from_standard(ecdsa_sig.hash_ty as u32)
                    .map_err(|error| NonStandardPartialSigsSighashType { input_index, error })?;
                if target_ecdsa_sighash_ty != flag {
                    return Err(WrongSighashFlag {
                        input_index,
                        required: target_ecdsa_sighash_ty,
                        got: flag,
                        pubkey: *key,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Data required to call [`GetKey`] to get the private key to sign an input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyRequest {
    /// Request a private key using the associated public key.
    Pubkey(PublicKey),
    /// Request a private key using BIP-32 fingerprint and derivation path.
    Bip32(KeySource),
}

/// Trait to get a private key from a key request, key is then used to sign an input.
pub trait GetKey {
    /// An error occurred while getting the key.
    type Error: core::fmt::Debug;

    /// Attempts to get the private key for `key_request`.
    ///
    /// # Returns
    /// - `Some(key)` if the key is found.
    /// - `None` if the key was not found but no error was encountered.
    /// - `Err` if an error was encountered while looking for the key.
    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error>;
}

impl GetKey for Xpriv {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(_) => Err(GetKeyError::NotSupported),
            KeyRequest::Bip32((fingerprint, path)) => {
                let key = if self.fingerprint(secp) == fingerprint {
                    let k = self.derive_priv(secp, &path)?;
                    Some(k.to_priv())
                } else {
                    None
                };
                Ok(key)
            }
        }
    }
}

/// Map of input index -> pubkey associated with secret key used to create signature for that input.
pub type SigningKeys = BTreeMap<usize, Vec<PublicKey>>;

/// Map of input index -> the error encountered while attempting to sign that input.
pub type SigningErrors = BTreeMap<usize, SignError>;

#[rustfmt::skip]
macro_rules! impl_get_key_for_set {
    ($set:ident) => {

impl GetKey for $set<Xpriv> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(_) => Err(GetKeyError::NotSupported),
            KeyRequest::Bip32((fingerprint, path)) => {
                for xpriv in self.iter() {
                    if xpriv.parent_fingerprint == fingerprint {
                        let k = xpriv.derive_priv(secp, &path)?;
                        return Ok(Some(k.to_priv()));
                    }
                }
                Ok(None)
            }
        }
    }
}}}

impl_get_key_for_set!(BTreeSet);
#[cfg(feature = "std")]
impl_get_key_for_set!(HashSet);

#[rustfmt::skip]
macro_rules! impl_get_key_for_map {
    ($map:ident) => {

impl GetKey for $map<PublicKey, PrivateKey> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        _: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(pk) => Ok(self.get(&pk).cloned()),
            KeyRequest::Bip32(_) => Err(GetKeyError::NotSupported),
        }
    }
}}}
impl_get_key_for_map!(BTreeMap);
#[cfg(feature = "std")]
impl_get_key_for_map!(HashMap);

/// Errors when getting a key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GetKeyError {
    /// A bip32 error.
    Bip32(bip32::Error),
    /// The GetKey operation is not supported for this key request.
    NotSupported,
}

impl fmt::Display for GetKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use GetKeyError::*;

        match *self {
            Bip32(ref e) => write_err!(f, "a bip23 error"; e),
            NotSupported =>
                f.write_str("the GetKey operation is not supported for this key request"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use GetKeyError::*;

        match *self {
            NotSupported => None,
            Bip32(ref e) => Some(e),
        }
    }
}

impl From<bip32::Error> for GetKeyError {
    fn from(e: bip32::Error) -> Self { GetKeyError::Bip32(e) }
}

/// The various output types supported by the Bitcoin network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum OutputType {
    /// An output of type: pay-to-pubkey or pay-to-pubkey-hash.
    Bare,
    /// A pay-to-witness-pubkey-hash output (P2WPKH).
    Wpkh,
    /// A pay-to-witness-script-hash output (P2WSH).
    Wsh,
    /// A nested segwit output, pay-to-witness-pubkey-hash nested in a pay-to-script-hash.
    ShWpkh,
    /// A nested segwit output, pay-to-witness-script-hash nested in a pay-to-script-hash.
    ShWsh,
    /// A pay-to-script-hash output excluding wrapped segwit (P2SH).
    Sh,
    /// A taproot output (P2TR).
    Tr,
}

impl OutputType {
    /// The signing algorithm used to sign this output type.
    pub fn signing_algorithm(&self) -> SigningAlgorithm {
        use OutputType::*;

        match self {
            Bare | Wpkh | Wsh | ShWpkh | ShWsh | Sh => SigningAlgorithm::Ecdsa,
            Tr => SigningAlgorithm::Schnorr,
        }
    }
}

/// Signing algorithms supported by the Bitcoin network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningAlgorithm {
    /// The Elliptic Curve Digital Signature Algorithm (see [wikipedia]).
    ///
    /// [wikipedia]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    Ecdsa,
    /// The Schnorr signature algorithm (see [wikipedia]).
    ///
    /// [wikipedia]: https://en.wikipedia.org/wiki/Schnorr_signature
    Schnorr,
}

/// An error occurred while decoding a v2 PSBT.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// Magic bytes for a PSBT must be the ASCII for "psbt" serialized in most
    /// significant byte order.
    InvalidMagic,
    /// The separator for a PSBT must be `0xff`.
    InvalidSeparator,
    /// Signals that there are no more key-value pairs in a key-value map.
    NoMorePairs,
    /// Error decoding global map.
    Global(global::DecodeError),
    /// Error decoding input map.
    Input(input::DecodeError),
    /// Error decoding output map.
    Output(output::DecodeError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecodeError::*;

        match *self {
            InvalidMagic => f.write_str("invalid magic"),
            InvalidSeparator => f.write_str("invalid separator"),
            NoMorePairs => f.write_str("no more key-value pairs for this psbt map"),
            Global(ref e) => write_err!(f, "global map decode error"; e),
            Input(ref e) => write_err!(f, "input map decode error"; e),
            Output(ref e) => write_err!(f, "output map decode error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DecodeError::*;

        match *self {
            InvalidMagic | InvalidSeparator | NoMorePairs => None,
            Global(ref e) => Some(e),
            Input(ref e) => Some(e),
            Output(ref e) => Some(e),
        }
    }
}

impl From<global::DecodeError> for DecodeError {
    fn from(e: global::DecodeError) -> Self { Self::Global(e) }
}

impl From<input::DecodeError> for DecodeError {
    fn from(e: input::DecodeError) -> Self { Self::Input(e) }
}

impl From<output::DecodeError> for DecodeError {
    fn from(e: output::DecodeError) -> Self { Self::Output(e) }
}

/// If the "base64" feature is enabled we implement `Display` and `FromStr` using base64 encoding.
#[cfg(feature = "base64")]
mod display_from_str {
    use core::fmt::{self, Display, Formatter};
    use core::str::FromStr;

    use bitcoin::base64::display::Base64Display;
    use bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};

    use super::*;

    impl Display for Psbt {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}", Base64Display::new(&self.serialize(), &BASE64_STANDARD))
        }
    }

    impl FromStr for Psbt {
        type Err = ParsePsbtError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let data = BASE64_STANDARD.decode(s).map_err(ParsePsbtError::Base64Encoding)?;
            Psbt::deserialize(&data).map_err(ParsePsbtError::PsbtEncoding)
        }
    }

    /// Error encountered during PSBT decoding from Base64 string.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum ParsePsbtError {
        /// Error in internal PSBT data structure.
        PsbtEncoding(DeserializeError),
        /// Error in PSBT Base64 encoding.
        Base64Encoding(bitcoin::base64::DecodeError),
    }

    impl Display for ParsePsbtError {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            use self::ParsePsbtError::*;

            match *self {
                PsbtEncoding(ref e) => write_err!(f, "error in internal PSBT data structure"; e),
                Base64Encoding(ref e) => write_err!(f, "error in PSBT base64 encoding"; e),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for ParsePsbtError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            use self::ParsePsbtError::*;

            match self {
                PsbtEncoding(e) => Some(e),
                Base64Encoding(e) => Some(e),
            }
        }
    }
}

/// Error combining two input maps.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CombineError {
    /// Error while combining the global maps.
    Global(global::CombineError),
    /// Error while combining the input maps.
    Input(input::CombineError),
    /// Error while combining the output maps.
    Output(output::CombineError),
}

impl fmt::Display for CombineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CombineError::*;

        match *self {
            Global(ref e) => write_err!(f, "error while combining the global maps"; e),
            Input(ref e) => write_err!(f, "error while combining the input maps"; e),
            Output(ref e) => write_err!(f, "error while combining the output maps"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CombineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use CombineError::*;

        match *self {
            Global(ref e) => Some(e),
            Input(ref e) => Some(e),
            Output(ref e) => Some(e),
        }
    }
}

impl From<global::CombineError> for CombineError {
    fn from(e: global::CombineError) -> Self { Self::Global(e) }
}

impl From<input::CombineError> for CombineError {
    fn from(e: input::CombineError) -> Self { Self::Input(e) }
}

impl From<output::CombineError> for CombineError {
    fn from(e: output::CombineError) -> Self { Self::Output(e) }
}
