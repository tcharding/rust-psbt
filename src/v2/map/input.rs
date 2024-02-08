// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;
use core::fmt;

use bitcoin::bip32::KeySource;
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash as _};
use bitcoin::hex::DisplayHex;
use bitcoin::key::{PublicKey, XOnlyPublicKey};
use bitcoin::locktime::absolute;
use bitcoin::sighash::{EcdsaSighashType, NonStandardSighashTypeError, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash};
use bitcoin::{
    ecdsa, hashes, secp256k1, taproot, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};

use crate::consts::{
    PSBT_IN_BIP32_DERIVATION, PSBT_IN_FINAL_SCRIPTSIG, PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_HASH160, PSBT_IN_HASH256, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_PARTIAL_SIG, PSBT_IN_PREVIOUS_TXID, PSBT_IN_PROPRIETARY, PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, PSBT_IN_REQUIRED_TIME_LOCKTIME, PSBT_IN_RIPEMD160,
    PSBT_IN_SEQUENCE, PSBT_IN_SHA256, PSBT_IN_SIGHASH_TYPE, PSBT_IN_TAP_BIP32_DERIVATION,
    PSBT_IN_TAP_INTERNAL_KEY, PSBT_IN_TAP_KEY_SIG, PSBT_IN_TAP_LEAF_SCRIPT,
    PSBT_IN_TAP_MERKLE_ROOT, PSBT_IN_TAP_SCRIPT_SIG, PSBT_IN_WITNESS_SCRIPT, PSBT_IN_WITNESS_UTXO,
};
use crate::error::{write_err, FundingUtxoError};
use crate::prelude::*;
use crate::serialize::{Deserialize, Serialize};
use crate::sighash_type::{InvalidSighashTypeError, PsbtSighashType};
use crate::v2::map::Map;
use crate::{io, raw, serialize};

/// A key-value map for an input of the corresponding index in the unsigned
/// transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Input {
    /// The txid of the previous transaction whose output at `self.spent_output_index` is being spent.
    ///
    /// In other words, the output being spent by this `Input` is:
    ///
    ///  `OutPoint { txid: self.previous_txid, vout: self.spent_output_index }`
    pub previous_txid: Txid,

    /// The index of the output being spent in the transaction with the txid of `self.previous_txid`.
    pub spent_output_index: u32,

    /// The sequence number of this input.
    ///
    /// If omitted, assumed to be the final sequence number ([`Sequence::MAX`]).
    pub sequence: Option<Sequence>,

    /// The minimum Unix timestamp that this input requires to be set as the transaction's lock time.
    pub min_time: Option<absolute::Time>,

    /// The minimum block height that this input requires to be set as the transaction's lock time.
    pub min_height: Option<absolute::Height>,

    /// The non-witness transaction this input spends from. Should only be
    /// `Option::Some` for inputs which spend non-segwit outputs or
    /// if it is unknown whether an input spends a segwit output.
    pub non_witness_utxo: Option<Transaction>,
    /// The transaction output this input spends from. Should only be
    /// `Option::Some` for inputs which spend segwit outputs,
    /// including P2SH embedded ones.
    pub witness_utxo: Option<TxOut>,
    /// A map from public keys to their corresponding signature as would be
    /// pushed to the stack from a scriptSig or witness for a non-taproot inputs.
    pub partial_sigs: BTreeMap<PublicKey, ecdsa::Signature>,
    /// The sighash type to be used for this input. Signatures for this input
    /// must use the sighash type.
    pub sighash_type: Option<PsbtSighashType>,
    /// The redeem script for this input.
    pub redeem_script: Option<ScriptBuf>,
    /// The witness script for this input.
    pub witness_script: Option<ScriptBuf>,
    /// A map from public keys needed to sign this input to their corresponding
    /// master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivations: BTreeMap<secp256k1::PublicKey, KeySource>,
    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    pub final_script_sig: Option<ScriptBuf>,
    /// The finalized, fully-constructed scriptWitness with signatures and any
    /// other scripts necessary for this input to pass validation.
    pub final_script_witness: Option<Witness>,
    /// TODO: Proof of reserves commitment
    /// RIPEMD160 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub ripemd160_preimages: BTreeMap<ripemd160::Hash, Vec<u8>>,
    /// SHA256 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub sha256_preimages: BTreeMap<sha256::Hash, Vec<u8>>,
    /// HSAH160 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub hash160_preimages: BTreeMap<hash160::Hash, Vec<u8>>,
    /// HAS256 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub hash256_preimages: BTreeMap<sha256d::Hash, Vec<u8>>,
    /// Serialized taproot signature with sighash type for key spend.
    pub tap_key_sig: Option<taproot::Signature>,
    /// Map of `<xonlypubkey>|<leafhash>` with signature.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_script_sigs: BTreeMap<(XOnlyPublicKey, TapLeafHash), taproot::Signature>,
    /// Map of Control blocks to Script version pair.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_scripts: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>,
    /// Map of tap root x only keys to origin info and leaf hashes contained in it.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    /// Taproot Internal key.
    pub tap_internal_key: Option<XOnlyPublicKey>,
    /// Taproot Merkle root.
    pub tap_merkle_root: Option<TapNodeHash>,
    /// Proprietary key-value pairs for this input.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this input.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknowns: BTreeMap<raw::Key, Vec<u8>>,
}

impl Input {
    /// Creates a new `Input` that spends the `previous_output`.
    pub fn new(previous_output: &OutPoint) -> Self {
        Input {
            previous_txid: previous_output.txid,
            spent_output_index: previous_output.vout,
            sequence: None,
            min_time: None,
            min_height: None,
            non_witness_utxo: None,
            witness_utxo: None,
            partial_sigs: BTreeMap::new(),
            sighash_type: None,
            redeem_script: None,
            witness_script: None,
            bip32_derivations: BTreeMap::new(),
            final_script_sig: None,
            final_script_witness: None,
            ripemd160_preimages: BTreeMap::new(),
            sha256_preimages: BTreeMap::new(),
            hash160_preimages: BTreeMap::new(),
            hash256_preimages: BTreeMap::new(),
            tap_key_sig: None,
            tap_script_sigs: BTreeMap::new(),
            tap_scripts: BTreeMap::new(),
            tap_key_origins: BTreeMap::new(),
            tap_internal_key: None,
            tap_merkle_root: None,
            proprietaries: BTreeMap::new(),
            unknowns: BTreeMap::new(),
        }
    }

    // /// Converts this `Input` to a `v0::Input`.
    // pub(crate) fn into_v0(self) -> v0::Input {
    //     v0::Input {
    //         non_witness_utxo: self.non_witness_utxo,
    //         witness_utxo: self.witness_utxo,
    //         partial_sigs: self.partial_sigs,
    //         sighash_type: self.sighash_type,
    //         redeem_script: self.redeem_script,
    //         witness_script: self.witness_script,
    //         bip32_derivation: self.bip32_derivations,
    //         final_script_sig: self.final_script_sig,
    //         final_script_witness: self.final_script_witness,
    //         ripemd160_preimages: self.ripemd160_preimages,
    //         sha256_preimages: self.sha256_preimages,
    //         hash160_preimages: self.hash160_preimages,
    //         hash256_preimages: self.hash256_preimages,
    //         tap_key_sig: self.tap_key_sig,
    //         tap_script_sigs: self.tap_script_sigs,
    //         tap_scripts: self.tap_scripts,
    //         tap_key_origins: self.tap_key_origins,
    //         tap_internal_key: self.tap_internal_key,
    //         tap_merkle_root: self.tap_merkle_root,
    //         proprietary: self.proprietaries,
    //         unknown: self.unknowns,
    //     }
    // }

    /// Creates a new finalized input.
    ///
    /// Note the `Witness` is not optional because `miniscript` returns an empty `Witness` in the
    /// case that this is a legacy input.
    ///
    /// The `final_script_sig` and `final_script_witness` should come from `miniscript`.
    #[cfg(feature = "miniscript")]
    pub(crate) fn finalize(
        &self,
        final_script_sig: ScriptBuf,
        final_script_witness: Witness,
    ) -> Result<Input, FinalizeError> {
        debug_assert!(self.has_funding_utxo());

        let mut ret = Input {
            previous_txid: self.previous_txid,
            spent_output_index: self.spent_output_index,
            non_witness_utxo: self.non_witness_utxo.clone(),
            witness_utxo: self.witness_utxo.clone(),

            // Set below.
            final_script_sig: None,
            final_script_witness: None,

            // Clear everything else.
            sequence: None,
            min_time: None,
            min_height: None,
            partial_sigs: BTreeMap::new(),
            sighash_type: None,
            redeem_script: None,
            witness_script: None,
            bip32_derivations: BTreeMap::new(),
            ripemd160_preimages: BTreeMap::new(),
            sha256_preimages: BTreeMap::new(),
            hash160_preimages: BTreeMap::new(),
            hash256_preimages: BTreeMap::new(),
            tap_key_sig: None,
            tap_script_sigs: BTreeMap::new(),
            tap_scripts: BTreeMap::new(),
            tap_key_origins: BTreeMap::new(),
            tap_internal_key: None,
            tap_merkle_root: None,
            proprietaries: BTreeMap::new(),
            unknowns: BTreeMap::new(),
        };

        // TODO: These errors should only trigger if there are bugs in this crate or miniscript.
        // Is there an infallible way to do this?
        if self.witness_utxo.is_some() {
            if final_script_witness.is_empty() {
                return Err(FinalizeError::EmptyWitness);
            }
            ret.final_script_sig = Some(final_script_sig);
            ret.final_script_witness = Some(final_script_witness);
        } else {
            // TODO: Any checks should do here?
            ret.final_script_sig = Some(final_script_sig);
        }

        Ok(ret)
    }

    // TODO: Work out if this is in line with bip-370
    #[cfg(feature = "miniscript")]
    pub(crate) fn lock_time(&self) -> absolute::LockTime {
        match (self.min_height, self.min_time) {
            // If we have both, bip says use height.
            (Some(height), Some(_)) => height.into(),
            (Some(height), None) => height.into(),
            (None, Some(time)) => time.into(),
            // TODO: Check this is correct.
            (None, None) => absolute::LockTime::ZERO,
        }
    }

    pub(crate) fn has_lock_time(&self) -> bool {
        self.min_time.is_some() || self.min_height.is_some()
    }

    pub(crate) fn is_satisfied_with_height_based_lock_time(&self) -> bool {
        self.requires_height_based_lock_time()
            || self.min_time.is_some() && self.min_height.is_some()
            || self.min_time.is_none() && self.min_height.is_none()
    }

    pub(crate) fn requires_time_based_lock_time(&self) -> bool {
        self.min_time.is_some() && self.min_height.is_none()
    }

    pub(crate) fn requires_height_based_lock_time(&self) -> bool {
        self.min_height.is_some() && self.min_time.is_none()
    }

    /// Constructs a [`TxIn`] for this input, excluding any signature material.
    pub(crate) fn unsigned_tx_in(&self) -> TxIn {
        TxIn {
            previous_output: self.out_point(),
            script_sig: ScriptBuf::default(),
            // TODO: Check this ZERO is correct.
            sequence: self.sequence.unwrap_or(Sequence::ZERO),
            witness: Witness::default(),
        }
    }

    /// Constructs a signed [`TxIn`] for this input.
    ///
    /// Should only be called on a finalized PSBT.
    pub(crate) fn signed_tx_in(&self) -> TxIn {
        debug_assert!(self.is_finalized());

        let script_sig = self.final_script_sig.as_ref().expect("checked by is_finalized");
        let witness = self.final_script_witness.as_ref().expect("checked by is_finalized");

        TxIn {
            previous_output: self.out_point(),
            script_sig: script_sig.clone(),
            // TODO: Check this MAX is correct.
            sequence: self.sequence.unwrap_or(Sequence::MAX),
            witness: witness.clone(),
        }
    }

    #[cfg(feature = "miniscript")]
    pub(crate) fn has_funding_utxo(&self) -> bool { self.funding_utxo().is_ok() }

    /// Returns a reference to the funding utxo for this input.
    pub fn funding_utxo(&self) -> Result<&TxOut, FundingUtxoError> {
        if let Some(ref utxo) = self.witness_utxo {
            Ok(utxo)
        } else if let Some(ref tx) = self.non_witness_utxo {
            let vout = self.spent_output_index as usize;
            tx.output.get(vout).ok_or(FundingUtxoError::OutOfBounds { vout, len: tx.output.len() })
        } else {
            Err(FundingUtxoError::MissingUtxo)
        }
    }

    /// Returns true if this input has been finalized.
    ///
    /// > It checks whether all inputs have complete scriptSigs and scriptWitnesses by checking for
    /// the presence of 0x07 Finalized scriptSig and 0x08 Finalized scriptWitness typed records.
    ///
    /// Therefore a finalized input must have both `final_script_sig` and `final_script_witness`
    /// fields set. For legacy transactions the `final_script_witness` will be an empty [`Witness`].
    pub fn is_finalized(&self) -> bool {
        self.final_script_sig.is_some() && self.final_script_witness.is_some()
    }

    /// TODO: Use this.
    #[allow(dead_code)]
    fn has_sig_data(&self) -> bool {
        !(self.partial_sigs.is_empty()
            && self.tap_key_sig.is_none()
            && self.tap_script_sigs.is_empty())
    }

    fn out_point(&self) -> OutPoint {
        OutPoint { txid: self.previous_txid, vout: self.spent_output_index }
    }

    /// Obtains the [`EcdsaSighashType`] for this input if one is specified. If no sighash type is
    /// specified, returns [`EcdsaSighashType::All`].
    ///
    /// # Errors
    ///
    /// If the `sighash_type` field is set to a non-standard ECDSA sighash value.
    pub fn ecdsa_hash_ty(&self) -> Result<EcdsaSighashType, NonStandardSighashTypeError> {
        self.sighash_type
            .map(|sighash_type| sighash_type.ecdsa_hash_ty())
            .unwrap_or(Ok(EcdsaSighashType::All))
    }

    /// Obtains the [`TapSighashType`] for this input if one is specified. If no sighash type is
    /// specified, returns [`TapSighashType::Default`].
    ///
    /// # Errors
    ///
    /// If the `sighash_type` field is set to a invalid Taproot sighash value.
    pub fn taproot_hash_ty(&self) -> Result<TapSighashType, InvalidSighashTypeError> {
        self.sighash_type
            .map(|sighash_type| sighash_type.taproot_hash_ty())
            .unwrap_or(Ok(TapSighashType::Default))
    }

    pub(in crate::v2) fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, DecodeError> {
        // These are placeholder values that never exist in a encode `Input`.
        let invalid = OutPoint { txid: Txid::all_zeros(), vout: u32::MAX };
        let mut rv = Self::new(&invalid);

        loop {
            match raw::Pair::decode(r) {
                Ok(pair) => rv.insert_pair(pair)?,
                Err(serialize::Error::NoMorePairs) => break,
                Err(e) => return Err(DecodeError::DeserPair(e)),
            }
        }

        if rv.previous_txid == Txid::all_zeros() {
            return Err(DecodeError::MissingPreviousTxid);
        }
        if rv.spent_output_index == u32::MAX {
            return Err(DecodeError::MissingSpentOutputIndex);
        }
        Ok(rv)
    }

    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), InsertPairError> {
        let raw::Pair { key: raw_key, value: raw_value } = pair;

        match raw_key.type_value {
            PSBT_IN_PREVIOUS_TXID => {
                if self.previous_txid != Txid::all_zeros() {
                    return Err(InsertPairError::DuplicateKey(raw_key));
                }
                let txid: Txid = Deserialize::deserialize(&raw_value)?;
                self.previous_txid = txid;
            }
            PSBT_IN_OUTPUT_INDEX => {
                if self.spent_output_index != u32::MAX {
                    return Err(InsertPairError::DuplicateKey(raw_key));
                }
                let vout: u32 = Deserialize::deserialize(&raw_value)?;
                self.spent_output_index = vout;
            }
            PSBT_IN_SEQUENCE => {
                v2_impl_psbt_insert_pair! {
                    self.sequence <= <raw_key: _>|<raw_value: Sequence>
                }
            }
            PSBT_IN_REQUIRED_TIME_LOCKTIME => {
                v2_impl_psbt_insert_pair! {
                    self.min_time <= <raw_key: _>|<raw_value: absolute::Time>
                }
            }
            PSBT_IN_REQUIRED_HEIGHT_LOCKTIME => {
                v2_impl_psbt_insert_pair! {
                    self.min_height <= <raw_key: _>|<raw_value: absolute::Height>
                }
            }
            PSBT_IN_WITNESS_UTXO => {
                v2_impl_psbt_insert_pair! {
                    self.witness_utxo <= <raw_key: _>|<raw_value: TxOut>
                }
            }
            PSBT_IN_PARTIAL_SIG => {
                v2_impl_psbt_insert_pair! {
                    self.partial_sigs <= <raw_key: PublicKey>|<raw_value: ecdsa::Signature>
                }
            }
            PSBT_IN_SIGHASH_TYPE => {
                v2_impl_psbt_insert_pair! {
                    self.sighash_type <= <raw_key: _>|<raw_value: PsbtSighashType>
                }
            }
            PSBT_IN_REDEEM_SCRIPT => {
                v2_impl_psbt_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_IN_WITNESS_SCRIPT => {
                v2_impl_psbt_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_IN_BIP32_DERIVATION => {
                v2_impl_psbt_insert_pair! {
                    self.bip32_derivations <= <raw_key: secp256k1::PublicKey>|<raw_value: KeySource>
                }
            }
            PSBT_IN_FINAL_SCRIPTSIG => {
                v2_impl_psbt_insert_pair! {
                    self.final_script_sig <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_IN_FINAL_SCRIPTWITNESS => {
                v2_impl_psbt_insert_pair! {
                    self.final_script_witness <= <raw_key: _>|<raw_value: Witness>
                }
            }
            PSBT_IN_RIPEMD160 => {
                psbt_insert_hash_pair(
                    &mut self.ripemd160_preimages,
                    raw_key,
                    raw_value,
                    HashType::Ripemd,
                )?;
            }
            PSBT_IN_SHA256 => {
                psbt_insert_hash_pair(
                    &mut self.sha256_preimages,
                    raw_key,
                    raw_value,
                    HashType::Sha256,
                )?;
            }
            PSBT_IN_HASH160 => {
                psbt_insert_hash_pair(
                    &mut self.hash160_preimages,
                    raw_key,
                    raw_value,
                    HashType::Hash160,
                )?;
            }
            PSBT_IN_HASH256 => {
                psbt_insert_hash_pair(
                    &mut self.hash256_preimages,
                    raw_key,
                    raw_value,
                    HashType::Hash256,
                )?;
            }
            PSBT_IN_TAP_KEY_SIG => {
                v2_impl_psbt_insert_pair! {
                    self.tap_key_sig <= <raw_key: _>|<raw_value: taproot::Signature>
                }
            }
            PSBT_IN_TAP_SCRIPT_SIG => {
                v2_impl_psbt_insert_pair! {
                    self.tap_script_sigs <= <raw_key: (XOnlyPublicKey, TapLeafHash)>|<raw_value: taproot::Signature>
                }
            }
            PSBT_IN_TAP_LEAF_SCRIPT => {
                v2_impl_psbt_insert_pair! {
                    self.tap_scripts <= <raw_key: ControlBlock>|< raw_value: (ScriptBuf, LeafVersion)>
                }
            }
            PSBT_IN_TAP_BIP32_DERIVATION => {
                v2_impl_psbt_insert_pair! {
                    self.tap_key_origins <= <raw_key: XOnlyPublicKey>|< raw_value: (Vec<TapLeafHash>, KeySource)>
                }
            }
            PSBT_IN_TAP_INTERNAL_KEY => {
                v2_impl_psbt_insert_pair! {
                    self.tap_internal_key <= <raw_key: _>|< raw_value: XOnlyPublicKey>
                }
            }
            PSBT_IN_TAP_MERKLE_ROOT => {
                v2_impl_psbt_insert_pair! {
                    self.tap_merkle_root <= <raw_key: _>|< raw_value: TapNodeHash>
                }
            }
            PSBT_IN_PROPRIETARY => {
                let key = raw::ProprietaryKey::try_from(raw_key.clone())?;
                match self.proprietaries.entry(key) {
                    btree_map::Entry::Vacant(empty_key) => {
                        empty_key.insert(raw_value);
                    }
                    btree_map::Entry::Occupied(_) =>
                        return Err(InsertPairError::DuplicateKey(raw_key)),
                }
            }
            // Note, PSBT v2 does not exclude any keys from the input map.
            _ => match self.unknowns.entry(raw_key) {
                btree_map::Entry::Vacant(empty_key) => {
                    empty_key.insert(raw_value);
                }
                btree_map::Entry::Occupied(k) =>
                    return Err(InsertPairError::DuplicateKey(k.key().clone())),
            },
        }

        Ok(())
    }

    /// Combines this [`Input`] with `other`.
    pub fn combine(&mut self, other: Self) -> Result<(), CombineError> {
        if self.previous_txid != other.previous_txid {
            return Err(CombineError::PreviousTxidMismatch {
                this: self.previous_txid,
                that: other.previous_txid,
            });
        }

        if self.spent_output_index != other.spent_output_index {
            return Err(CombineError::SpentOutputIndexMismatch {
                this: self.spent_output_index,
                that: other.spent_output_index,
            });
        }

        // TODO: Should we keep any value other than Sequence::MAX since it is default?
        v2_combine_option!(sequence, self, other);
        v2_combine_option!(min_time, self, other);
        v2_combine_option!(min_height, self, other);
        v2_combine_option!(non_witness_utxo, self, other);

        // TODO: Copied from v0, confirm this is correct.
        if let (&None, Some(witness_utxo)) = (&self.witness_utxo, other.witness_utxo) {
            self.witness_utxo = Some(witness_utxo);
            self.non_witness_utxo = None; // Clear out any non-witness UTXO when we set a witness one
        }

        v2_combine_map!(partial_sigs, self, other);
        // TODO: Why do we not combine sighash_type?
        v2_combine_option!(redeem_script, self, other);
        v2_combine_option!(witness_script, self, other);
        v2_combine_map!(bip32_derivations, self, other);
        v2_combine_option!(final_script_sig, self, other);
        v2_combine_option!(final_script_witness, self, other);
        v2_combine_map!(ripemd160_preimages, self, other);
        v2_combine_map!(sha256_preimages, self, other);
        v2_combine_map!(hash160_preimages, self, other);
        v2_combine_map!(hash256_preimages, self, other);
        v2_combine_option!(tap_key_sig, self, other);
        v2_combine_map!(tap_script_sigs, self, other);
        v2_combine_map!(tap_scripts, self, other);
        v2_combine_map!(tap_key_origins, self, other);
        v2_combine_option!(tap_internal_key, self, other);
        v2_combine_option!(tap_merkle_root, self, other);
        v2_combine_map!(proprietaries, self, other);
        v2_combine_map!(unknowns, self, other);

        Ok(())
    }
}

impl Map for Input {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_IN_PREVIOUS_TXID, key: vec![] },
            value: self.previous_txid.serialize(),
        });

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_IN_OUTPUT_INDEX, key: vec![] },
            value: self.spent_output_index.serialize(),
        });

        v2_impl_psbt_get_pair! {
            rv.push(self.sequence, PSBT_IN_SEQUENCE)
        }
        v2_impl_psbt_get_pair! {
            rv.push(self.min_time, PSBT_IN_REQUIRED_TIME_LOCKTIME)
        }
        v2_impl_psbt_get_pair! {
            rv.push(self.min_height, PSBT_IN_REQUIRED_HEIGHT_LOCKTIME)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.non_witness_utxo, PSBT_IN_NON_WITNESS_UTXO)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.witness_utxo, PSBT_IN_WITNESS_UTXO)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.partial_sigs, PSBT_IN_PARTIAL_SIG)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.sighash_type, PSBT_IN_SIGHASH_TYPE)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.redeem_script, PSBT_IN_REDEEM_SCRIPT)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.witness_script, PSBT_IN_WITNESS_SCRIPT)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.bip32_derivations, PSBT_IN_BIP32_DERIVATION)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.final_script_sig, PSBT_IN_FINAL_SCRIPTSIG)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.final_script_witness, PSBT_IN_FINAL_SCRIPTWITNESS)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.ripemd160_preimages, PSBT_IN_RIPEMD160)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.sha256_preimages, PSBT_IN_SHA256)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.hash160_preimages, PSBT_IN_HASH160)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.hash256_preimages, PSBT_IN_HASH256)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.tap_key_sig, PSBT_IN_TAP_KEY_SIG)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.tap_script_sigs, PSBT_IN_TAP_SCRIPT_SIG)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.tap_scripts, PSBT_IN_TAP_LEAF_SCRIPT)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.tap_key_origins, PSBT_IN_TAP_BIP32_DERIVATION)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.tap_internal_key, PSBT_IN_TAP_INTERNAL_KEY)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.tap_merkle_root, PSBT_IN_TAP_MERKLE_ROOT)
        }
        for (key, value) in self.proprietaries.iter() {
            rv.push(raw::Pair { key: key.to_key(), value: value.clone() });
        }

        for (key, value) in self.unknowns.iter() {
            rv.push(raw::Pair { key: key.clone(), value: value.clone() });
        }

        rv
    }
}

// TODO: This is an exact duplicate of that in v0.
fn psbt_insert_hash_pair<H>(
    map: &mut BTreeMap<H, Vec<u8>>,
    raw_key: raw::Key,
    raw_value: Vec<u8>,
    hash_type: HashType,
) -> Result<(), InsertPairError>
where
    H: hashes::Hash + Deserialize,
{
    if raw_key.key.is_empty() {
        return Err(InsertPairError::InvalidKeyDataEmpty(raw_key));
    }

    let key_val: H = Deserialize::deserialize(&raw_key.key)?;
    match map.entry(key_val) {
        btree_map::Entry::Vacant(empty_key) => {
            let val: Vec<u8> = Deserialize::deserialize(&raw_value)?;

            if <H as hashes::Hash>::hash(&val) != key_val {
                return Err(HashPreimageError {
                    preimage: val.into_boxed_slice(),
                    hash: Box::from(key_val.borrow()),
                    hash_type,
                }
                .into());
            }
            empty_key.insert(val);
            Ok(())
        }
        btree_map::Entry::Occupied(_) => Err(InsertPairError::DuplicateKey(raw_key)),
    }
}

/// Enables building an [`Input`] using the standard builder pattern.
pub struct InputBuilder(Input);

impl InputBuilder {
    /// Creates a new builder that can be used to build an [`Input`] that spends `previous_output`.
    pub fn new(previous_output: &OutPoint) -> Self { Self(Input::new(previous_output)) }

    /// Sets the [`Input::min_time`] field.
    pub fn minimum_required_time_based_lock_time(mut self, lock: absolute::Time) -> Self {
        self.0.min_time = Some(lock);
        self
    }

    /// Sets the [`Input::min_height`] field.
    pub fn minimum_required_height_based_lock_time(mut self, lock: absolute::Height) -> Self {
        self.0.min_height = Some(lock);
        self
    }

    /// Funds this input with a segwit UTXO.
    pub fn segwit_fund(mut self, utxo: TxOut) -> Self {
        self.0.witness_utxo = Some(utxo);
        self
    }

    /// Funds this input with a legacy UTXO.
    ///
    /// Caller to guarantee that this `tx` is correct for this input (i.e., has a txid equal to
    /// `self.previous_txid`).
    // TODO: Consider adding error checks that tx is correct.
    pub fn legacy_fund(mut self, tx: Transaction) -> Self {
        self.0.non_witness_utxo = Some(tx);
        self
    }

    /// Builds the [`Input`].
    pub fn build(self) -> Input { self.0 }
}

/// An error while decoding.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// Error inserting a key-value pair.
    InsertPair(InsertPairError),
    /// Error decoding a pair.
    DeserPair(serialize::Error),
    /// Input must contain a previous txid.
    MissingPreviousTxid,
    /// Input must contain a spent output index.
    MissingSpentOutputIndex,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecodeError::*;

        match *self {
            InsertPair(ref e) => write_err!(f, "error inserting a key-value pair"; e),
            DeserPair(ref e) => write_err!(f, "error decoding pair"; e),
            MissingPreviousTxid => write!(f, "input must contain a previous txid"),
            MissingSpentOutputIndex => write!(f, "input must contain a spent output index"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DecodeError::*;

        match *self {
            InsertPair(ref e) => Some(e),
            DeserPair(ref e) => Some(e),
            MissingPreviousTxid | MissingSpentOutputIndex => None,
        }
    }
}

impl From<InsertPairError> for DecodeError {
    fn from(e: InsertPairError) -> Self { Self::InsertPair(e) }
}

/// Error inserting a key-value pair.
#[derive(Debug)]
pub enum InsertPairError {
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(raw::Key),
    /// Error deserializing raw value.
    Deser(serialize::Error),
    /// Key should contain data.
    InvalidKeyDataEmpty(raw::Key),
    /// Key should not contain data.
    InvalidKeyDataNotEmpty(raw::Key),
    /// The pre-image must hash to the correponding psbt hash
    HashPreimage(HashPreimageError),
}

impl fmt::Display for InsertPairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InsertPairError::*;

        match *self {
            DuplicateKey(ref key) => write!(f, "duplicate key: {}", key),
            Deser(ref e) => write_err!(f, "error deserializing raw value"; e),
            InvalidKeyDataEmpty(ref key) => write!(f, "key should contain data: {}", key),
            InvalidKeyDataNotEmpty(ref key) => write!(f, "key should not contain data: {}", key),
            HashPreimage(ref e) => write_err!(f, "invalid hash preimage"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InsertPairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InsertPairError::*;

        match *self {
            Deser(ref e) => Some(e),
            HashPreimage(ref e) => Some(e),
            DuplicateKey(_) | InvalidKeyDataEmpty(_) | InvalidKeyDataNotEmpty(_) => None,
        }
    }
}

impl From<serialize::Error> for InsertPairError {
    fn from(e: serialize::Error) -> Self { Self::Deser(e) }
}

impl From<HashPreimageError> for InsertPairError {
    fn from(e: HashPreimageError) -> Self { Self::HashPreimage(e) }
}

/// An hash and hash preimage do not match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashPreimageError {
    /// The hash-type causing this error.
    hash_type: HashType,
    /// The hash pre-image.
    preimage: Box<[u8]>,
    /// The hash (should equal hash of the preimage).
    hash: Box<[u8]>,
}

impl fmt::Display for HashPreimageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid hash preimage {} {:x} {:x}",
            self.hash_type,
            self.preimage.as_hex(),
            self.hash.as_hex()
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HashPreimageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Enum for marking invalid preimage error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum HashType {
    /// The ripemd hash algorithm.
    Ripemd,
    /// The sha-256 hash algorithm.
    Sha256,
    /// The hash-160 hash algorithm.
    Hash160,
    /// The Hash-256 hash algorithm.
    Hash256,
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", stringify!(self)) }
}

/// Error finalizing an input.
#[cfg(feature = "miniscript")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizeError {
    /// Failed to create a final witness.
    EmptyWitness,
    /// Unexpected witness data.
    UnexpectedWitness,
}

#[cfg(feature = "miniscript")]
impl fmt::Display for FinalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FinalizeError::*;

        match *self {
            EmptyWitness => write!(f, "failed to create a final witness"),
            UnexpectedWitness => write!(f, "unexpected witness data"),
        }
    }
}

#[cfg(all(feature = "std", feature = "miniscript"))]
impl std::error::Error for FinalizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Error combining two input maps.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CombineError {
    /// The previous txids are not the same.
    PreviousTxidMismatch {
        /// Attempted to combine a PBST with `this` previous txid.
        this: Txid,
        /// Into a PBST with `that` previous txid.
        that: Txid,
    },
    /// The spent output indecies are not the same.
    SpentOutputIndexMismatch {
        /// Attempted to combine a PBST with `this` spent output index.
        this: u32,
        /// Into a PBST with `that` spent output index.
        that: u32,
    },
}
impl fmt::Display for CombineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CombineError::*;

        match *self {
            PreviousTxidMismatch { ref this, ref that } =>
                write!(f, "combine two PSBTs with different previous txids: {:?} {:?}", this, that),
            SpentOutputIndexMismatch { ref this, ref that } => write!(
                f,
                "combine two PSBTs with different spent output indecies: {:?} {:?}",
                this, that
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CombineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use CombineError::*;

        match *self {
            PreviousTxidMismatch { .. } | SpentOutputIndexMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(feature = "std")]
    fn out_point() -> OutPoint {
        let txid = Txid::hash(b"some arbitrary bytes");
        let vout = 0xab;
        OutPoint { txid, vout }
    }

    #[test]
    #[cfg(feature = "std")]
    fn serialize_roundtrip() {
        let input = Input::new(&out_point());

        let ser = input.serialize_map();
        let mut d = std::io::Cursor::new(ser);

        let decoded = Input::decode(&mut d).expect("failed to decode");

        assert_eq!(decoded, input);
    }
}
