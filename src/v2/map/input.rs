// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;
use core::fmt;

use bitcoin::bip32::KeySource;
use bitcoin::consensus::encode as consensus;
use bitcoin::hashes::{self, hash160, ripemd160, sha256, sha256d, Hash as _};
use bitcoin::key::{PublicKey, XOnlyPublicKey};
use bitcoin::locktime::absolute;
use bitcoin::sighash::{EcdsaSighashType, NonStandardSighashTypeError, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash};
use bitcoin::{
    ecdsa, secp256k1, taproot, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
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
use crate::{error, io, raw, v0, Error};

/// A key-value map for an input of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,
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
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this input.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Input {
    /// Creates a new `Input` that spends the `previous_output`.
    pub fn new(previous_output: OutPoint) -> Self {
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
            bip32_derivation: BTreeMap::new(),
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
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),
        }
    }

    /// Converts this `Input` to a `v0::Input`.
    pub(crate) fn into_v0(self) -> v0::Input {
        v0::Input {
            non_witness_utxo: self.non_witness_utxo,
            witness_utxo: self.witness_utxo,
            partial_sigs: self.partial_sigs,
            sighash_type: self.sighash_type,
            redeem_script: self.redeem_script,
            witness_script: self.witness_script,
            bip32_derivation: self.bip32_derivation,
            final_script_sig: self.final_script_sig,
            final_script_witness: self.final_script_witness,
            ripemd160_preimages: self.ripemd160_preimages,
            sha256_preimages: self.sha256_preimages,
            hash160_preimages: self.hash160_preimages,
            hash256_preimages: self.hash256_preimages,
            tap_key_sig: self.tap_key_sig,
            tap_script_sigs: self.tap_script_sigs,
            tap_scripts: self.tap_scripts,
            tap_key_origins: self.tap_key_origins,
            tap_internal_key: self.tap_internal_key,
            tap_merkle_root: self.tap_merkle_root,
            proprietary: self.proprietary,
            unknown: self.unknown,
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
    pub(crate) fn tx_in(&self) -> TxIn {
        TxIn {
            previous_output: self.out_point(),
            script_sig: ScriptBuf::default(),
            sequence: self.sequence.unwrap_or(Sequence::ZERO),
            witness: Witness::default(),
        }
    }

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

    /// TODO: Use this.
    #[allow(dead_code)]
    fn is_finalized(&self) -> bool {
        // TODO: Confirm this covers taproot sigs?
        self.final_script_sig.is_some() || self.final_script_witness.is_some()
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

    pub(crate) fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, DecodeError> {
        let invalid = OutPoint { txid: Txid::all_zeros(), vout: u32::MAX };
        let mut rv = Self::new(invalid);

        loop {
            match raw::Pair::decode(r) {
                Ok(pair) => rv.insert_pair(pair)?,
                Err(crate::Error::NoMorePairs) => {
                    if rv.previous_txid == Txid::all_zeros() {
                        return Err(DecodeError::MissingPreviousTxid);
                    }

                    if rv.spent_output_index == u32::MAX {
                        return Err(DecodeError::MissingSpentOutputIndex);
                    }
                    return Ok(rv);
                }
                Err(e) => return Err(DecodeError::Crate(e)),
            }
        }
    }

    pub(super) fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), Error> {
        let raw::Pair { key: raw_key, value: raw_value } = pair;

        match raw_key.type_value {
            v if v == PSBT_IN_PREVIOUS_TXID => {
                if self.previous_txid != Txid::all_zeros() {
                    return Err(Error::DuplicateKey(raw_key));
                }
                let txid: Txid = Deserialize::deserialize(&raw_value)?;
                self.previous_txid = txid;
            }
            v if v == PSBT_IN_OUTPUT_INDEX => {
                if self.spent_output_index != u32::MAX {
                    return Err(Error::DuplicateKey(raw_key));
                }
                let vout: u32 = Deserialize::deserialize(&raw_value)?;
                self.spent_output_index = vout;
            }
            v if v == PSBT_IN_SEQUENCE => {
                impl_psbt_insert_pair! {
                    self.sequence <= <raw_key: _>|<raw_value: Sequence>
                }
            }
            v if v == PSBT_IN_REQUIRED_TIME_LOCKTIME => {
                impl_psbt_insert_pair! {
                    self.min_time <= <raw_key: _>|<raw_value: absolute::Time>
                }
            }
            v if v == PSBT_IN_REQUIRED_HEIGHT_LOCKTIME => {
                impl_psbt_insert_pair! {
                    self.min_height <= <raw_key: _>|<raw_value: absolute::Height>
                }
            }
            v if v == PSBT_IN_WITNESS_UTXO => {
                impl_psbt_insert_pair! {
                    self.witness_utxo <= <raw_key: _>|<raw_value: TxOut>
                }
            }
            v if v == PSBT_IN_PARTIAL_SIG => {
                impl_psbt_insert_pair! {
                    self.partial_sigs <= <raw_key: PublicKey>|<raw_value: ecdsa::Signature>
                }
            }
            v if v == PSBT_IN_SIGHASH_TYPE => {
                impl_psbt_insert_pair! {
                    self.sighash_type <= <raw_key: _>|<raw_value: PsbtSighashType>
                }
            }
            v if v == PSBT_IN_REDEEM_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            v if v == PSBT_IN_WITNESS_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            v if v == PSBT_IN_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.bip32_derivation <= <raw_key: secp256k1::PublicKey>|<raw_value: KeySource>
                }
            }
            v if v == PSBT_IN_FINAL_SCRIPTSIG => {
                impl_psbt_insert_pair! {
                    self.final_script_sig <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            v if v == PSBT_IN_FINAL_SCRIPTWITNESS => {
                impl_psbt_insert_pair! {
                    self.final_script_witness <= <raw_key: _>|<raw_value: Witness>
                }
            }
            v if v == PSBT_IN_RIPEMD160 => {
                psbt_insert_hash_pair(
                    &mut self.ripemd160_preimages,
                    raw_key,
                    raw_value,
                    error::PsbtHash::Ripemd,
                )?;
            }
            v if v == PSBT_IN_SHA256 => {
                psbt_insert_hash_pair(
                    &mut self.sha256_preimages,
                    raw_key,
                    raw_value,
                    error::PsbtHash::Sha256,
                )?;
            }
            v if v == PSBT_IN_HASH160 => {
                psbt_insert_hash_pair(
                    &mut self.hash160_preimages,
                    raw_key,
                    raw_value,
                    error::PsbtHash::Hash160,
                )?;
            }
            v if v == PSBT_IN_HASH256 => {
                psbt_insert_hash_pair(
                    &mut self.hash256_preimages,
                    raw_key,
                    raw_value,
                    error::PsbtHash::Hash256,
                )?;
            }
            v if v == PSBT_IN_TAP_KEY_SIG => {
                impl_psbt_insert_pair! {
                    self.tap_key_sig <= <raw_key: _>|<raw_value: taproot::Signature>
                }
            }
            v if v == PSBT_IN_TAP_SCRIPT_SIG => {
                impl_psbt_insert_pair! {
                    self.tap_script_sigs <= <raw_key: (XOnlyPublicKey, TapLeafHash)>|<raw_value: taproot::Signature>
                }
            }
            v if v == PSBT_IN_TAP_LEAF_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.tap_scripts <= <raw_key: ControlBlock>|< raw_value: (ScriptBuf, LeafVersion)>
                }
            }
            v if v == PSBT_IN_TAP_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.tap_key_origins <= <raw_key: XOnlyPublicKey>|< raw_value: (Vec<TapLeafHash>, KeySource)>
                }
            }
            v if v == PSBT_IN_TAP_INTERNAL_KEY => {
                impl_psbt_insert_pair! {
                    self.tap_internal_key <= <raw_key: _>|< raw_value: XOnlyPublicKey>
                }
            }
            v if v == PSBT_IN_TAP_MERKLE_ROOT => {
                impl_psbt_insert_pair! {
                    self.tap_merkle_root <= <raw_key: _>|< raw_value: TapNodeHash>
                }
            }
            v if v == PSBT_IN_PROPRIETARY => {
                let key = raw::ProprietaryKey::try_from(raw_key.clone())?;
                match self.proprietary.entry(key) {
                    btree_map::Entry::Vacant(empty_key) => {
                        empty_key.insert(raw_value);
                    }
                    btree_map::Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key)),
                }
            }
            _ => match self.unknown.entry(raw_key) {
                btree_map::Entry::Vacant(empty_key) => {
                    empty_key.insert(raw_value);
                }
                btree_map::Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone())),
            },
        }

        Ok(())
    }

    /// Combines this [`Input`] with `other` `Input` (as described by BIP 174).
    pub fn combine(&mut self, other: Self) {
        combine!(non_witness_utxo, self, other);

        if let (&None, Some(witness_utxo)) = (&self.witness_utxo, other.witness_utxo) {
            self.witness_utxo = Some(witness_utxo);
            self.non_witness_utxo = None; // Clear out any non-witness UTXO when we set a witness one
        }

        self.partial_sigs.extend(other.partial_sigs);
        self.bip32_derivation.extend(other.bip32_derivation);
        self.ripemd160_preimages.extend(other.ripemd160_preimages);
        self.sha256_preimages.extend(other.sha256_preimages);
        self.hash160_preimages.extend(other.hash160_preimages);
        self.hash256_preimages.extend(other.hash256_preimages);
        self.tap_script_sigs.extend(other.tap_script_sigs);
        self.tap_scripts.extend(other.tap_scripts);
        self.tap_key_origins.extend(other.tap_key_origins);
        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);

        combine!(redeem_script, self, other);
        combine!(witness_script, self, other);
        combine!(final_script_sig, self, other);
        combine!(final_script_witness, self, other);
        combine!(tap_key_sig, self, other);
        combine!(tap_internal_key, self, other);
        combine!(tap_merkle_root, self, other);
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

        impl_psbt_get_pair! {
            rv.push(self.sequence, PSBT_IN_SEQUENCE)
        }
        impl_psbt_get_pair! {
            rv.push(self.min_time, PSBT_IN_REQUIRED_TIME_LOCKTIME)
        }
        impl_psbt_get_pair! {
            rv.push(self.min_height, PSBT_IN_REQUIRED_HEIGHT_LOCKTIME)
        }

        impl_psbt_get_pair! {
            rv.push(self.non_witness_utxo, PSBT_IN_NON_WITNESS_UTXO)
        }

        impl_psbt_get_pair! {
            rv.push(self.witness_utxo, PSBT_IN_WITNESS_UTXO)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.partial_sigs, PSBT_IN_PARTIAL_SIG)
        }

        impl_psbt_get_pair! {
            rv.push(self.sighash_type, PSBT_IN_SIGHASH_TYPE)
        }

        impl_psbt_get_pair! {
            rv.push(self.redeem_script, PSBT_IN_REDEEM_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push(self.witness_script, PSBT_IN_WITNESS_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.bip32_derivation, PSBT_IN_BIP32_DERIVATION)
        }

        impl_psbt_get_pair! {
            rv.push(self.final_script_sig, PSBT_IN_FINAL_SCRIPTSIG)
        }

        impl_psbt_get_pair! {
            rv.push(self.final_script_witness, PSBT_IN_FINAL_SCRIPTWITNESS)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.ripemd160_preimages, PSBT_IN_RIPEMD160)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.sha256_preimages, PSBT_IN_SHA256)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.hash160_preimages, PSBT_IN_HASH160)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.hash256_preimages, PSBT_IN_HASH256)
        }

        impl_psbt_get_pair! {
            rv.push(self.tap_key_sig, PSBT_IN_TAP_KEY_SIG)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.tap_script_sigs, PSBT_IN_TAP_SCRIPT_SIG)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.tap_scripts, PSBT_IN_TAP_LEAF_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.tap_key_origins, PSBT_IN_TAP_BIP32_DERIVATION)
        }

        impl_psbt_get_pair! {
            rv.push(self.tap_internal_key, PSBT_IN_TAP_INTERNAL_KEY)
        }

        impl_psbt_get_pair! {
            rv.push(self.tap_merkle_root, PSBT_IN_TAP_MERKLE_ROOT)
        }
        for (key, value) in self.proprietary.iter() {
            rv.push(raw::Pair { key: key.to_key(), value: value.clone() });
        }

        for (key, value) in self.unknown.iter() {
            rv.push(raw::Pair { key: key.clone(), value: value.clone() });
        }

        rv
    }
}

fn psbt_insert_hash_pair<H>(
    map: &mut BTreeMap<H, Vec<u8>>,
    raw_key: raw::Key,
    raw_value: Vec<u8>,
    hash_type: error::PsbtHash,
) -> Result<(), Error>
where
    H: hashes::Hash + Deserialize,
{
    if raw_key.key.is_empty() {
        return Err(crate::Error::InvalidKey(raw_key));
    }
    let key_val: H = Deserialize::deserialize(&raw_key.key)?;
    match map.entry(key_val) {
        btree_map::Entry::Vacant(empty_key) => {
            let val: Vec<u8> = Deserialize::deserialize(&raw_value)?;
            if <H as hashes::Hash>::hash(&val) != key_val {
                return Err(crate::Error::InvalidPreimageHashPair {
                    preimage: val.into_boxed_slice(),
                    hash: Box::from(key_val.borrow()),
                    hash_type,
                });
            }
            empty_key.insert(val);
            Ok(())
        }
        btree_map::Entry::Occupied(_) => Err(crate::Error::DuplicateKey(raw_key)),
    }
}

/// Enables building an [`Input`] using the standard builder pattern.
pub struct InputBuilder(Input);

impl InputBuilder {
    /// Creates a new builder that can be used to build an [`Input`] that spends `previous_output`.
    pub fn new(previous_output: OutPoint) -> Self { Self(Input::new(previous_output)) }

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

    /// Builds the [`Input`].
    pub fn build(self) -> Input { self.0 }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// Error consensus deserializing type.
    Consensus(consensus::Error),
    /// Known keys must be according to spec.
    InvalidKey(raw::Key),
    /// Non-proprietary key type found when proprietary key was expected
    InvalidProprietaryKey,
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(raw::Key),
    /// Input must contain a previous txid.
    MissingPreviousTxid,
    /// Input must contain a spent output index.
    MissingSpentOutputIndex,
    /// TODO: Remove this variant, its a kludge
    Crate(crate::error::Error),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecodeError::*;

        match *self {
            Consensus(ref e) => write_err!(f, "error consensus deserializing type"; e),
            InvalidKey(ref key) => write!(f, "invalid key: {}", key),
            InvalidProprietaryKey =>
                write!(f, "non-proprietary key type found when proprietary key was expected"),
            DuplicateKey(ref key) => write!(f, "duplicate key: {}", key),
            MissingPreviousTxid => write!(f, "input must contain a previous txid"),
            MissingSpentOutputIndex => write!(f, "input must contain a spent output index"),
            Crate(ref e) => write_err!(f, "kludge"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use DecodeError::*;

        match *self {
            Consensus(ref e) => Some(e),
            Crate(ref e) => Some(e),
            InvalidKey(_)
            | InvalidProprietaryKey
            | DuplicateKey(_)
            | MissingPreviousTxid
            | MissingSpentOutputIndex => None,
        }
    }
}

impl From<consensus::Error> for DecodeError {
    fn from(e: consensus::Error) -> Self { Self::Consensus(e) }
}

// TODO: Remove this.
impl From<crate::error::Error> for DecodeError {
    fn from(e: crate::error::Error) -> Self { Self::Crate(e) }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use super::*;

    #[test]
    fn psbt_sighash_type_ecdsa() {
        for ecdsa in &[
            EcdsaSighashType::All,
            EcdsaSighashType::None,
            EcdsaSighashType::Single,
            EcdsaSighashType::AllPlusAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        ] {
            let sighash = PsbtSighashType::from(*ecdsa);
            let s = format!("{}", sighash);
            let back = PsbtSighashType::from_str(&s).unwrap();
            assert_eq!(back, sighash);
            assert_eq!(back.ecdsa_hash_ty().unwrap(), *ecdsa);
        }
    }

    #[test]
    fn psbt_sighash_type_taproot() {
        for tap in &[
            TapSighashType::Default,
            TapSighashType::All,
            TapSighashType::None,
            TapSighashType::Single,
            TapSighashType::AllPlusAnyoneCanPay,
            TapSighashType::NonePlusAnyoneCanPay,
            TapSighashType::SinglePlusAnyoneCanPay,
        ] {
            let sighash = PsbtSighashType::from(*tap);
            let s = format!("{}", sighash);
            let back = PsbtSighashType::from_str(&s).unwrap();
            assert_eq!(back, sighash);
            assert_eq!(back.taproot_hash_ty().unwrap(), *tap);
        }
    }

    #[test]
    fn psbt_sighash_type_notstd() {
        let nonstd = 0xdddddddd;
        let sighash = PsbtSighashType { inner: nonstd };
        let s = format!("{}", sighash);
        let back = PsbtSighashType::from_str(&s).unwrap();

        assert_eq!(back, sighash);
        // TODO: Uncomment this stuff.
        // assert_eq!(back.ecdsa_hash_ty(), Err(NonStandardSighashTypeError(nonstd)));
        // assert_eq!(back.taproot_hash_ty(), Err(InvalidSighashTypeError(nonstd)));
    }

    fn out_point() -> OutPoint {
        let txid = Txid::hash(b"some arbitrary bytes");
        let vout = 0xab;
        OutPoint { txid, vout }
    }

    #[test]
    fn serialize_roundtrip() {
        let input = Input::new(out_point());

        let ser = input.serialize_map();
        let mut d = std::io::Cursor::new(ser);

        let decoded = Input::decode(&mut d).expect("failed to decode");

        assert_eq!(decoded, input);
    }
}
