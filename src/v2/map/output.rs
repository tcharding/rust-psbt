// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;
use core::fmt;

use bitcoin::bip32::KeySource;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::taproot::{TapLeafHash, TapTree};
use bitcoin::{secp256k1, Amount, ScriptBuf, TxOut};

use crate::consts::{
    PSBT_OUT_AMOUNT, PSBT_OUT_BIP32_DERIVATION, PSBT_OUT_PROPRIETARY, PSBT_OUT_REDEEM_SCRIPT,
    PSBT_OUT_SCRIPT, PSBT_OUT_TAP_BIP32_DERIVATION, PSBT_OUT_TAP_INTERNAL_KEY, PSBT_OUT_TAP_TREE,
    PSBT_OUT_WITNESS_SCRIPT,
};
use crate::error::write_err;
use crate::prelude::*;
use crate::serialize::{Deserialize, Serialize};
use crate::v2::map::Map;
use crate::{io, raw, serialize};

/// A key-value map for an output of the corresponding index in the unsigned
/// transaction.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Output {
    /// The output's amount (serialized as satoshis).
    pub amount: Amount,

    /// The script for this output, also known as the scriptPubKey.
    pub script_pubkey: ScriptBuf,

    /// The redeem script for this output.
    pub redeem_script: Option<ScriptBuf>,
    /// The witness script for this output.
    pub witness_script: Option<ScriptBuf>,
    /// A map from public keys needed to spend this output to their
    /// corresponding master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivations: BTreeMap<secp256k1::PublicKey, KeySource>,
    /// The internal pubkey.
    pub tap_internal_key: Option<XOnlyPublicKey>,
    /// Taproot Output tree.
    pub tap_tree: Option<TapTree>,
    /// Map of tap root x only keys to origin info and leaf hashes contained in it.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    /// Proprietary key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknowns: BTreeMap<raw::Key, Vec<u8>>,
}

impl Output {
    /// Creates a new [`Output`] using `utxo`.
    pub fn new(utxo: TxOut) -> Self {
        Output {
            amount: utxo.value,
            script_pubkey: utxo.script_pubkey,
            redeem_script: None,
            witness_script: None,
            bip32_derivations: BTreeMap::new(),
            tap_internal_key: None,
            tap_tree: None,
            tap_key_origins: BTreeMap::new(),
            proprietaries: BTreeMap::new(),
            unknowns: BTreeMap::new(),
        }
    }

    // /// Converts this `Output` to a `v0::Output`.
    // pub(crate) fn into_v0(self) -> v0::Output {
    //     v0::Output {
    //         redeem_script: self.redeem_script,
    //         witness_script: self.witness_script,
    //         bip32_derivation: self.bip32_derivations,
    //         tap_internal_key: self.tap_internal_key,
    //         tap_tree: self.tap_tree,
    //         tap_key_origins: self.tap_key_origins,
    //         proprietary: self.proprietaries,
    //         unknown: self.unknowns,
    //     }
    // }

    /// Creates the [`TxOut`] associated with this `Output`.
    pub(crate) fn tx_out(&self) -> TxOut {
        TxOut { value: self.amount, script_pubkey: self.script_pubkey.clone() }
    }

    pub(in crate::v2) fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, DecodeError> {
        // These are placeholder values that never exist in a encode `Output`.
        let invalid = TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::default() };
        let mut rv = Self::new(invalid);

        loop {
            match raw::Pair::decode(r) {
                Ok(pair) => rv.insert_pair(pair)?,
                Err(serialize::Error::NoMorePairs) => break,
                Err(e) => return Err(DecodeError::DeserPair(e)),
            }
        }

        if rv.amount == Amount::ZERO {
            return Err(DecodeError::MissingValue);
        }
        if rv.script_pubkey == ScriptBuf::default() {
            return Err(DecodeError::MissingScriptPubkey);
        }
        Ok(rv)
    }

    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), InsertPairError> {
        let raw::Pair { key: raw_key, value: raw_value } = pair;

        match raw_key.type_value {
            PSBT_OUT_AMOUNT => {
                if self.amount != Amount::ZERO {
                    return Err(InsertPairError::DuplicateKey(raw_key));
                }
                let amount: Amount = Deserialize::deserialize(&raw_value)?;
                self.amount = amount;
            }
            PSBT_OUT_SCRIPT => {
                if self.script_pubkey != ScriptBuf::default() {
                    return Err(InsertPairError::DuplicateKey(raw_key));
                }
                let script: ScriptBuf = Deserialize::deserialize(&raw_value)?;
                self.script_pubkey = script;
            }

            PSBT_OUT_REDEEM_SCRIPT => {
                v2_impl_psbt_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_OUT_WITNESS_SCRIPT => {
                v2_impl_psbt_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_OUT_BIP32_DERIVATION => {
                v2_impl_psbt_insert_pair! {
                    self.bip32_derivations <= <raw_key: secp256k1::PublicKey>|<raw_value: KeySource>
                }
            }
            PSBT_OUT_PROPRIETARY => {
                let key = raw::ProprietaryKey::try_from(raw_key.clone())?;
                match self.proprietaries.entry(key) {
                    btree_map::Entry::Vacant(empty_key) => {
                        empty_key.insert(raw_value);
                    }
                    btree_map::Entry::Occupied(_) =>
                        return Err(InsertPairError::DuplicateKey(raw_key)),
                }
            }
            PSBT_OUT_TAP_INTERNAL_KEY => {
                v2_impl_psbt_insert_pair! {
                    self.tap_internal_key <= <raw_key: _>|<raw_value: XOnlyPublicKey>
                }
            }
            PSBT_OUT_TAP_TREE => {
                v2_impl_psbt_insert_pair! {
                    self.tap_tree <= <raw_key: _>|<raw_value: TapTree>
                }
            }
            PSBT_OUT_TAP_BIP32_DERIVATION => {
                v2_impl_psbt_insert_pair! {
                    self.tap_key_origins <= <raw_key: XOnlyPublicKey>|< raw_value: (Vec<TapLeafHash>, KeySource)>
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

    /// Combines this [`Output`] with `other` `Output` (as described by BIP 174).
    pub fn combine(&mut self, other: Self) -> Result<(), CombineError> {
        if self.amount != other.amount {
            return Err(CombineError::AmountMismatch { this: self.amount, that: other.amount });
        }

        if self.script_pubkey != other.script_pubkey {
            return Err(CombineError::ScriptPubkeyMismatch {
                this: self.script_pubkey.clone(),
                that: other.script_pubkey,
            });
        }

        v2_combine_option!(redeem_script, self, other);
        v2_combine_option!(witness_script, self, other);
        v2_combine_map!(bip32_derivations, self, other);
        v2_combine_option!(tap_internal_key, self, other);
        v2_combine_option!(tap_tree, self, other);
        v2_combine_map!(tap_key_origins, self, other);
        v2_combine_map!(proprietaries, self, other);
        v2_combine_map!(unknowns, self, other);

        Ok(())
    }
}

impl Map for Output {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_OUT_AMOUNT, key: vec![] },
            value: self.amount.serialize(),
        });

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_OUT_SCRIPT, key: vec![] },
            value: self.script_pubkey.serialize(),
        });

        v2_impl_psbt_get_pair! {
            rv.push(self.redeem_script, PSBT_OUT_REDEEM_SCRIPT)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.witness_script, PSBT_OUT_WITNESS_SCRIPT)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.bip32_derivations, PSBT_OUT_BIP32_DERIVATION)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.tap_internal_key, PSBT_OUT_TAP_INTERNAL_KEY)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.tap_tree, PSBT_OUT_TAP_TREE)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.tap_key_origins, PSBT_OUT_TAP_BIP32_DERIVATION)
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

/// Enables building an [`Output`] using the standard builder pattern.
// This is only provided for uniformity with the `InputBuilder`.
pub struct OutputBuilder(Output);

impl OutputBuilder {
    /// Creates a new builder that can be used to build an [`Output`] around `utxo`.
    pub fn new(utxo: TxOut) -> Self { OutputBuilder(Output::new(utxo)) }

    /// Build the [`Output`].
    pub fn build(self) -> Output { self.0 }
}

/// An error while decoding.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// Error inserting a key-value pair.
    InsertPair(InsertPairError),
    /// Error deserializing a pair.
    DeserPair(serialize::Error),
    /// Encoded output is missing a value.
    MissingValue,
    /// Encoded output is missing a script pubkey.
    MissingScriptPubkey,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecodeError::*;

        match *self {
            InsertPair(ref e) => write_err!(f, "error inserting a pair"; e),
            DeserPair(ref e) => write_err!(f, "error deserializing a pair"; e),
            MissingValue => write!(f, "encoded output is missing a value"),
            MissingScriptPubkey => write!(f, "encoded output is missing a script pubkey"),
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
            MissingValue | MissingScriptPubkey => None,
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
}

impl fmt::Display for InsertPairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InsertPairError::*;

        match *self {
            DuplicateKey(ref key) => write!(f, "duplicate key: {}", key),
            Deser(ref e) => write_err!(f, "error deserializing raw value"; e),
            InvalidKeyDataEmpty(ref key) => write!(f, "key should contain data: {}", key),
            InvalidKeyDataNotEmpty(ref key) => write!(f, "key should not contain data: {}", key),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InsertPairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InsertPairError::*;

        match *self {
            Deser(ref e) => Some(e),
            DuplicateKey(_) | InvalidKeyDataEmpty(_) | InvalidKeyDataNotEmpty(_) => None,
        }
    }
}

impl From<serialize::Error> for InsertPairError {
    fn from(e: serialize::Error) -> Self { Self::Deser(e) }
}

/// Error combining two output maps.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CombineError {
    /// The amounts are not the same.
    AmountMismatch {
        /// Attempted to combine a PBST with `this` previous txid.
        this: Amount,
        /// Into a PBST with `that` previous txid.
        that: Amount,
    },
    /// The script_pubkeys are not the same.
    ScriptPubkeyMismatch {
        /// Attempted to combine a PBST with `this` script_pubkey.
        this: ScriptBuf,
        /// Into a PBST with `that` script_pubkey.
        that: ScriptBuf,
    },
}

impl fmt::Display for CombineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CombineError::*;

        match *self {
            AmountMismatch { ref this, ref that } =>
                write!(f, "combine two PSBTs with different amounts: {} {}", this, that),
            ScriptPubkeyMismatch { ref this, ref that } =>
                write!(f, "combine two PSBTs with different script_pubkeys: {:x} {:x}", this, that),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CombineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use CombineError::*;

        match *self {
            AmountMismatch { .. } | ScriptPubkeyMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::*;

    fn tx_out() -> TxOut {
        // Arbitrary script, may not even be a valid scriptPubkey.
        let script = ScriptBuf::from_hex("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac")
            .expect("failed to parse script form hex");
        let value = Amount::from_sat(123_456_789);
        TxOut { value, script_pubkey: script }
    }

    #[test]
    fn serialize_roundtrip() {
        let output = Output::new(tx_out());

        let ser = output.serialize_map();
        let mut d = std::io::Cursor::new(ser);

        let decoded = Output::decode(&mut d).expect("failed to decode");

        assert_eq!(decoded, output);
    }
}
