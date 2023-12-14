// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;
use core::fmt;

use bitcoin::bip32::KeySource;
use bitcoin::consensus::encode as consensus;
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
use crate::{io, raw, v0, Error};

/// A key-value map for an output of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
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
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,
    /// The internal pubkey.
    pub tap_internal_key: Option<XOnlyPublicKey>,
    /// Taproot Output tree.
    pub tap_tree: Option<TapTree>,
    /// Map of tap root x only keys to origin info and leaf hashes contained in it.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    /// Proprietary key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Output {
    /// Creates a new [`Output`] using `utxo`.
    pub fn new(utxo: TxOut) -> Self {
        Output {
            amount: utxo.value,
            script_pubkey: utxo.script_pubkey,
            redeem_script: None,
            witness_script: None,
            bip32_derivation: BTreeMap::new(),
            tap_internal_key: None,
            tap_tree: None,
            tap_key_origins: BTreeMap::new(),
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),
        }
    }

    /// Converts this `Output` to a `v0::Output`.
    pub(crate) fn into_v0(self) -> v0::Output {
        v0::Output {
            redeem_script: self.redeem_script,
            witness_script: self.witness_script,
            bip32_derivation: self.bip32_derivation,
            tap_internal_key: self.tap_internal_key,
            tap_tree: self.tap_tree,
            tap_key_origins: self.tap_key_origins,
            proprietary: self.proprietary,
            unknown: self.unknown,
        }
    }

    /// Creates the [`TxOut`] associated with this `Output`.
    pub(crate) fn tx_out(&self) -> TxOut {
        TxOut { value: self.amount, script_pubkey: self.script_pubkey.clone() }
    }

    pub(crate) fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, DecodeError> {
        let invalid = TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::default() };
        let mut rv = Self::new(invalid);

        loop {
            match raw::Pair::decode(r) {
                Ok(pair) => rv.insert_pair(pair)?,
                Err(crate::Error::NoMorePairs) => {
                    if rv.amount == Amount::ZERO {
                        return Err(DecodeError::ZeroValue);
                    }

                    if rv.script_pubkey == ScriptBuf::default() {
                        return Err(DecodeError::EmptyScriptPubkey);
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
            v if v == PSBT_OUT_AMOUNT => {
                if self.amount != Amount::ZERO {
                    return Err(Error::DuplicateKey(raw_key));
                }
                let amount: Amount = Deserialize::deserialize(&raw_value)?;
                self.amount = amount;
            }
            v if v == PSBT_OUT_SCRIPT => {
                if self.script_pubkey != ScriptBuf::default() {
                    return Err(Error::DuplicateKey(raw_key));
                }
                let script: ScriptBuf = Deserialize::deserialize(&raw_value)?;
                self.script_pubkey = script;
            }

            v if v == PSBT_OUT_REDEEM_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            v if v == PSBT_OUT_WITNESS_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            v if v == PSBT_OUT_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.bip32_derivation <= <raw_key: secp256k1::PublicKey>|<raw_value: KeySource>
                }
            }
            v if v == PSBT_OUT_PROPRIETARY => {
                let key = raw::ProprietaryKey::try_from(raw_key.clone())?;
                match self.proprietary.entry(key) {
                    btree_map::Entry::Vacant(empty_key) => {
                        empty_key.insert(raw_value);
                    }
                    btree_map::Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key)),
                }
            }
            v if v == PSBT_OUT_TAP_INTERNAL_KEY => {
                impl_psbt_insert_pair! {
                    self.tap_internal_key <= <raw_key: _>|<raw_value: XOnlyPublicKey>
                }
            }
            v if v == PSBT_OUT_TAP_TREE => {
                impl_psbt_insert_pair! {
                    self.tap_tree <= <raw_key: _>|<raw_value: TapTree>
                }
            }
            v if v == PSBT_OUT_TAP_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.tap_key_origins <= <raw_key: XOnlyPublicKey>|< raw_value: (Vec<TapLeafHash>, KeySource)>
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

    /// Combines this [`Output`] with `other` `Output` (as described by BIP 174).
    pub fn combine(&mut self, other: Self) {
        self.bip32_derivation.extend(other.bip32_derivation);
        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);
        self.tap_key_origins.extend(other.tap_key_origins);

        combine!(redeem_script, self, other);
        combine!(witness_script, self, other);
        combine!(tap_internal_key, self, other);
        combine!(tap_tree, self, other);
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

        impl_psbt_get_pair! {
            rv.push(self.redeem_script, PSBT_OUT_REDEEM_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push(self.witness_script, PSBT_OUT_WITNESS_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.bip32_derivation, PSBT_OUT_BIP32_DERIVATION)
        }

        impl_psbt_get_pair! {
            rv.push(self.tap_internal_key, PSBT_OUT_TAP_INTERNAL_KEY)
        }

        impl_psbt_get_pair! {
            rv.push(self.tap_tree, PSBT_OUT_TAP_TREE)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.tap_key_origins, PSBT_OUT_TAP_BIP32_DERIVATION)
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

/// Enables building an [`Output`] using the standard builder pattern.
// This is only provided for uniformity with the `InputBuilder`.
pub struct OutputBuilder(Output);

impl OutputBuilder {
    /// Creates a new builder that can be used to build an [`Output`] around `utxo`.
    pub fn new(utxo: TxOut) -> Self { OutputBuilder(Output::new(utxo)) }

    /// Build the [`Output`].
    pub fn build(self) -> Output { self.0 }
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
    /// Output has zero value.
    ZeroValue,
    /// Output has an empty script pubkey.
    EmptyScriptPubkey,
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
            ZeroValue => write!(f, "output has zero value"),
            EmptyScriptPubkey => write!(f, "output has an empty script pubkey"),
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
            | ZeroValue
            | EmptyScriptPubkey => None,
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
