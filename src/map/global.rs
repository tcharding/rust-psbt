// SPDX-License-Identifier: CC0-1.0

use core::cmp;
use core::convert::TryFrom;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource, Xpub};
// TODO: This should be exposed like this in rust-bitcoin.
use bitcoin::consensus::encode as consensus;
use bitcoin::consensus::encode::MAX_VEC_SIZE;
use bitcoin::consensus::Decodable;
use bitcoin::transaction::Transaction;

use crate::io::{self, Cursor, Read};
use crate::map::Map;
use crate::prelude::*;
use crate::{raw, Error};

/// Type: Unsigned Transaction PSBT_GLOBAL_UNSIGNED_TX = 0x00
const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
/// Type: Extended Public Key PSBT_GLOBAL_XPUB = 0x01
const PSBT_GLOBAL_XPUB: u8 = 0x01;
/// Type: Version Number PSBT_GLOBAL_VERSION = 0xFB
const PSBT_GLOBAL_VERSION: u8 = 0xFB;
/// Type: Proprietary Use Type PSBT_GLOBAL_PROPRIETARY = 0xFC
const PSBT_GLOBAL_PROPRIETARY: u8 = 0xFC;

/// The global key-value map.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Global {
    /// The unsigned transaction, scriptSigs and witnesses for each input must be empty.
    pub unsigned_tx: Transaction,
    /// The version number of this PSBT. If omitted, the version number is 0.
    pub version: u32,
    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32.
    pub xpub: BTreeMap<Xpub, KeySource>,
    /// Global proprietary key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown global key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Map for Global {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_UNSIGNED_TX, key: vec![] },
            value: {
                // Manually serialized to ensure 0-input txs are serialized
                // without witnesses.
                let mut ret = Vec::new();
                ret.extend(consensus::serialize(&self.unsigned_tx.version));
                ret.extend(consensus::serialize(&self.unsigned_tx.input));
                ret.extend(consensus::serialize(&self.unsigned_tx.output));
                ret.extend(consensus::serialize(&self.unsigned_tx.lock_time));
                ret
            },
        });

        for (xpub, (fingerprint, derivation)) in &self.xpub {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_XPUB, key: xpub.encode().to_vec() },
                value: {
                    let mut ret = Vec::with_capacity(4 + derivation.len() * 4);
                    ret.extend(fingerprint.as_bytes());
                    derivation.into_iter().for_each(|n| ret.extend(&u32::from(*n).to_le_bytes()));
                    ret
                },
            });
        }

        // Serializing version only for non-default value; otherwise test vectors fail
        if self.version > 0 {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_VERSION, key: vec![] },
                value: self.version.to_le_bytes().to_vec(),
            });
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

impl Global {
    pub(crate) fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let mut r = r.take(MAX_VEC_SIZE as u64);
        let mut tx: Option<Transaction> = None;
        let mut version: Option<u32> = None;
        let mut unknowns: BTreeMap<raw::Key, Vec<u8>> = Default::default();
        let mut xpub_map: BTreeMap<Xpub, (Fingerprint, DerivationPath)> = Default::default();
        let mut proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>> = Default::default();

        loop {
            match raw::Pair::decode(&mut r) {
                Ok(pair) => {
                    match pair.key.type_value {
                        PSBT_GLOBAL_UNSIGNED_TX => {
                            // key has to be empty
                            if pair.key.key.is_empty() {
                                // there can only be one unsigned transaction
                                if tx.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);

                                    // Manually deserialized to ensure 0-input
                                    // txs without witnesses are deserialized
                                    // properly.
                                    tx = Some(Transaction {
                                        version: Decodable::consensus_decode(&mut decoder)?,
                                        input: Decodable::consensus_decode(&mut decoder)?,
                                        output: Decodable::consensus_decode(&mut decoder)?,
                                        lock_time: Decodable::consensus_decode(&mut decoder)?,
                                    });

                                    if decoder.position() != vlen as u64 {
                                        return Err(Error::PartialDataConsumption);
                                    }
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key));
                            }
                        }
                        PSBT_GLOBAL_XPUB => {
                            if !pair.key.key.is_empty() {
                                let xpub = Xpub::decode(&pair.key.key)
                                    .map_err(|_| Error::XPubKey(
                                        "Can't deserialize ExtendedPublicKey from global XPUB key data"
                                    ))?;

                                if pair.value.is_empty() || pair.value.len() % 4 != 0 {
                                    return Err(Error::XPubKey(
                                        "Incorrect length of global xpub derivation data",
                                    ));
                                }

                                let child_count = pair.value.len() / 4 - 1;
                                let mut decoder = Cursor::new(pair.value);
                                let mut fingerprint = [0u8; 4];
                                decoder.read_exact(&mut fingerprint[..]).map_err(|_| {
                                    Error::XPubKey("Can't read global xpub fingerprint")
                                })?;
                                let mut path = Vec::<ChildNumber>::with_capacity(child_count);
                                while let Ok(index) = u32::consensus_decode(&mut decoder) {
                                    path.push(ChildNumber::from(index))
                                }
                                let derivation = DerivationPath::from(path);
                                // Keys, according to BIP-174, must be unique
                                if xpub_map
                                    .insert(xpub, (Fingerprint::from(fingerprint), derivation))
                                    .is_some()
                                {
                                    return Err(Error::XPubKey("Repeated global xpub key"));
                                }
                            } else {
                                return Err(Error::XPubKey(
                                    "Xpub global key must contain serialized Xpub data",
                                ));
                            }
                        }
                        PSBT_GLOBAL_VERSION => {
                            // key has to be empty
                            if pair.key.key.is_empty() {
                                // there can only be one version
                                if version.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);
                                    if vlen != 4 {
                                        return Err(Error::Version(
                                            "invalid global version value length (must be 4 bytes)",
                                        ));
                                    }
                                    version = Some(Decodable::consensus_decode(&mut decoder)?);
                                    // We only understand version 0 PSBTs. According to BIP-174 we
                                    // should throw an error if we see anything other than version 0.
                                    if version != Some(0) {
                                        return Err(Error::Version(
                                            "PSBT versions greater than 0 are not supported",
                                        ));
                                    }
                                } else {
                                    return Err(Error::DuplicateKey(pair.key));
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key));
                            }
                        }
                        PSBT_GLOBAL_PROPRIETARY => match proprietary
                            .entry(raw::ProprietaryKey::try_from(pair.key.clone())?)
                        {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            }
                            btree_map::Entry::Occupied(_) =>
                                return Err(Error::DuplicateKey(pair.key)),
                        },
                        _ => match unknowns.entry(pair.key) {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            }
                            btree_map::Entry::Occupied(k) =>
                                return Err(Error::DuplicateKey(k.key().clone())),
                        },
                    }
                }
                Err(crate::Error::NoMorePairs) => break,
                Err(e) => return Err(e),
            }
        }

        if let Some(tx) = tx {
            Ok(Global {
                unsigned_tx: tx,
                version: version.unwrap_or(0),
                xpub: xpub_map,
                proprietary,
                unknown: unknowns,
            })
        } else {
            Err(Error::MustHaveUnsignedTx)
        }
    }

    /// Creates a PSBT from an unsigned transaction.
    ///
    /// # Errors
    ///
    /// If transactions is not unsigned.
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, Error> {
        let global = Global {
            unsigned_tx: tx,
            xpub: Default::default(),
            version: 0,
            proprietary: Default::default(),
            unknown: Default::default(),
        };
        global.unsigned_tx_checks()?;
        Ok(global)
    }

    /// Checks that unsigned transaction does not have scriptSig's or witness data.
    pub fn unsigned_tx_checks(&self) -> Result<(), Error> {
        for txin in &self.unsigned_tx.input {
            if !txin.script_sig.is_empty() {
                return Err(Error::UnsignedTxHasScriptSigs);
            }

            if !txin.witness.is_empty() {
                return Err(Error::UnsignedTxHasScriptWitnesses);
            }
        }

        Ok(())
    }
    /// Combines this [`Psbt`] with `other` PSBT as described by BIP 174.
    ///
    /// In accordance with BIP 174 this function is commutative i.e., `A.combine(B) == B.combine(A)`
    pub fn combine(&mut self, other: Self) -> Result<(), Error> {
        if self.unsigned_tx != other.unsigned_tx {
            return Err(Error::UnexpectedUnsignedTx {
                expected: Box::new(self.unsigned_tx.clone()),
                actual: Box::new(other.unsigned_tx),
            });
        }

        // BIP 174: The Combiner must remove any duplicate key-value pairs, in accordance with
        //          the specification. It can pick arbitrarily when conflicts occur.

        // Keeping the highest version
        self.version = cmp::max(self.version, other.version);

        // Merging xpubs
        for (xpub, (fingerprint1, derivation1)) in other.xpub {
            match self.xpub.entry(xpub) {
                btree_map::Entry::Vacant(entry) => {
                    entry.insert((fingerprint1, derivation1));
                }
                btree_map::Entry::Occupied(mut entry) => {
                    // Here in case of the conflict we select the version with algorithm:
                    // 1) if everything is equal we do nothing
                    // 2) report an error if
                    //    - derivation paths are equal and fingerprints are not
                    //    - derivation paths are of the same length, but not equal
                    //    - derivation paths has different length, but the shorter one
                    //      is not the strict suffix of the longer one
                    // 3) choose longest derivation otherwise

                    let (fingerprint2, derivation2) = entry.get().clone();

                    if (derivation1 == derivation2 && fingerprint1 == fingerprint2)
                        || (derivation1.len() < derivation2.len()
                            && derivation1[..]
                                == derivation2[derivation2.len() - derivation1.len()..])
                    {
                        continue;
                    } else if derivation2[..]
                        == derivation1[derivation1.len() - derivation2.len()..]
                    {
                        entry.insert((fingerprint1, derivation1));
                        continue;
                    }
                    return Err(Error::CombineInconsistentKeySources(Box::new(xpub)));
                }
            }
        }

        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);
        Ok(())
    }
}
