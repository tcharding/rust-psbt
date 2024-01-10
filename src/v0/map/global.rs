// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;
use core::{cmp, fmt};

use bitcoin::bip32::{self, ChildNumber, DerivationPath, Fingerprint, KeySource, Xpub};
// TODO: This should be exposed like this in rust-bitcoin.
use bitcoin::consensus::encode as consensus;
use bitcoin::consensus::encode::MAX_VEC_SIZE;
use bitcoin::consensus::Decodable;
use bitcoin::transaction::Transaction;

use crate::consts::{
    PSBT_GLOBAL_FALLBACK_LOCKTIME, PSBT_GLOBAL_INPUT_COUNT, PSBT_GLOBAL_OUTPUT_COUNT,
    PSBT_GLOBAL_PROPRIETARY, PSBT_GLOBAL_TX_MODIFIABLE, PSBT_GLOBAL_TX_VERSION,
    PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_VERSION, PSBT_GLOBAL_XPUB,
};
use crate::error::{write_err, InconsistentKeySourcesError};
use crate::io::{self, Cursor, Read};
use crate::prelude::*;
use crate::v0::error::{CombineError, UnsignedTxChecksError};
use crate::v0::map::Map;
use crate::version::Version;
use crate::{consts, raw, serialize, V0};

/// The global key-value map.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Global {
    /// The unsigned transaction, scriptSigs and witnesses for each input must be empty.
    pub unsigned_tx: Transaction,
    /// The version number of this PSBT. If omitted, the version number is 0.
    pub version: Version,
    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32.
    pub xpubs: BTreeMap<Xpub, KeySource>,
    /// Global proprietary key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown global key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknowns: BTreeMap<raw::Key, Vec<u8>>,
}

// TODO: Change this to a new DecodeError same as in v2.
impl Global {
    pub(crate) fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, DecodeError> {
        let mut r = r.take(MAX_VEC_SIZE as u64);
        let mut tx: Option<Transaction> = None;
        let mut version: Option<Version> = None;
        let mut unknowns: BTreeMap<raw::Key, Vec<u8>> = Default::default();
        let mut xpubs: BTreeMap<Xpub, (Fingerprint, DerivationPath)> = Default::default();
        let mut proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>> = Default::default();

        // Use a closure so we can insert pair into one of the mutable local variables above.
        let mut insert_pair = |pair: raw::Pair| {
            match pair.key.type_value {
                PSBT_GLOBAL_UNSIGNED_TX =>
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
                                return Err(InsertPairError::DecodeTxPartial);
                            }
                        } else {
                            return Err(InsertPairError::DuplicateKey(pair.key));
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataNotEmpty(pair.key));
                    },
                PSBT_GLOBAL_VERSION =>
                    if pair.key.key.is_empty() {
                        if version.is_none() {
                            let vlen: usize = pair.value.len();
                            let mut decoder = Cursor::new(pair.value);
                            if vlen != 4 {
                                return Err::<(), InsertPairError>(
                                    InsertPairError::ValueWrongLength(vlen, 4),
                                );
                            }
                            let ver = Decodable::consensus_decode(&mut decoder)?;
                            if ver != 0 {
                                return Err(InsertPairError::WrongVersion(ver));
                            }
                            version = Some(Version::try_from(ver).expect("valid, this is 0"));
                        } else {
                            return Err(InsertPairError::DuplicateKey(pair.key));
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataNotEmpty(pair.key));
                    },
                PSBT_GLOBAL_XPUB =>
                    if !pair.key.key.is_empty() {
                        let xpub = Xpub::decode(&pair.key.key)?;
                        if pair.value.is_empty() {
                            // TODO: keypair value is empty, consider adding a better error type.
                            return Err(InsertPairError::InvalidKeyDataNotEmpty(pair.key));
                        }
                        if pair.value.len() < 4 {
                            // TODO: Add better error here.
                            return Err(InsertPairError::XpubInvalidFingerprint);
                        }
                        // TODO: Can we restrict the value further?
                        if pair.value.len() % 4 != 0 {
                            return Err(InsertPairError::XpubInvalidPath(pair.value.len()));
                        }

                        let child_count = pair.value.len() / 4 - 1;
                        let mut decoder = Cursor::new(pair.value);
                        let mut fingerprint = [0u8; 4];
                        decoder
                            .read_exact(&mut fingerprint[..])
                            .expect("in-memory readers don't err");
                        let mut path = Vec::<ChildNumber>::with_capacity(child_count);
                        while let Ok(index) = u32::consensus_decode(&mut decoder) {
                            path.push(ChildNumber::from(index))
                        }
                        let derivation = DerivationPath::from(path);
                        // Keys, according to BIP-174, must be unique
                        if let Some(key_source) =
                            xpubs.insert(xpub, (Fingerprint::from(fingerprint), derivation))
                        {
                            return Err(InsertPairError::DuplicateXpub(key_source));
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataEmpty(pair.key));
                    },
                PSBT_GLOBAL_PROPRIETARY =>
                    if !pair.key.key.is_empty() {
                        match proprietaries.entry(
                            raw::ProprietaryKey::try_from(pair.key.clone())
                                .map_err(|_| InsertPairError::InvalidProprietaryKey)?,
                        ) {
                            btree_map::Entry::Vacant(empty_key) => {
                                empty_key.insert(pair.value);
                            }
                            btree_map::Entry::Occupied(_) =>
                                return Err(InsertPairError::DuplicateKey(pair.key)),
                        }
                    } else {
                        return Err(InsertPairError::InvalidKeyDataEmpty(pair.key));
                    },
                v if v == PSBT_GLOBAL_TX_VERSION
                    || v == PSBT_GLOBAL_TX_MODIFIABLE
                    || v == PSBT_GLOBAL_FALLBACK_LOCKTIME
                    || v == PSBT_GLOBAL_INPUT_COUNT
                    || v == PSBT_GLOBAL_OUTPUT_COUNT =>
                {
                    return Err(InsertPairError::ExcludedKey { key_type_value: v });
                }
                _ => match unknowns.entry(pair.key) {
                    btree_map::Entry::Vacant(empty_key) => {
                        empty_key.insert(pair.value);
                    }
                    btree_map::Entry::Occupied(k) => {
                        return Err(InsertPairError::DuplicateKey(k.key().clone()));
                    }
                },
            }
            Ok(())
        };

        loop {
            match raw::Pair::decode(&mut r) {
                Ok(pair) => insert_pair(pair)?,
                Err(serialize::Error::NoMorePairs) => break,
                Err(e) => return Err(DecodeError::DeserPair(e)),
            }
        }

        if let Some(tx) = tx {
            Ok(Global {
                unsigned_tx: tx,
                version: version.unwrap_or(Version::ZERO),
                xpubs,
                proprietaries,
                unknowns,
            })
        } else {
            Err(DecodeError::MissingUnsignedTx)
        }
    }

    /// Creates a PSBT from an unsigned transaction.
    ///
    /// # Errors
    ///
    /// If transactions is not unsigned.
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, UnsignedTxChecksError> {
        let global = Global {
            unsigned_tx: tx,
            xpubs: Default::default(),
            version: Version::ZERO,
            proprietaries: Default::default(),
            unknowns: Default::default(),
        };
        global.unsigned_tx_checks()?;
        Ok(global)
    }

    /// Checks that unsigned transaction does not have scriptSig's or witness data.
    pub fn unsigned_tx_checks(&self) -> Result<(), UnsignedTxChecksError> {
        use UnsignedTxChecksError::*;

        for txin in &self.unsigned_tx.input {
            if !txin.script_sig.is_empty() {
                return Err(HasScriptSigs);
            }

            if !txin.witness.is_empty() {
                return Err(HasScriptWitnesses);
            }
        }

        Ok(())
    }

    /// Combines this [`Global`] with `other`.
    ///
    /// In accordance with BIP 174 this function is commutative i.e., `A.combine(B) == B.combine(A)`
    pub fn combine(&mut self, other: Self) -> Result<(), CombineError> {
        if self.unsigned_tx != other.unsigned_tx {
            return Err(CombineError::UnexpectedUnsignedTx {
                expected: Box::new(self.unsigned_tx.clone()),
                actual: Box::new(other.unsigned_tx),
            });
        }

        // BIP 174: The Combiner must remove any duplicate key-value pairs, in accordance with
        //          the specification. It can pick arbitrarily when conflicts occur.

        // Keeping the highest version
        self.version = cmp::max(self.version, other.version);

        // Merging xpubs
        for (xpub, (fingerprint1, derivation1)) in other.xpubs {
            match self.xpubs.entry(xpub) {
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
                    return Err(InconsistentKeySourcesError(xpub).into());
                }
            }
        }

        combine_map!(proprietaries, self, other);
        combine_map!(unknowns, self, other);

        Ok(())
    }
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

        for (xpub, (fingerprint, derivation)) in &self.xpubs {
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
        if self.version != V0 {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_VERSION, key: vec![] },
                value: self.version.to_u32().to_le_bytes().to_vec(),
            });
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

#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// Error inserting a key-value pair.
    InsertPair(InsertPairError),
    /// Error deserializing a pair.
    DeserPair(serialize::Error),
    /// Serialized PSBT is missing the version number.
    MissingVersion,
    /// Serialized PSBT is missing the transaction version number.
    MissingTxVersion,
    /// Serialized PSBT is missing the input count.
    MissingInputCount,
    /// Input count overflows word size for current architecture.
    InputCountOverflow(u64),
    /// Serialized PSBT is missing the output count.
    MissingOutputCount,
    /// Output count overflows word size for current architecture.
    OutputCountOverflow(u64),
    /// PSBT v0 requires an unsigned transaction.
    MissingUnsignedTx,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecodeError::*;

        match *self {
            InsertPair(ref e) => write_err!(f, "error inserting a pair"; e),
            DeserPair(ref e) => write_err!(f, "error deserializing a pair"; e),
            MissingVersion => write!(f, "serialized PSBT is missing the version number"),
            MissingTxVersion =>
                write!(f, "serialized PSBT is missing the transaction version number"),
            MissingInputCount => write!(f, "serialized PSBT is missing the input count"),
            InputCountOverflow(count) =>
                write!(f, "input count overflows word size for current architecture: {}", count),
            MissingOutputCount => write!(f, "serialized PSBT is missing the output count"),
            OutputCountOverflow(count) =>
                write!(f, "output count overflows word size for current architecture: {}", count),
            MissingUnsignedTx => write!(f, "PSBT v0 requires an unsigned transaction"),
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
            MissingVersion
            | MissingTxVersion
            | MissingInputCount
            | InputCountOverflow(_)
            | MissingOutputCount
            | OutputCountOverflow(_)
            | MissingUnsignedTx => None,
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
    /// Key should contain data.
    InvalidKeyDataEmpty(raw::Key),
    /// Key should not contain data.
    InvalidKeyDataNotEmpty(raw::Key),
    /// Error deserializing raw value.
    Deser(serialize::Error),
    /// Error consensus deserializing value.
    Consensus(consensus::Error),
    /// Transaction decoding did not consume all key-value data.
    DecodeTxPartial,
    /// Value was not the correct length (got, want).
    // TODO: Use struct instead of tuple.
    ValueWrongLength(usize, usize),
    /// PSBT_GLOBAL_VERSION: PSBT v0 expects the version to be 0.
    WrongVersion(u32),
    /// PSBT_GLOBAL_XPUB: Must contain 4 bytes for the xpub fingerprint.
    XpubInvalidFingerprint,
    /// PSBT_GLOBAL_XPUB: derivation path must be a list of 32 byte varints.
    XpubInvalidPath(usize),
    /// PSBT_GLOBAL_XPUB: Failed to decode a BIP-32 type.
    Bip32(bip32::Error),
    /// PSBT_GLOBAL_XPUB: xpubs must be unique.
    DuplicateXpub(KeySource),
    /// PSBT_GLOBAL_PROPRIETARY: Invalid proprietary key.
    InvalidProprietaryKey,
    /// Key must be excluded from this version of PSBT (see consts.rs for u8 values).
    ExcludedKey { key_type_value: u8 },
}

impl fmt::Display for InsertPairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InsertPairError::*;

        match *self {
            DuplicateKey(ref key) => write!(f, "duplicate key: {}", key),
            InvalidKeyDataEmpty(ref key) => write!(f, "key should contain data: {}", key),
            InvalidKeyDataNotEmpty(ref key) => write!(f, "key should not contain data: {}", key),
            Deser(ref e) => write_err!(f, "error deserializing raw value"; e),
            Consensus(ref e) => write_err!(f, "error consensus deserializing type"; e),
            DecodeTxPartial => write!(f, "transaction decoding did not consume all key-value data"),
            ValueWrongLength(got, want) =>
                write!(f, "value (keyvalue pair) wrong length (got, want) {} {}", got, want),
            WrongVersion(v) =>
                write!(f, "PSBT_GLOBAL_VERSION: PSBT v2 expects the version to be 2, found: {}", v),
            XpubInvalidFingerprint =>
                write!(f, "PSBT_GLOBAL_XPUB: derivation path must be a list of 32 byte varints"),
            XpubInvalidPath(len) => write!(
                f,
                "PSBT_GLOBAL_XPUB: derivation path must be a list of 32 byte varints: {}",
                len
            ),
            Bip32(ref e) => write_err!(f, "PSBT_GLOBAL_XPUB: Failed to decode a BIP-32 type"; e),
            DuplicateXpub((fingerprint, ref derivation_path)) => write!(
                f,
                "PSBT_GLOBAL_XPUB: xpubs must be unique ({}, {})",
                fingerprint, derivation_path
            ),
            InvalidProprietaryKey => write!(f, "PSBT_GLOBAL_PROPRIETARY: Invalid proprietary key"),
            ExcludedKey { key_type_value } => write!(
                f,
                "found a keypair type that is explicitly excluded: {}",
                consts::psbt_global_key_type_value_to_str(key_type_value)
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InsertPairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InsertPairError::*;

        match *self {
            Deser(ref e) => Some(e),
            Consensus(ref e) => Some(e),
            Bip32(ref e) => Some(e),
            DuplicateKey(_)
            | DecodeTxPartial
            | InvalidKeyDataEmpty(_)
            | InvalidKeyDataNotEmpty(_)
            | ValueWrongLength(..)
            | WrongVersion(_)
            | XpubInvalidFingerprint
            | XpubInvalidPath(_)
            | DuplicateXpub(_)
            | InvalidProprietaryKey
            | ExcludedKey { .. } => None,
        }
    }
}

impl From<serialize::Error> for InsertPairError {
    fn from(e: serialize::Error) -> Self { Self::Deser(e) }
}

impl From<consensus::Error> for InsertPairError {
    fn from(e: consensus::Error) -> Self { Self::Consensus(e) }
}

impl From<bip32::Error> for InsertPairError {
    fn from(e: bip32::Error) -> Self { Self::Bip32(e) }
}
