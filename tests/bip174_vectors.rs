//! BIP-174 test vector executor.
//!
//! Data driven BIP 174 test vectors executor.
//!
//! Parses `bip174_vectors.json` and runs each case through a single dispatcher
//! keyed on the `task` field. One `#[test]` per vector, named after its
//! `description`, so `cargo test` output maps 1-to-1 with the JSON document.

#![cfg(all(feature = "std", feature = "base64", feature = "serde"))]

mod util;

use std::str::FromStr;
use std::sync::OnceLock;

use psbt_v2::bitcoin::bip32::{DerivationPath, Xpriv};
use psbt_v2::bitcoin::{
    OutPoint, PrivateKey, PublicKey, ScriptBuf, TxOut,
};
use psbt_v2::PsbtSighashType;
use serde::{de, Deserialize, Deserializer};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Task {
    FailDeserialize,
    FailSign,
    Deserialize,
    Create,
    Update,
    Sign,
    Combine,
    Finalize,
    Extract,
}

#[derive(Debug, Deserialize)]
struct PubKeyPath {
    #[serde(alias = "key")]
    pub _key: PublicKey,
    #[serde(alias = "path")]
    pub _path: DerivationPath,
}

#[derive(Debug, Deserialize)]
struct PrivKeyPath {
    #[serde(alias = "key")]
    pub _key: PrivateKey,
    #[serde(alias = "path")]
    pub _path: DerivationPath,
}

fn deserialize_sighash<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<PsbtSighashType>, D::Error> {
    let opt: Option<String> = Option::deserialize(d)?;
    match opt {
        None => Ok(None),
        Some(s) => PsbtSighashType::from_str(&s).map(Some).map_err(de::Error::custom),
    }
}

#[derive(Debug, Deserialize)]
struct TestFile {
    cases: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    #[serde(default, alias = "description")]
    _description: String,
    #[serde(default, alias = "expected")]
    _expected: PsbtData,
    #[serde(alias = "supplementary")]
    _supplementary: Supplementary,
}

/// Holds the optional hex/base64 encodings of a PSBT.
#[derive(Debug, Deserialize, Default)]
struct PsbtData {
    #[serde(default, alias = "hex")]
    _hex: Option<String>,
    #[serde(default, alias = "base64")]
    _base64: Option<String>,
}

/// Per-input update data for the updater task.
///
/// Matched to a PSBT input by computing `txid(previous_tx)` and finding the
/// input whose `previous_output.txid` equals it.
#[derive(Debug, Deserialize)]
struct InputUpdate {
    /// Consensus-encoded hex of the funding transaction.
    #[serde(alias = "previous_tx")]
    _previous_tx: String,
    /// If true, install the matched output as `witness_utxo`; otherwise
    /// install the whole transaction as `non_witness_utxo`.
    #[serde(default, alias = "witness")]
    _witness: bool,
    #[serde(default, alias = "redeem_script")]
    _redeem_script: Option<ScriptBuf>,
    #[serde(default, alias = "witness_script")]
    _witness_script: Option<ScriptBuf>,
    #[serde(default, alias = "bip32_derivation")]
    _bip32_derivation: Vec<PubKeyPath>,
}

/// Per-output update data for the updater task (positional).
#[derive(Debug, Deserialize, Default)]
struct OutputUpdate {
    #[serde(default, alias = "bip32_derivation")]
    _bip32_derivation: Vec<PubKeyPath>,
}

#[derive(Debug, Deserialize)]
struct Supplementary {
    #[serde(alias = "task")]
    _task: Task,

    /// Consensus-encoded hex of the final extracted transaction (extract task).
    #[serde(default, alias = "tx")]
    _tx: Option<String>,

    /// Input PSBTs for update/sign/combine/finalize/extract tasks.
    #[serde(default, alias = "psbts")]
    _psbts: Option<Vec<PsbtData>>,

    /// Master extended private key (create/update tasks).
    #[serde(default, alias = "xpriv")]
    _xpriv: Option<Xpriv>,

    /// Seed WIF (create task - used to verify xpriv derivation).
    #[serde(default, alias = "seed")]
    _seed: Option<PrivateKey>,

    /// Transaction inputs for the creator task.
    #[serde(default, alias = "inputs")]
    _inputs: Option<Vec<OutPoint>>,

    /// Transaction outputs for the creator task.
    #[serde(default, alias = "outputs")]
    _outputs: Option<Vec<TxOut>>,

    /// Private key / derivation path pairs (sign task).
    #[serde(default, alias = "private_keys")]
    _private_keys: Option<Vec<PrivKeyPath>>,

    /// Sighash type symbolic name.
    #[serde(default, deserialize_with = "deserialize_sighash", alias = "sighash")]
    _sighash: Option<PsbtSighashType>,

    /// Per-input update directives for the updater task.
    #[serde(default, alias = "input_updates")]
    _input_updates: Option<Vec<InputUpdate>>,

    /// Per-output update directives for the updater task (positional).
    #[serde(default, alias = "output_updates")]
    _output_updates: Option<Vec<OutputUpdate>>,
}

fn execute_case(_case: &TestCase) {}

fn check_case(idx: usize) {
    static VECTORS: OnceLock<TestFile> = OnceLock::new();
    let file = VECTORS.get_or_init(|| {
        let data: &str = include_str!("data/bip174_vectors.json");
        serde_json::from_str(data).expect("failed to deserialise bip174_vectors.json")
    });
    execute_case(&file.cases[idx]);
}

#[test]
fn read_json() {
    check_case(1);
}
