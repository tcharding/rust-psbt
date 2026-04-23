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
use psbt_v2::bitcoin::{OutPoint, PrivateKey, PublicKey, ScriptBuf, TxOut};
use psbt_v2::v0::Psbt;
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
    supplementary: Supplementary,
}

/// Holds the optional hex/base64 encodings of a PSBT.
#[derive(Debug, Deserialize, Default)]
struct PsbtData {
    hex: Option<String>,
    base64: Option<String>,
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
    task: Task,

    /// Consensus-encoded hex of the final extracted transaction (extract task).
    #[serde(default, alias = "tx")]
    _tx: Option<String>,

    /// Input PSBTs for update/sign/combine/finalize/extract tasks.
    #[serde(default)]
    psbts: Option<Vec<PsbtData>>,

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

fn run_fail_deserialize(supplementary: &Supplementary) {
    if let Some(psbts) = &supplementary.psbts {
        for PsbtData { hex, base64 } in psbts {
            let hex = hex.as_deref().expect("fail vector must have hex");
            let base64 = base64.as_deref().expect("fail vector must have base64");
            util::assert_invalid_v0(hex, base64);
        }
    }
}

fn run_fail_sign(supplementary: &Supplementary) {
    if let Some(psbts) = &supplementary.psbts {
        for PsbtData { hex, base64 } in psbts {
            let hex = hex.as_deref().expect("fail vector must have hex");
            let base64 = base64.as_deref().expect("fail vector must have base64");
            let hex_psbt = util::hex_psbt_v0(hex).expect("should parse");
            let base64_psbt = Psbt::from_str(base64).expect("base64 must decode when hex decoded");
            assert_eq!(hex_psbt, base64_psbt);
            assert!(base64_psbt.signer_checks().is_err(), "expected signer_checks() to fail");
        }
    }
}

fn run_deserialize(supplementary: &Supplementary) {
    if let Some(psbts) = &supplementary.psbts {
        for PsbtData { hex, base64 } in psbts {
            let hex = hex.as_deref().expect("pass vector must have hex");
            let base64 = base64.as_deref().expect("pass vector must have base64");
            util::assert_valid_v0(hex, base64);
        }
    }
}

fn execute_case(case: &TestCase) {
    match case.supplementary.task {
        Task::FailDeserialize => run_fail_deserialize(&case.supplementary),
        Task::FailSign => run_fail_sign(&case.supplementary),
        Task::Deserialize => run_deserialize(&case.supplementary),
        Task::Create => unimplemented!("run_create not yet implemented"),
        Task::Update => unimplemented!("run_update not yet implemented"),
        Task::Sign => unimplemented!("run_sign not yet implemented"),
        Task::Combine => unimplemented!("run_combine not yet implemented"),
        Task::Finalize => unimplemented!("run_finalize not yet implemented"),
        Task::Extract => unimplemented!("run_extract not yet implemented"),
    }
}

fn check_case(idx: usize) {
    static VECTORS: OnceLock<TestFile> = OnceLock::new();
    let file = VECTORS.get_or_init(|| {
        let data: &str = include_str!("data/bip174_vectors.json");
        serde_json::from_str(data).expect("failed to deserialise bip174_vectors.json")
    });
    execute_case(&file.cases[idx]);
}

#[test]
fn network_transaction_not_psbt_format() { check_case(0); }

#[test]
fn missing_outputs() { check_case(1); }

#[test]
fn unsigned_tx_has_signatures() { check_case(2); }

#[test]
fn missing_unsigned_tx() { check_case(3); }

#[test]
fn duplicate_keys_in_input() { check_case(4); }

#[test]
fn invalid_global_transaction() { check_case(5); }

#[test]
fn invalid_input_witness_utxo() { check_case(6); }

#[test]
fn invalid_pubkey_length_for_input_partial_signature() { check_case(7); }

#[test]
fn invalid_redeemscript() { check_case(8); }

#[test]
fn invalid_witness_script() { check_case(9); }

#[test]
fn invalid_pubkey_in_input_bip_32_derivation_paths() { check_case(10); }

#[test]
fn invalid_non_witness_utxo() { check_case(11); }

#[test]
fn invalid_final_scriptsig() { check_case(12); }

#[test]
fn invalid_final_script_witness() { check_case(13); }

#[test]
fn invalid_pubkey_in_output_bip_32_derivation_paths() { check_case(14); }

#[test]
fn invalid_input_sighash_type() { check_case(15); }

#[test]
fn invalid_output_redeemscript() { check_case(16); }

#[test]
fn invalid_output_witness_script() { check_case(17); }

#[test]
fn unsigned_tx_serialized_with_witness_serialization_format() { check_case(18); }

#[test]
fn value_data_size_does_not_match_value_len() { check_case(19); }

#[test]
fn no_outputs_one_p2pkh_input() { check_case(20); }

#[test]
fn no_outputs_one_p2sh_p2wpkh_input_and_one_signed_and_finalized_p2pkh_input() { check_case(21); }

#[test]
fn no_outputs_and_a_p2pkh_input_without_final_scriptsig_and_sighash_type_set() { check_case(22); }

#[test]
fn outputs_filled_with_p2pkh_input_and_p2sh_p2wpkh_input_with_reedem_script_both_with_non_final_scriptsigs(
) {
    check_case(23);
}

#[test]
fn one_p2sh_p2wsh_2_of_2_multisig_input_with_redeemscript_witness_script_and_keypaths_one_signature_available(
) {
    check_case(24);
}

#[test]
fn outputs_filled_one_p2wsh_2_of_2_multisig_input_witness_script_keypaths_and_global_xpubs_available_no_signatures(
) {
    check_case(25);
}

#[test]
fn unknown_types_in_the_inputs() { check_case(26); }

#[test]
fn psbt_global_xpub() { check_case(27); }

#[test]
fn no_inputs_nor_outputs_in_global_unsigned_tx() { check_case(28); }

#[test]
fn no_inputs() { check_case(29); }

#[test]
fn witness_utxo_provided_for_non_witness_input() { check_case(30); }

#[test]
fn redeemscript_with_non_witness_utxo_does_not_match_the_scriptpubkey() { check_case(31); }

#[test]
fn redeemscript_with_witness_utxo_does_not_match_the_scriptpubkey() { check_case(32); }

#[test]
fn witness_script_with_witness_utxo_does_not_match_the_redeemscript() { check_case(33); }
