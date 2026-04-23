//! BIP-174 test vector executor.
//!
//! Data driven BIP 174 test vectors executor.
//!
//! Parses `bip174_vectors.json` and runs each case through a single dispatcher
//! keyed on the `task` field. One `#[test]` per vector, named after its
//! `description`, so `cargo test` output maps 1-to-1 with the JSON document.

#![cfg(all(feature = "std", feature = "base64", feature = "serde"))]

mod util;

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::OnceLock;

use bitcoin::{transaction, Sequence, Transaction, TxIn, Witness};
use psbt_v2::bitcoin::absolute::LockTime;
use psbt_v2::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use psbt_v2::bitcoin::consensus::encode::deserialize;
use psbt_v2::bitcoin::hex::FromHex;
use psbt_v2::bitcoin::secp256k1::Secp256k1;
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
    pub key: PublicKey,
    pub path: DerivationPath,
}

#[derive(Debug, Deserialize)]
struct PrivKeyPath {
    pub key: PrivateKey,
    pub path: DerivationPath,
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
    #[serde(default)]
    expected: PsbtData,
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
    #[serde(default)]
    previous_tx: String,
    /// If true, install the matched output as `witness_utxo`; otherwise
    /// install the whole transaction as `non_witness_utxo`.
    #[serde(default)]
    witness: bool,
    #[serde(default)]
    redeem_script: Option<ScriptBuf>,
    #[serde(default)]
    witness_script: Option<ScriptBuf>,
    #[serde(default)]
    bip32_derivation: Vec<PubKeyPath>,
}

/// Per-output update data for the updater task (positional).
#[derive(Debug, Deserialize, Default)]
struct OutputUpdate {
    #[serde(default)]
    bip32_derivation: Vec<PubKeyPath>,
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
    #[serde(default)]
    xpriv: Option<Xpriv>,

    /// Seed WIF (create task - used to verify xpriv derivation).
    #[serde(default)]
    seed: Option<PrivateKey>,

    /// Transaction inputs for the creator task.
    #[serde(default)]
    inputs: Option<Vec<OutPoint>>,

    /// Transaction outputs for the creator task.
    #[serde(default)]
    outputs: Option<Vec<TxOut>>,

    /// Private key / derivation path pairs (sign task).
    #[serde(default)]
    private_keys: Option<Vec<PrivKeyPath>>,

    /// Sighash type symbolic name.
    #[serde(default, deserialize_with = "deserialize_sighash")]
    sighash: Option<PsbtSighashType>,

    /// Per-input update directives for the updater task.
    #[serde(default)]
    input_updates: Option<Vec<InputUpdate>>,

    /// Per-output update directives for the updater task (positional).
    #[serde(default)]
    output_updates: Option<Vec<OutputUpdate>>,
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

/// Creator: build an unsigned transaction from the given inputs and outputs,
/// wrap it in a PSBT, and compare against the expected serialisation.
fn run_create(expected: &PsbtData, supplementary: &Supplementary) {
    let inputs = supplementary.inputs.as_ref().expect("create task needs inputs");
    let outputs = supplementary.outputs.as_ref().expect("create task needs outputs");
    let expected_hex = expected.hex.as_deref().expect("create expected must have hex");

    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .iter()
            .map(|o| TxIn {
                previous_output: OutPoint { txid: o.txid, vout: o.vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            })
            .collect(),
        output: outputs.clone(),
    };

    let psbt = Psbt::from_unsigned_tx(tx).expect("failed to create PSBT from unsigned tx");
    let expected_psbt = util::hex_psbt_v0(expected_hex).expect("expected PSBT must be valid");
    assert_eq!(psbt, expected_psbt);
}

/// Decode a consensus-encoded transaction from a hex string.
fn consensus_tx(hex: &str) -> Transaction {
    let bytes = Vec::from_hex(hex).expect("previous_tx must be valid hex");
    deserialize::<Transaction>(&bytes).expect("previous_tx must be a valid transaction")
}

/// Updater: apply whatever combination of UTXOs, scripts, BIP-32 derivation
/// paths, and sighash type the vector specifies, then compare against the
/// expected PSBT.
///
/// Per-input updates are matched to PSBT inputs by `txid(previous_tx)`.
/// Per-output updates are applied positionally.
/// A sighash type, when present, is applied to every input.
fn run_update(expected: &PsbtData, supplementary: &Supplementary) {
    let input_psbts = supplementary.psbts.as_deref().unwrap_or(&[]);
    assert!(!input_psbts.is_empty(), "update task needs at least one input PSBT");
    let input_hex = input_psbts[0].hex.as_deref().expect("update input must have hex");
    let mut psbt = util::hex_psbt_v0(input_hex).expect("update input PSBT must be valid");

    let expected_hex = expected.hex.as_deref().expect("update expected must have hex");
    let expected_psbt =
        util::hex_psbt_v0(expected_hex).expect("update expected PSBT must be valid");

    // Compute the fingerprint lazily — only needed when bip32_derivation is present.
    let fp = supplementary.xpriv.map(|xpriv| {
        let secp = Secp256k1::new();
        Xpub::from_priv(&secp, &xpriv).fingerprint()
    });

    if let Some(updates) = supplementary.input_updates.as_ref() {
        for u in updates {
            let prev_tx = consensus_tx(&u.previous_tx);
            let txid = prev_tx.compute_txid();
            let i = psbt
                .unsigned_tx
                .input
                .iter()
                .position(|txin| txin.previous_output.txid == txid)
                .expect("input_update previous_tx does not match any PSBT input");
            let vout = psbt.unsigned_tx.input[i].previous_output.vout as usize;
            if u.witness {
                psbt.inputs[i].witness_utxo = Some(prev_tx.output[vout].clone());
            } else {
                psbt.inputs[i].non_witness_utxo = Some(prev_tx);
            }
            if let Some(rs) = &u.redeem_script {
                psbt.inputs[i].redeem_script = Some(rs.clone());
            }
            if let Some(ws) = &u.witness_script {
                psbt.inputs[i].witness_script = Some(ws.clone());
            }
            if !u.bip32_derivation.is_empty() {
                let fp = fp.expect("bip32_derivation requires xpriv");
                psbt.inputs[i].bip32_derivation =
                    u.bip32_derivation.iter().map(|p| (p.key, (fp, p.path.clone()))).collect();
            }
        }
    }

    if let Some(updates) = supplementary.output_updates.as_ref() {
        for (i, u) in updates.iter().enumerate() {
            if !u.bip32_derivation.is_empty() {
                let fp = fp.expect("bip32_derivation requires xpriv");
                psbt.outputs[i].bip32_derivation =
                    u.bip32_derivation.iter().map(|p| (p.key, (fp, p.path.clone()))).collect();
            }
        }
    }

    if let Some(sighash) = supplementary.sighash {
        for input in &mut psbt.inputs {
            input.sighash_type = Some(sighash);
        }
    }

    assert_eq!(psbt, expected_psbt);
}

/// Signer: for each listed private key, derive it from the canonical BIP-174
/// master xpriv via the supplied path, assert it matches the WIF key in the
/// vector (strict verification), then sign the PSBT and compare.
fn run_sign(expected: &PsbtData, supplementary: &Supplementary) {
    let secp = Secp256k1::new();
    let xpriv = supplementary.xpriv.expect("must be available to verify public keys");

    if let Some(sk) = supplementary.seed {
        let seeded = Xpriv::new_master(xpriv.network, &sk.inner.secret_bytes()).unwrap();
        assert_eq!(seeded, xpriv);
    }

    let input_psbts = supplementary.psbts.as_deref().unwrap_or(&[]);
    assert!(!input_psbts.is_empty(), "sign task needs at least one input PSBT");
    let input_hex = input_psbts[0].hex.as_deref().expect("sign input must have hex");
    let mut psbt = util::hex_psbt_v0(input_hex).expect("sign input PSBT must be valid");

    let expected_hex = expected.hex.as_deref().expect("sign expected must have hex");
    let expected_psbt = util::hex_psbt_v0(expected_hex).expect("sign expected PSBT must be valid");

    let mut key_map: BTreeMap<PublicKey, PrivateKey> = BTreeMap::new();

    if let Some(priv_key_paths) = &supplementary.private_keys {
        for PrivKeyPath { key: wif_priv, path } in priv_key_paths {
            let derived =
                xpriv.derive_priv(&secp, path).expect("derivation must succeed").to_priv();
            assert_eq!(
                *wif_priv, derived,
                "WIF key in vector must match derivation from canonical xpriv"
            );
            key_map.insert(wif_priv.public_key(&secp), *wif_priv);
        }
    }

    // sign() returns Err when it encounters errors for some inputs, even if
    // other inputs were signed successfully. We tolerate errors only when the
    // failing input had no key in our map (expected for multisig where we hold
    // a subset of the required keys).
    match psbt.sign(&key_map, &secp) {
        Ok(_) => {}
        Err((_, errors)) =>
            for (input_idx, err) in &errors {
                assert!(
                    matches!(err, psbt_v2::v0::bitcoin::SignError::KeyNotFound),
                    "unexpected sign error on input {}: {:?}",
                    input_idx,
                    err
                );
            },
    }
    assert_eq!(psbt, expected_psbt);
}

fn execute_case(case: &TestCase) {
    match case.supplementary.task {
        Task::FailDeserialize => run_fail_deserialize(&case.supplementary),
        Task::FailSign => run_fail_sign(&case.supplementary),
        Task::Deserialize => run_deserialize(&case.supplementary),
        Task::Create => run_create(&case.expected, &case.supplementary),
        Task::Update => run_update(&case.expected, &case.supplementary),
        Task::Sign => run_sign(&case.expected, &case.supplementary),
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

#[test]
fn workflow_a_step_1_creator_creates_psbt() { check_case(34); }

#[test]
fn workflow_a_step_2_updater_updates_keys() { check_case(35); }

#[test]
fn workflow_a_step_3_updater_updates_sighash() { check_case(36); }

#[test]
fn workflow_a_step_4_signer_that_supports_sighash_all_for_p2pkh_and_p2wpkh_spends_and_uses_rfc6979_for_nonce_generation_provides_first_signature(
) {
    check_case(37);
}

#[test]
fn workflow_a_step_5_signer_provides_second_signature() { check_case(38); }
