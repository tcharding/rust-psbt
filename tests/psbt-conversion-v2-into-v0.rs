//! Tests for the lossy `Updater::into_psbt_v0` conversion (BIP-370 to BIP-174).

use std::str::FromStr;

use psbt_v2::bitcoin::bip32::{IntoDerivationPath, Xpriv, Xpub};
use psbt_v2::bitcoin::ecdsa::Signature as EcdsaSignature;
use psbt_v2::bitcoin::secp256k1::{self, Secp256k1};
use psbt_v2::bitcoin::sighash::EcdsaSighashType;
use psbt_v2::bitcoin::{absolute, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, TxOut};
use psbt_v2::v2::{Creator, Input, Output, Signer, Updater};
use psbt_v2::PsbtSighashType;

// source: valid compressed public keys (from secp256k1 generator point and a modified one)
const PUBKEY_HEX: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

// source: bip32 test vector
const TEST_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const TEST_XPRIV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

fn make_script(byte: u8) -> ScriptBuf { ScriptBuf::from(vec![byte; 4]) }

fn make_tx_out(sats: u64) -> TxOut {
    TxOut { value: Amount::from_sat(sats), script_pubkey: make_script(0xab) }
}

/// Populates global map with every v2 field that has a v0
/// equivalent then asserts every one survives the conversion.
#[test]
fn global_map_preserves_all_v0_compatible_fields() {
    let xpub = Xpub::from_str(TEST_XPUB).unwrap();
    let pk = PublicKey::from_str(PUBKEY_HEX).unwrap();
    let path = "m/0".into_derivation_path().unwrap();
    let fingerprint = xpub.fingerprint();

    let mut input_a = Input::new(&OutPoint::null());
    input_a.witness_utxo = Some(make_tx_out(50_000));
    input_a.redeem_script = Some(make_script(0x11));
    input_a.bip32_derivations.insert(pk, (fingerprint, path.clone()));

    let input_b = Input::new(&OutPoint::null());

    let mut output = Output::new(make_tx_out(40_000));
    output.witness_script = Some(make_script(0x22));

    let mut psbt = Creator::new()
        .constructor_modifiable()
        .input(input_a)
        .input(input_b)
        .output(output)
        .output(Output::new(make_tx_out(9_000)))
        .psbt()
        .unwrap();
    psbt.global.xpubs.insert(xpub, (fingerprint, path));

    let v0 = Updater::new(psbt).unwrap().into_psbt_v0();
    let parsed = psbt_v2::v0::Psbt::deserialize(&v0.serialize()).expect("v0 codec");

    assert_eq!(parsed, v0);
    assert!(parsed.xpub.contains_key(&xpub));
}

/// Populates input map with every v2 field that has a v0
/// equivalent then asserts every one survives the conversion.
#[test]
fn input_map_preserves_all_v0_compatible_fields() {
    let prev = OutPoint::null();
    let witness_utxo = make_tx_out(123_456);
    let redeem_script = make_script(0xde);
    let witness_script = make_script(0xad);
    let final_script_sig = make_script(0x51);
    let sighash = PsbtSighashType::from_str("SIGHASH_ALL").unwrap();
    let pk = PublicKey::from_str(PUBKEY_HEX).unwrap();
    let path = "m/0".into_derivation_path().unwrap();
    let fingerprint = Xpub::from_str(TEST_XPUB).unwrap().fingerprint();
    let secp = Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&[0x01u8; 32]).unwrap();
    let partial_sig_pk = PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, &sk));
    let partial_sig = EcdsaSignature {
        signature: secp.sign_ecdsa(&secp256k1::Message::from_digest([0x42u8; 32]), &sk),
        sighash_type: EcdsaSighashType::All,
    };

    let mut input = Input::new(&prev);
    input.witness_utxo = Some(witness_utxo.clone());
    input.redeem_script = Some(redeem_script.clone());
    input.witness_script = Some(witness_script.clone());
    input.final_script_sig = Some(final_script_sig.clone());
    input.sighash_type = Some(sighash);
    input.bip32_derivations.insert(pk, (fingerprint, path.clone()));
    input.partial_sigs.insert(partial_sig_pk, partial_sig);

    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .output(Output::new(make_tx_out(1)))
        .psbt()
        .unwrap();
    let v0_input = Updater::new(psbt).unwrap().into_psbt_v0().inputs.remove(0);

    assert_eq!(v0_input.witness_utxo, Some(witness_utxo));
    assert_eq!(v0_input.redeem_script, Some(redeem_script));
    assert_eq!(v0_input.witness_script, Some(witness_script));
    assert_eq!(v0_input.final_script_sig, Some(final_script_sig));
    assert_eq!(v0_input.sighash_type, Some(sighash));
    assert_eq!(v0_input.bip32_derivation.get(&pk), Some(&(fingerprint, path)));
    assert_eq!(v0_input.partial_sigs.get(&partial_sig_pk), Some(&partial_sig));
}

// If the conversion builds the unsigned transaction differently from what
// the v2 signer used, the signatures could differ or become invalid.
#[test]
fn signing_v2_then_converting_matches_signing_after_conversion() {
    let prev = OutPoint::null();
    let witness_utxo = make_tx_out(123_456);
    let pk = PublicKey::from_str(PUBKEY_HEX).unwrap();
    let path = "m/0".into_derivation_path().unwrap();
    let fingerprint = Xpub::from_str(TEST_XPUB).unwrap().fingerprint();

    let mut input = Input::new(&prev);
    input.witness_utxo = Some(witness_utxo);
    input.bip32_derivations.insert(pk, (fingerprint, path));

    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .output(Output::new(make_tx_out(1)))
        .psbt()
        .unwrap();

    let secp = Secp256k1::<secp256k1::All>::new();
    let xpriv = Xpriv::from_str(TEST_XPRIV).unwrap();

    let (signed_v2, _) = Signer::new(psbt.clone()).unwrap().sign(&xpriv, &secp).unwrap();
    let v2_signed_input = Updater::new(signed_v2).unwrap().into_psbt_v0().inputs.remove(0);

    let mut v0_psbt = Updater::new(psbt).unwrap().into_psbt_v0();
    v0_psbt.sign(&xpriv, &secp).unwrap();
    let v0_signed_input = v0_psbt.inputs.remove(0);

    assert_eq!(v0_signed_input.partial_sigs, v2_signed_input.partial_sigs);
}

/// Populates output map with every v2 field that has a v0
/// equivalent then asserts every one survives the conversion.
#[test]
fn output_map_preserves_all_v0_compatible_fields() {
    let redeem_script = make_script(0x01);
    let witness_script = make_script(0x02);
    let pk = PublicKey::from_str(PUBKEY_HEX).unwrap();
    let path = "m/1".into_derivation_path().unwrap();
    let fingerprint = Xpub::from_str(TEST_XPUB).unwrap().fingerprint();

    let mut output = Output::new(make_tx_out(7_000));
    output.redeem_script = Some(redeem_script.clone());
    output.witness_script = Some(witness_script.clone());
    output.bip32_derivations.insert(pk, (fingerprint, path.clone()));

    let psbt = Creator::new()
        .constructor_modifiable()
        .input(Input::new(&OutPoint::null()))
        .output(output)
        .psbt()
        .unwrap();
    let v0_out = Updater::new(psbt).unwrap().into_psbt_v0().outputs.remove(0);

    assert_eq!(v0_out.redeem_script, Some(redeem_script));
    assert_eq!(v0_out.witness_script, Some(witness_script));
    assert_eq!(v0_out.bip32_derivation.get(&pk), Some(&(fingerprint, path)));
}

/// Fields min_time/min_height and sequence have no v0 equivalent in the input map.
/// They must surface in unsigned_tx.lock_time and unsigned_tx.input[i].sequence.
#[test]
fn v2_only_input_fields_surface_in_v0_unsigned_tx() {
    let height = absolute::Height::from_consensus(800_000).unwrap();
    let mut input = Input::new(&OutPoint::null());
    input.min_height = Some(height);
    input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .output(Output::new(make_tx_out(1)))
        .psbt()
        .unwrap();

    let v0 = Updater::new(psbt).unwrap().into_psbt_v0();

    assert_eq!(v0.unsigned_tx.lock_time, absolute::LockTime::Blocks(height));
    assert_eq!(v0.unsigned_tx.input[0].sequence, Sequence::ENABLE_LOCKTIME_NO_RBF);
}
