// SPDX-License-Identifier: CC0-1.0

//! PSBT v0 (BIP-174) integration tests against a running `bitcoind` instance.
//!
//! Each test exercises a specific transaction type through the v0 codec. The PSBT is built with
//! the v2 API and serialized as v0. `decodepsbt` verifies Core can parse the PSBT envelope, and
//! `sendrawtransaction` verifies Core accepts the extracted tx.

use bitcoind_tests::client::Client;
use psbt::bitcoin::bip32::{IntoDerivationPath, Xpriv, Xpub};
use psbt::bitcoin::secp256k1::Secp256k1;
use psbt::bitcoin::{Address, Amount, CompressedPublicKey, Network, OutPoint, TxOut};
use psbt::psbt::{Creator, Finalizer, Signer};
use psbt::{Extractor, InputBuilder, OutputBuilder};
use psbt_v2 as psbt;

const TEST_XPRIV: &str =
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const TEST_XPUB: &str =
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

const NETWORK: Network = Network::Regtest;
const ONE_BTC: Amount = Amount::from_int_btc(1);
const FEE: Amount = Amount::from_sat(1_000);

/// A single P2WPKH input spending to a P2WPKH output and a change output.
#[test]
fn p2wpkh() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::new()?;
    client.mine_a_block()?;

    // Generate key material.
    let xpriv: Xpriv = TEST_XPRIV.parse()?;
    let xpub: Xpub = TEST_XPUB.parse()?;
    let fingerprint = xpub.fingerprint();
    let path = "m/0".into_derivation_path()?;
    let secp = Secp256k1::new();

    let (cpk, address) = {
        let derived = xpriv.derive_priv(&secp, &path)?;
        let xpub = Xpub::from_priv(&secp, &derived);
        let pk = xpub.to_pub();
        let cpk = CompressedPublicKey::try_from(pk).expect("compressed");
        (cpk, Address::p2wpkh(&cpk, NETWORK))
    };

    // Fund the test address.
    let txid = client.send(ONE_BTC, &address)?;
    client.balance.send(ONE_BTC);
    client.mine_a_block()?;
    client.assert_balance_is_as_expected()?;

    // Fetch the funded UTXO.
    let tx = client.get_transaction(&txid)?;
    let spk = address.script_pubkey();
    let utxos: Vec<_> =
        tx.output.iter().zip(0u32..).filter(|(out, _)| out.script_pubkey == spk).collect();
    assert_eq!(utxos.len(), 1);
    let (fund, vout) = utxos[0];
    let out_point = OutPoint { txid, vout };

    // Build the PSBT.
    let receiver = client.core_wallet_controlled_address()?;
    let spend_amount = Amount::from_sat(50_000_000);
    let change_amount = fund.value - spend_amount - FEE;

    let spend_output = TxOut { value: spend_amount, script_pubkey: receiver.script_pubkey() };
    let change_output = TxOut { value: change_amount, script_pubkey: address.script_pubkey() };

    let mut input = InputBuilder::new(&out_point).segwit_fund(fund.clone()).build();
    input.bip32_derivations.insert(cpk.into(), (fingerprint, path.clone()));
    input.sequence = Some(psbt::bitcoin::Sequence::MAX);

    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .output(OutputBuilder::new(spend_output).build())
        .output(OutputBuilder::new(change_output).build())
        .psbt()?;

    // Sign and finalize the PSBT.
    let (signed, _) = Signer::new(psbt)?.sign(&xpriv, &secp).unwrap();
    let finalized = Finalizer::new(signed)?.finalize(&secp)?;

    // Ask Bitcoin Core to decode the PSBT, proving it can parse the v0 envelope.
    let b64 = finalized.serialize_v0_base64_lossy()?;
    client.decode_psbt(&b64)?;

    // Broadcast the extracted transaction.
    let tx = Extractor::new(finalized)?.extract_tx_unchecked_fee_rate()?;
    client.send_raw_transaction(&tx)?;
    client.mine_a_block()?;
    client.balance.receive(spend_amount);
    client.assert_balance_is_as_expected()?;

    Ok(())
}
