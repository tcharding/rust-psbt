//! Test the bitcoind infrastructure.

// Depend directly on `bitcoin` (and `bitcoind_tests`) because we are explicitly
// testing the `bitcoind_tests` crate.
use bitcoin::Amount;
use bitcoind_tests::client::Client;

#[test]
fn bitcoind_get_core_wallet_controlled_address() {
    let client = Client::new().expect("failed to create client");
    let address = client.core_wallet_controlled_address().expect("get_new_address failed");
    println!("address: {}", address);
}

#[test]
fn bitcoind_send() {
    let mut client = Client::new().expect("failed to create client");
    assert_eq!(client.tracked_balance(), Amount::ZERO);

    // Mine a block to release initial funds (coinbase reward).
    client.mine_a_block().expect("initial mine_a_block failed");
    // Sanity check, we should have 50 BTC.
    assert_eq!(client.tracked_balance(), Amount::from_btc(50.0).unwrap());
    client.assert_balance_is_as_expected().expect("incorrect balance");

    let address = client.core_wallet_controlled_address().expect("get_new_address failed");
    let amount = Amount::ONE_BTC;

    let txid = client.send(amount, &address).expect("send failed");
    client.balance.send_to_self();

    client.mine_a_block().expect("mine_a_block failed");

    client.assert_balance_is_as_expected().expect("incorrect balance");
    println!("txid: {}", txid);
}
