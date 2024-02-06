use bitcoind::bitcoincore_rpc::bitcoincore_rpc_json::{AddressType, GetBlockchainInfoResult};
use bitcoind::bitcoincore_rpc::RpcApi;
use bitcoind::BitcoinD;
use psbt_v2::bitcoin::{Address, Amount, Network, Txid};

const NETWORK: Network = Network::Regtest;

/// A custom bitcoind client.
pub struct Client {
    bitcoind: BitcoinD,
}

impl Client {
    /// Creates a new [`Client`].
    pub fn new() -> anyhow::Result<Self> {
        let bitcoind = BitcoinD::from_downloaded()?;
        let client = Client { bitcoind };

        Ok(client)
    }

    /// Calls through to bitcoincore_rpc client.
    pub fn get_blockchain_info(&self) -> anyhow::Result<GetBlockchainInfoResult> {
        let client = &self.bitcoind.client;
        Ok(client.get_blockchain_info()?)
    }

    /// Gets an address controlled by the currently loaded Bitcoin Core wallet (via `bitcoind`).
    pub fn core_wallet_controlled_address(&self) -> anyhow::Result<Address> {
        let client = &self.bitcoind.client;
        let label = None;
        let address_type = Some(AddressType::Bech32m);
        let address = client.get_new_address(label, address_type)?.require_network(NETWORK)?;
        Ok(address)
    }

    /// Funds the bitcoind wallet with a spendable 50 BTC utxo.
    pub fn fund(&self) -> anyhow::Result<()> {
        let client = &self.bitcoind.client;
        // Generate to an address controlled by the bitcoind wallet and wait for funds to mature.
        let address = self.core_wallet_controlled_address()?;
        let _ = client.generate_to_address(101, &address)?;

        Ok(())
    }

    /// Send `amount` to `address` setting all other `bitcoincore_prc::send_to_address` args to `None`.
    pub fn send(&self, amount: Amount, address: &Address) -> anyhow::Result<Txid> {
        let client = &self.bitcoind.client;

        let comment = None;
        let comment_to = None;
        let subtract_fee = None;
        let replacable = None;
        let confirmation_target = None;
        let estimate_mode = None;

        let txid = client.send_to_address(
            address,
            amount,
            comment,
            comment_to,
            subtract_fee,
            replacable,
            confirmation_target,
            estimate_mode,
        )?;
        Ok(txid)
    }
}
