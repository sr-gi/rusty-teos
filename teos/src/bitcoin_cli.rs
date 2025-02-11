//! Logic related to the BitcoindClient, an simple bitcoind client implementation.

// This is an adaptation of a bitcoind client with the minimal functionality required by the tower
// The original piece of software can be found at https://github.com/lightningdevkit/ldk-sample/blob/main/src/bitcoind_client.rs

/* This file is licensed under either of
 *  Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0) or
 *  MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)
 * at your option.
*/

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use std::convert::TryInto;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use tokio::sync::Mutex;

use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::Transaction;
use bitcoincore_rpc::{Auth, RawTx};
use lightning::util::ser::Writeable;
use lightning_block_sync::http::{HttpEndpoint, JsonResponse};
use lightning_block_sync::rpc::RpcClient;
use lightning_block_sync::{AsyncBlockSourceResult, BlockData, BlockHeaderData, BlockSource};

/// A simple implementation of a bitcoind client (`bitcoin-cli`) with the minimal functionality required by the tower.
pub struct BitcoindClient<'a> {
    /// The underlying RPC client.
    bitcoind_rpc_client: Arc<Mutex<RpcClient>>,
    /// The hostname to connect to.
    host: &'a str,
    /// The port to connect to.
    port: u16,
    /// The RPC user `bitcoind` is configured with.
    rpc_user: String,
    /// The RPC password for the given user.
    rpc_password: String,
}

impl BlockSource for &BitcoindClient<'_> {
    /// Gets a block header given its hash.
    fn get_header<'a>(
        &'a self,
        header_hash: &'a BlockHash,
        height_hint: Option<u32>,
    ) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
        Box::pin(async move {
            let rpc = self.bitcoind_rpc_client.lock().await;
            rpc.get_header(header_hash, height_hint).await
        })
    }

    /// Gets a block given its hash.
    fn get_block<'a>(
        &'a self,
        header_hash: &'a BlockHash,
    ) -> AsyncBlockSourceResult<'a, BlockData> {
        Box::pin(async move {
            let rpc = self.bitcoind_rpc_client.lock().await;
            rpc.get_block(header_hash).await
        })
    }

    /// Get the best block known by our node.
    fn get_best_block(&self) -> AsyncBlockSourceResult<(BlockHash, Option<u32>)> {
        Box::pin(async move {
            let rpc = self.bitcoind_rpc_client.lock().await;
            rpc.get_best_block().await
        })
    }
}

// TODO: This is not being used atm since we're using bitcoincore-rpc.
// Not deleting it since wd should need it once both get merged.
impl<'a> BitcoindClient<'a> {
    /// Creates a new [BitcoindClient] instance.
    pub async fn new(
        host: &'a str,
        port: u16,
        auth: Auth,
        teos_network: &'a str,
    ) -> std::io::Result<BitcoindClient<'a>> {
        let http_endpoint = HttpEndpoint::for_host(host.to_owned()).with_port(port);
        let (rpc_user, rpc_password) = {
            let (user, pass) = auth.get_user_pass().map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Cannot read cookie file. {}", e),
                )
            })?;
            if user.is_none() {
                Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Empty btc_rpc_user parsed from rpc_cookie".to_string(),
                ))
            } else if pass.is_none() {
                Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Empty btc_rpc_password parsed from rpc_cookie",
                ))
            } else {
                Ok((user.unwrap(), pass.unwrap()))
            }
        }?;

        let rpc_credentials = URL_SAFE.encode(format!("{}:{}", rpc_user, rpc_password));
        let bitcoind_rpc_client = RpcClient::new(&rpc_credentials, http_endpoint);

        let client = Self {
            bitcoind_rpc_client: Arc::new(Mutex::new(bitcoind_rpc_client)),
            host,
            port,
            rpc_user,
            rpc_password,
        };

        // Test that bitcoind is reachable.
        let btc_network = client.get_chain().await?;

        // Assert teos runs on the same chain/network as bitcoind.
        if btc_network != teos_network {
            Err(Error::new(
                ErrorKind::InvalidInput,
                format!("bitcoind is running on {btc_network} but teosd is set to run on {teos_network}"),
            ))
        } else {
            Ok(client)
        }
    }

    /// Gets a fresh RPC client.
    pub fn get_new_rpc_client(&self) -> std::io::Result<RpcClient> {
        let http_endpoint = HttpEndpoint::for_host(self.host.to_owned()).with_port(self.port);
        let rpc_credentials = URL_SAFE.encode(format!("{}:{}", self.rpc_user, self.rpc_password));
        Ok(RpcClient::new(&rpc_credentials, http_endpoint))
    }

    /// Gets the hash of the chain tip and its height.
    pub async fn get_best_block_hash_and_height(
        &self,
    ) -> Result<(BlockHash, Option<u32>), std::io::Error> {
        let rpc = self.bitcoind_rpc_client.lock().await;
        rpc.call_method::<(BlockHash, Option<u32>)>("getblockchaininfo", &[])
            .await
    }

    /// Sends a transaction to the network.
    pub async fn send_raw_transaction(&self, raw_tx: &Transaction) -> Result<Txid, std::io::Error> {
        let rpc = self.bitcoind_rpc_client.lock().await;

        let raw_tx_json = serde_json::json!(raw_tx.encode().raw_hex());
        rpc.call_method::<Txid>("sendrawtransaction", &[raw_tx_json])
            .await
    }

    /// Gets a transaction given its id.
    pub async fn get_raw_transaction(&self, txid: &Txid) -> Result<Transaction, std::io::Error> {
        let rpc = self.bitcoind_rpc_client.lock().await;

        let txid_hex = serde_json::json!(txid.encode().raw_hex());
        rpc.call_method::<Transaction>("getrawtransaction", &[txid_hex])
            .await
    }

    /// Gets bitcoind's network.
    pub async fn get_chain(&self) -> std::io::Result<String> {
        // A wrapper type to extract "chain" key from getblockchaininfo JsonResponse.
        struct BtcNetwork(String);
        impl TryInto<BtcNetwork> for JsonResponse {
            type Error = std::io::Error;
            fn try_into(self) -> std::io::Result<BtcNetwork> {
                Ok(BtcNetwork(self.0["chain"].as_str().unwrap().to_string()))
            }
        }

        // Ask the RPC client for the network bitcoind is running on.
        let rpc = self.bitcoind_rpc_client.lock().await;
        let btc_network = rpc
            .call_method::<BtcNetwork>("getblockchaininfo", &[])
            .await?;

        Ok(btc_network.0)
    }
}
