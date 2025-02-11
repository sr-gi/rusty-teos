//! Logic related to the Carrier, the component in charge or sending/requesting transaction data from/to `bitcoind`.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};

use crate::responder::ConfirmationStatus;
use crate::{errors, rpc_errors};

use bitcoin::{Transaction, Txid};
use bitcoincore_rpc::{
    jsonrpc::error::Error::Rpc as RpcError, jsonrpc::error::Error::Transport as TransportError,
    Client as BitcoindClient, Error::JsonRpc as JsonRpcError, RpcApi,
};

/// Component in charge of the interaction with Bitcoind by sending / querying transactions via RPC.
#[derive(Debug)]
pub struct Carrier {
    /// The underlying bitcoin client used by the [Carrier].
    bitcoin_cli: Arc<BitcoindClient>,
    /// A flag that indicates wether bitcoind is reachable or not.
    bitcoind_reachable: Arc<(Mutex<bool>, Condvar)>,
    /// A map of receipts already issued by the [Carrier].
    /// Used to prevent potentially re-sending the same transaction over and over.
    issued_receipts: HashMap<Txid, ConfirmationStatus>,
    /// The last known block height.
    block_height: u32,
}

impl Carrier {
    /// Creates a new [Carrier] instance.
    pub fn new(
        bitcoin_cli: Arc<BitcoindClient>,
        bitcoind_reachable: Arc<(Mutex<bool>, Condvar)>,
        last_known_block_height: u32,
    ) -> Self {
        Carrier {
            bitcoin_cli,
            bitcoind_reachable,
            issued_receipts: HashMap::new(),
            block_height: last_known_block_height,
        }
    }

    /// The last known block height.
    pub(crate) fn block_height(&self) -> u32 {
        self.block_height
    }

    /// Clears the receipts cached by the [Carrier]. Should be called periodically to prevent it from
    /// growing unbounded.
    pub(crate) fn clear_receipts(&mut self) {
        if !self.issued_receipts.is_empty() {
            self.issued_receipts = HashMap::new()
        }
    }

    /// Updates the last known block height by the [Carrier].
    pub(crate) fn update_height(&mut self, height: u32) {
        self.block_height = height
    }

    /// Hangs the process until bitcoind is reachable. If bitcoind is already reachable it just passes trough.
    fn hang_until_bitcoind_reachable(&self) {
        let (lock, notifier) = &*self.bitcoind_reachable;
        let mut reachable = lock.lock().unwrap();
        while !*reachable {
            reachable = notifier.wait(reachable).unwrap();
        }
    }

    /// Flags bitcoind as unreachable.
    fn flag_bitcoind_unreachable(&self) {
        let (lock, _) = &*self.bitcoind_reachable;
        *lock.lock().unwrap() = false;
    }

    /// Sends a [Transaction] to the Bitcoin network.
    ///
    /// Returns a [ConfirmationStatus] indicating whether the transaction was accepted by the node or not.
    pub(crate) fn send_transaction(&mut self, tx: &Transaction) -> ConfirmationStatus {
        self.hang_until_bitcoind_reachable();

        if let Some(receipt) = self.issued_receipts.get(&tx.compute_txid()) {
            log::info!("Transaction already sent: {}", tx.compute_txid());
            return *receipt;
        }

        log::info!("Pushing transaction to the network: {}", tx.compute_txid());
        let receipt = match self.bitcoin_cli.send_raw_transaction(tx) {
            Ok(_) => {
                // Here the transaction could, potentially, have been in mempool before the current height.
                // This shouldn't really matter though.
                log::info!("Transaction successfully delivered: {}", tx.compute_txid());
                ConfirmationStatus::InMempoolSince(self.block_height)
            }
            Err(JsonRpcError(RpcError(rpcerr))) => match rpcerr.code {
                // Since we're pushing a raw transaction to the network we can face several rejections
                rpc_errors::RPC_VERIFY_REJECTED => {
                    log::error!("Transaction couldn't be broadcast. {rpcerr:?}");
                    ConfirmationStatus::Rejected(rpc_errors::RPC_VERIFY_REJECTED)
                }
                rpc_errors::RPC_VERIFY_ERROR => {
                    log::error!("Transaction couldn't be broadcast. {rpcerr:?}");
                    ConfirmationStatus::Rejected(rpc_errors::RPC_VERIFY_ERROR)
                }
                rpc_errors::RPC_VERIFY_ALREADY_IN_CHAIN => {
                    log::info!(
                        "Transaction was confirmed long ago, not keeping track of it: {}",
                        tx.compute_txid()
                    );

                    // Given we are not using txindex, if a transaction bounces we cannot get its confirmation count. However, [send_transaction] is guarded by
                    // checking whether the transaction id can be found in the [Responder]'s [TxIndex], meaning that if the transaction bounces it was confirmed long
                    // ago (> IRREVOCABLY_RESOLVED), so we don't need to worry about it.
                    ConfirmationStatus::IrrevocablyResolved
                }
                rpc_errors::RPC_DESERIALIZATION_ERROR => {
                    // Adding this here just for completeness. We should never end up here. The Carrier only sends txs handed by the Responder,
                    // who receives them from the Watcher, who checks that the tx can be properly deserialized.
                    log::info!("Transaction cannot be deserialized: {}", tx.compute_txid());
                    ConfirmationStatus::Rejected(rpc_errors::RPC_DESERIALIZATION_ERROR)
                }
                _ => {
                    // If something else happens (unlikely but possible) log it so we can treat it in future releases.
                    log::error!("Unexpected rpc error when calling sendrawtransaction: {rpcerr:?}");
                    ConfirmationStatus::Rejected(errors::UNKNOWN_JSON_RPC_EXCEPTION)
                }
            },
            Err(JsonRpcError(TransportError(_))) => {
                // Connection refused, bitcoind is down.
                log::error!("Connection lost with bitcoind, retrying request when possible");
                self.flag_bitcoind_unreachable();
                self.send_transaction(tx)
            }
            Err(e) => {
                // TODO: This may need finer catching.
                log::error!("Unexpected error when calling sendrawtransaction: {e:?}");
                ConfirmationStatus::Rejected(errors::UNKNOWN_JSON_RPC_EXCEPTION)
            }
        };

        self.issued_receipts.insert(tx.compute_txid(), receipt);

        receipt
    }

    /// Checks whether a given transaction can be found in the mempool.
    ///
    /// This uses `getrawtransaction` under the hood and, therefore, its behavior depends on whether `txindex` is enabled in bitcoind.
    /// If `txindex` is disabled (default), it will only pull data from the mempool. Otherwise, it will also pull data from the transaction
    /// index. Hence, we need to check whether the returned struct has any of the block related datum set (such as `blockhash`).
    pub(crate) fn in_mempool(&self, txid: &Txid) -> bool {
        self.hang_until_bitcoind_reachable();

        match self.bitcoin_cli.get_raw_transaction_info(txid, None) {
            Ok(tx) => tx.blockhash.is_none(),
            Err(JsonRpcError(RpcError(rpcerr))) => match rpcerr.code {
                rpc_errors::RPC_INVALID_ADDRESS_OR_KEY => {
                    log::info!("Transaction not found in mempool: {txid}");
                    false
                }
                e => {
                    // DISCUSS: This could result in a silent error with unknown consequences
                    log::error!("Unexpected error code when calling getrawtransaction: {e}");
                    false
                }
            },
            Err(JsonRpcError(TransportError(_))) => {
                // Connection refused, bitcoind is down.
                log::error!("Connection lost with bitcoind, retrying request when possible");
                self.flag_bitcoind_unreachable();
                self.in_mempool(txid)
            }
            // TODO: This may need finer catching.
            Err(e) => {
                // DISCUSS: This could result in a silent error with unknown consequences
                log::error!("Unexpected JSONRPCError when calling getrawtransaction: {e}");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    use crate::test_utils::{get_random_tx, start_server, BitcoindMock, MockOptions, START_HEIGHT};
    use teos_common::test_utils::{TXID_HEX, TX_HEX};

    use bitcoin::consensus;
    use bitcoin::hashes::hex::FromHex;
    use bitcoincore_rpc::Auth;

    impl Carrier {
        // Helper function to access issued_receipts in tests
        pub(crate) fn get_issued_receipts(&mut self) -> &mut HashMap<Txid, ConfirmationStatus> {
            &mut self.issued_receipts
        }

        // Helper function to access height in tests
        pub(crate) fn get_height(&self) -> u32 {
            self.block_height
        }
    }

    #[test]
    fn test_clear_receipts() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::default());
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        let start_height = START_HEIGHT as u32;

        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);

        // Lets add some dummy data into the cache
        for i in 0..10 {
            carrier.issued_receipts.insert(
                get_random_tx().compute_txid(),
                ConfirmationStatus::ConfirmedIn(start_height - i),
            );
        }

        // Check it empties on request
        assert!(!carrier.issued_receipts.is_empty());
        carrier.clear_receipts();
        assert!(carrier.issued_receipts.is_empty());
    }

    #[test]
    fn test_send_transaction_ok() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::default());
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock.server);

        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let tx = consensus::deserialize(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx);

        assert_eq!(r, ConfirmationStatus::InMempoolSince(start_height));

        // Check the receipt is on the cache
        assert_eq!(carrier.issued_receipts.get(&tx.compute_txid()).unwrap(), &r);
    }

    #[test]
    fn test_send_transaction_ok_already_in_mempool() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::in_mempool());
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock.server);

        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let tx = consensus::deserialize(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx);

        assert_eq!(r, ConfirmationStatus::InMempoolSince(start_height));

        // Check the receipt is on the cache
        assert_eq!(carrier.issued_receipts.get(&tx.compute_txid()).unwrap(), &r);
    }

    #[test]
    fn test_send_transaction_verify_rejected() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::with_error(
            rpc_errors::RPC_VERIFY_REJECTED as i64,
        ));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock.server);

        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let tx = consensus::deserialize(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx);

        assert_eq!(
            r,
            ConfirmationStatus::Rejected(rpc_errors::RPC_VERIFY_REJECTED)
        );

        // Check the receipt is on the cache
        assert_eq!(carrier.issued_receipts.get(&tx.compute_txid()).unwrap(), &r);
    }

    #[test]
    fn test_send_transaction_verify_error() {
        let bitcoind_mock =
            BitcoindMock::new(MockOptions::with_error(rpc_errors::RPC_VERIFY_ERROR as i64));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock.server);

        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let tx = consensus::deserialize(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx);

        assert_eq!(
            r,
            ConfirmationStatus::Rejected(rpc_errors::RPC_VERIFY_ERROR)
        );

        // Check the receipt is on the cache
        assert_eq!(carrier.issued_receipts.get(&tx.compute_txid()).unwrap(), &r);
    }

    #[test]
    fn test_send_transaction_verify_already_in_chain() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::with_error(
            rpc_errors::RPC_VERIFY_ALREADY_IN_CHAIN as i64,
        ));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock.server);

        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let tx = consensus::deserialize(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx);

        assert_eq!(r, ConfirmationStatus::IrrevocablyResolved);

        // Check the receipt is on the cache
        assert_eq!(carrier.issued_receipts.get(&tx.compute_txid()).unwrap(), &r);
    }

    #[test]
    fn test_send_transaction_unexpected_error() {
        let bitcoind_mock =
            BitcoindMock::new(MockOptions::with_error(rpc_errors::RPC_MISC_ERROR as i64));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock.server);

        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let tx = consensus::deserialize(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx);

        assert_eq!(
            r,
            ConfirmationStatus::Rejected(errors::UNKNOWN_JSON_RPC_EXCEPTION)
        );

        // Check the receipt is on the cache
        assert_eq!(carrier.issued_receipts.get(&tx.compute_txid()).unwrap(), &r);
    }

    #[test]
    fn test_send_transaction_connection_error() {
        // Try to connect to an offline bitcoind.
        let bitcoind_mock = BitcoindMock::new(MockOptions::default());
        let bitcoind_reachable = Arc::new((Mutex::new(false), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        let start_height = START_HEIGHT as u32;
        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable.clone(), start_height);

        let tx = consensus::deserialize(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let delay = std::time::Duration::new(3, 0);

        thread::spawn(move || {
            thread::sleep(delay);
            let (reachable, notifier) = &*bitcoind_reachable;
            *reachable.lock().unwrap() = true;
            notifier.notify_all();
        });

        let before = std::time::Instant::now();
        carrier.send_transaction(&tx);

        // Check the request has hanged for ~delay
        assert_eq!(
            (std::time::Instant::now() - before).as_secs(),
            delay.as_secs()
        );
    }

    #[test]
    fn test_in_mempool() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::in_mempool());
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock.server);

        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let vec = Vec::from_hex(TXID_HEX).unwrap();
        let hash: bitcoin::hashes::sha256d::Hash = bitcoin::hashes::Hash::from_slice(&vec).unwrap();
        let txid = Txid::from(hash);
        assert!(carrier.in_mempool(&txid));
    }

    #[test]
    fn test_not_in_mempool() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::default());
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock.server);

        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let vec = Vec::from_hex(TXID_HEX).unwrap();
        let hash: bitcoin::hashes::sha256d::Hash = bitcoin::hashes::Hash::from_slice(&vec).unwrap();
        let txid = Txid::from(hash);
        assert!(!carrier.in_mempool(&txid));
    }

    #[test]
    fn test_not_in_mempool_via_error() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::with_error(
            rpc_errors::RPC_INVALID_ADDRESS_OR_KEY as i64,
        ));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock.server);

        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let vec = Vec::from_hex(TXID_HEX).unwrap();
        let hash: bitcoin::hashes::sha256d::Hash = bitcoin::hashes::Hash::from_slice(&vec).unwrap();
        let txid = Txid::from(hash);
        assert!(!carrier.in_mempool(&txid));
    }

    #[test]
    fn test_in_mempool_unexpected_error() {
        let bitcoind_mock =
            BitcoindMock::new(MockOptions::with_error(rpc_errors::RPC_MISC_ERROR as i64));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock.server);

        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let vec = Vec::from_hex(TXID_HEX).unwrap();
        let hash: bitcoin::hashes::sha256d::Hash = bitcoin::hashes::Hash::from_slice(&vec).unwrap();
        let txid = Txid::from(hash);
        assert!(!carrier.in_mempool(&txid));
    }

    #[test]
    fn test_in_mempool_connection_error() {
        // Try to connect to an offline bitcoind.
        let bitcoind_mock = BitcoindMock::new(MockOptions::default());
        let bitcoind_reachable = Arc::new((Mutex::new(false), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        let start_height = START_HEIGHT as u32;
        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable.clone(), start_height);

        let vec = Vec::from_hex(TXID_HEX).unwrap();
        let hash: bitcoin::hashes::sha256d::Hash = bitcoin::hashes::Hash::from_slice(&vec).unwrap();
        let txid = Txid::from(hash);
        let delay = std::time::Duration::new(3, 0);

        thread::spawn(move || {
            thread::sleep(delay);
            let (reachable, notifier) = &*bitcoind_reachable;
            *reachable.lock().unwrap() = true;
            notifier.notify_all();
        });

        let before = std::time::Instant::now();
        carrier.in_mempool(&txid);

        // Check the request has hanged for ~delay
        assert_eq!(
            (std::time::Instant::now() - before).as_secs(),
            delay.as_secs()
        );
    }
}
