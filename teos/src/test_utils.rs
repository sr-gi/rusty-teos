// Part of this file is an adaptation of test_utils from rust-lightning's lightning_block_sync crate.
// The original piece of software can be found at https://github.com/rust-bitcoin/rust-lightning/blob/main/lightning-block-sync/src/test_utils.rs

/* This file is licensed under either of
 *  Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0) or
 *  MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)
 * at your option.
*/

use rand::Rng;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use jsonrpc_http_server::jsonrpc_core::error::ErrorCode as JsonRpcErrorCode;
use jsonrpc_http_server::jsonrpc_core::{Error as JsonRpcError, IoHandler, Params, Value};
use jsonrpc_http_server::{CloseHandle, Server, ServerBuilder};

use bitcoincore_rpc::{Auth, Client as BitcoindClient};

use bitcoin::block::Block;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::script::{Builder, ScriptBuf};
use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
use bitcoin::hash_types::BlockHash;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::Hash;
use bitcoin::merkle_tree::calculate_root;
use bitcoin::pow::Work;
use bitcoin::Amount;
use bitcoin::Network;
use bitcoin::Witness;
use lightning_block_sync::poll::{
    ChainPoller, Poll, Validate, ValidatedBlock, ValidatedBlockHeader,
};
use lightning_block_sync::{
    AsyncBlockSourceResult, BlockData, BlockHeaderData, BlockSource, BlockSourceError,
    UnboundedCache,
};

use teos_common::constants::IRREVOCABLY_RESOLVED;
use teos_common::cryptography::{get_random_bytes, get_random_keypair};
use teos_common::test_utils::{generate_random_appointment, get_random_user_id, TXID_HEX, TX_HEX};
use teos_common::UserId;

use crate::api::internal::InternalAPI;
use crate::carrier::Carrier;
use crate::dbm::DBM;
use crate::extended_appointment::{ExtendedAppointment, UUID};
use crate::gatekeeper::{Gatekeeper, UserInfo};
use crate::protos as msgs;
use crate::responder::{ConfirmationStatus, Responder, TransactionTracker};
use crate::rpc_errors;
use crate::watcher::{Breach, Watcher};

pub(crate) const SLOTS: u32 = 21;
pub(crate) const DURATION: u32 = 500;
pub(crate) const EXPIRY_DELTA: u32 = 42;
pub(crate) const START_HEIGHT: usize = 100;

pub(crate) const AVAILABLE_SLOTS: u32 = 21;
pub(crate) const SUBSCRIPTION_START: u32 = START_HEIGHT as u32;
pub(crate) const SUBSCRIPTION_EXPIRY: u32 = SUBSCRIPTION_START + 42;

#[derive(Clone, Default, Debug)]
pub(crate) struct Blockchain {
    pub blocks: Vec<Block>,
    without_blocks: Option<std::ops::RangeFrom<usize>>,
    without_headers: bool,
    malformed_headers: bool,
    pub unreachable: Arc<Mutex<bool>>,
}

#[allow(dead_code)]
impl Blockchain {
    pub fn default() -> Self {
        Blockchain::with_network(Network::Bitcoin)
    }

    pub fn with_network(network: Network) -> Self {
        let blocks = vec![genesis_block(network)];
        Self {
            blocks,
            ..Default::default()
        }
    }

    pub fn with_height(mut self, height: usize) -> Self {
        self.blocks.reserve_exact(height);
        for _ in 1..=height {
            self.generate(None);
        }

        self
    }

    pub fn with_height_and_txs(mut self, height: usize, tx_count: u8) -> Self {
        for _ in 1..=height {
            self.generate(Some((0..tx_count).map(|_| get_random_tx()).collect()));
        }

        self
    }

    pub fn without_blocks(self, range: std::ops::RangeFrom<usize>) -> Self {
        Self {
            without_blocks: Some(range),
            ..self
        }
    }

    pub fn without_headers(self) -> Self {
        Self {
            without_headers: true,
            ..self
        }
    }

    pub fn malformed_headers(self) -> Self {
        Self {
            malformed_headers: true,
            ..self
        }
    }

    pub fn unreachable(self) -> Self {
        Self {
            unreachable: Arc::new(Mutex::new(true)),
            ..self
        }
    }

    pub fn fork_at_height(&self, height: usize) -> Self {
        assert!(height + 1 < self.blocks.len());
        let mut blocks = self.blocks.clone();
        let mut prev_blockhash = blocks[height].block_hash();
        for block in blocks.iter_mut().skip(height + 1) {
            block.header.prev_blockhash = prev_blockhash;
            block.header.nonce += 1;
            prev_blockhash = block.block_hash();
        }
        Self {
            blocks,
            without_blocks: None,
            unreachable: self.unreachable.clone(),
            ..*self
        }
    }

    pub fn at_height(&self, height: usize) -> ValidatedBlockHeader {
        let block_header = self.at_height_unvalidated(height);
        let block_hash = self.blocks[height].block_hash();
        block_header.validate(block_hash).unwrap()
    }

    fn at_height_unvalidated(&self, height: usize) -> BlockHeaderData {
        assert!(!self.blocks.is_empty());
        assert!(height < self.blocks.len());
        let height_bytes = height.to_be_bytes();
        let mut padded_bytes = [0u8; 32];
        padded_bytes[32 - height_bytes.len()..].copy_from_slice(&height_bytes);
        BlockHeaderData {
            chainwork: self.blocks[0].header.work() + Work::from_be_bytes(padded_bytes),
            height: height as u32,
            header: self.blocks[height].header,
        }
    }

    pub fn tip(&self) -> ValidatedBlockHeader {
        assert!(!self.blocks.is_empty());
        self.at_height(self.blocks.len() - 1)
    }

    pub fn disconnect_tip(&mut self) -> Option<Block> {
        self.blocks.pop()
    }

    pub fn header_cache(&self, heights: std::ops::RangeInclusive<usize>) -> UnboundedCache {
        let mut cache = UnboundedCache::new();
        for i in heights {
            let value = self.at_height(i);
            let key = value.header.block_hash();
            assert!(cache.insert(key, value).is_none());
        }
        cache
    }

    pub fn get_block_count(&self) -> u32 {
        (self.blocks.len() - 1) as u32
    }

    pub fn generate(&mut self, txs: Option<Vec<Transaction>>) -> Block {
        // FIXME: replace this magic number with something meaningul
        let bits = bitcoin::CompactTarget::from_consensus(553713663);

        let prev_block = self.blocks.last().unwrap();
        let prev_blockhash = prev_block.block_hash();
        let time = prev_block.header.time + (self.blocks.len() + 1) as u32;
        let txdata = match txs {
            Some(v) => {
                if v.is_empty() {
                    vec![get_random_tx()]
                } else {
                    v
                }
            }
            None => vec![get_random_tx()],
        };
        let hashes = txdata.iter().map(|obj| obj.compute_txid().to_raw_hash());
        let mut header = bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(0),
            prev_blockhash,
            merkle_root: calculate_root(hashes).unwrap().into(),
            time,
            bits,
            nonce: 0,
        };

        while header.validate_pow(header.target()).is_err() {
            header.nonce += 1;
        }

        let block = Block { header, txdata };
        self.blocks.push(block.clone());

        block
    }
}

impl BlockSource for Blockchain {
    fn get_header<'a>(
        &'a self,
        header_hash: &'a BlockHash,
        _height_hint: Option<u32>,
    ) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
        Box::pin(async move {
            if self.without_headers {
                return Err(BlockSourceError::persistent("header not found"));
            }

            for (height, block) in self.blocks.iter().enumerate() {
                if block.header.block_hash() == *header_hash {
                    let mut header_data = self.at_height_unvalidated(height);
                    if self.malformed_headers {
                        header_data.header.time += 1;
                    }

                    return Ok(header_data);
                }
            }
            Err(BlockSourceError::transient("header not found"))
        })
    }

    fn get_block<'a>(&'a self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<BlockData> {
        Box::pin(async move {
            for (height, block) in self.blocks.iter().enumerate() {
                if block.header.block_hash() == *header_hash {
                    if let Some(without_blocks) = &self.without_blocks {
                        if without_blocks.contains(&height) {
                            return Err(BlockSourceError::persistent("block not found"));
                        }
                    }
                    return Ok(BlockData::FullBlock(block.clone()));
                }
            }
            Err(BlockSourceError::transient("block not found"))
        })
    }

    fn get_best_block(&self) -> AsyncBlockSourceResult<(BlockHash, Option<u32>)> {
        Box::pin(async move {
            if *self.unreachable.lock().unwrap() {
                return Err(BlockSourceError::transient("Connection refused"));
            }
            match self.blocks.last() {
                None => Err(BlockSourceError::transient("empty chain")),
                Some(block) => {
                    let height = (self.blocks.len() - 1) as u32;
                    Ok((block.block_hash(), Some(height)))
                }
            }
        })
    }
}

pub(crate) fn generate_uuid() -> UUID {
    let mut rng = rand::thread_rng();

    UUID::from_slice(&rng.gen::<[u8; 20]>()).unwrap()
}

pub(crate) fn get_random_tx() -> Transaction {
    let mut rng = rand::thread_rng();
    let prev_txid_bytes = get_random_bytes(32);

    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::locktime::absolute::LockTime::from_height(0).unwrap(),
        input: vec![TxIn {
            previous_output: OutPoint::new(
                Txid::from_slice(&prev_txid_bytes).unwrap(),
                rng.gen_range(0..200),
            ),
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
            sequence: bitcoin::Sequence(0),
        }],
        output: vec![TxOut {
            script_pubkey: Builder::new().push_int(1).into_script(),
            value: Amount::from_sat(rng.gen_range(0..21_000_000_000)),
        }],
    }
}

pub(crate) fn generate_dummy_appointment(dispute_txid: Option<&Txid>) -> ExtendedAppointment {
    let appointment = generate_random_appointment(dispute_txid);
    let user_id = get_random_user_id();
    let user_signature = String::new();
    let start_block = 42;

    ExtendedAppointment::new(appointment, user_id, user_signature, start_block)
}

pub(crate) fn generate_dummy_appointment_with_user(
    user_id: UserId,
    dispute_txid: Option<&Txid>,
) -> (UUID, ExtendedAppointment) {
    let mut app = generate_dummy_appointment(dispute_txid);
    app.user_id = user_id;

    (app.uuid(), app)
}

pub(crate) fn get_random_breach() -> Breach {
    let dispute_tx = get_random_tx();
    let penalty_tx = get_random_tx();

    Breach::new(dispute_tx, penalty_tx)
}

pub(crate) fn get_random_tracker(
    user_id: UserId,
    status: ConfirmationStatus,
) -> TransactionTracker {
    let breach = get_random_breach();
    TransactionTracker::new(breach, user_id, status)
}

pub(crate) fn store_appointment_and_its_user(dbm: &DBM, appointment: &ExtendedAppointment) {
    dbm.store_user(
        appointment.user_id,
        &UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY),
    )
    // It's ok if the user is already stored.
    .ok();
    dbm.store_appointment(appointment.uuid(), appointment)
        .unwrap();
}

pub(crate) async fn get_last_n_blocks(chain: &mut Blockchain, n: usize) -> Vec<ValidatedBlock> {
    let mut last_n_blocks = Vec::with_capacity(n);
    let mut last_known_block = Ok(chain.tip());
    let poller = ChainPoller::new(chain, Network::Regtest);

    for _ in 0..n {
        let header = last_known_block.unwrap();
        let block = poller.fetch_block(&header).await.unwrap();
        last_n_blocks.push(block);
        last_known_block = poller.look_up_previous_header(&header).await;
    }

    last_n_blocks
}

pub(crate) enum MockedServerQuery {
    Regular,
    InMempoool,
    Error(i64),
}

pub(crate) fn create_carrier(query: MockedServerQuery, height: u32) -> (Carrier, BitcoindStopper) {
    let bitcoind_mock = match query {
        MockedServerQuery::Regular => BitcoindMock::new(MockOptions::default()),
        MockedServerQuery::InMempoool => BitcoindMock::new(MockOptions::in_mempool()),
        MockedServerQuery::Error(x) => BitcoindMock::new(MockOptions::with_error(x)),
    };
    let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
    let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
    start_server(bitcoind_mock.server);

    (
        Carrier::new(bitcoin_cli, bitcoind_reachable, height),
        bitcoind_mock.stopper,
    )
}

pub(crate) async fn create_responder(
    chain: &mut Blockchain,
    gatekeeper: Arc<Gatekeeper>,
    dbm: Arc<Mutex<DBM>>,
    server_url: &str,
) -> Responder {
    let height = chain.tip().height;
    // For the local TxIndex logic to be sound, our index needs to have, at least, IRREVOCABLY_RESOLVED blocks
    debug_assert!(height >= IRREVOCABLY_RESOLVED);

    let last_n_blocks = get_last_n_blocks(chain, IRREVOCABLY_RESOLVED as usize).await;

    let bitcoin_cli = Arc::new(BitcoindClient::new(server_url, Auth::None).unwrap());
    let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
    let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, height);

    Responder::new(last_n_blocks.as_slice(), height, carrier, gatekeeper, dbm)
}

pub(crate) async fn create_watcher(
    chain: &mut Blockchain,
    responder: Arc<Responder>,
    gatekeeper: Arc<Gatekeeper>,
    bitcoind_mock: BitcoindMock,
    dbm: Arc<Mutex<DBM>>,
) -> (Watcher, BitcoindStopper) {
    let last_n_blocks = get_last_n_blocks(chain, 6).await;

    start_server(bitcoind_mock.server);
    let (tower_sk, tower_pk) = get_random_keypair();
    let tower_id = UserId(tower_pk);
    (
        Watcher::new(
            gatekeeper,
            responder,
            last_n_blocks.as_slice(),
            chain.get_block_count(),
            tower_sk,
            tower_id,
            dbm,
        ),
        bitcoind_mock.stopper,
    )
}
#[derive(Clone)]
pub(crate) struct ApiConfig {
    slots: u32,
    duration: u32,
    bitcoind_reachable: bool,
}

impl ApiConfig {
    pub fn new(slots: u32, duration: u32) -> Self {
        Self {
            slots,
            duration,
            bitcoind_reachable: true,
        }
    }

    pub fn bitcoind_unreachable(&mut self) -> Self {
        self.bitcoind_reachable = false;
        self.clone()
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            slots: SLOTS,
            duration: DURATION,
            bitcoind_reachable: true,
        }
    }
}

pub(crate) async fn create_api_with_config(
    api_config: ApiConfig,
) -> (Arc<InternalAPI>, BitcoindStopper) {
    let bitcoind_mock = BitcoindMock::new(MockOptions::default());
    let mut chain = Blockchain::default().with_height(START_HEIGHT);

    let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
    let gk = Arc::new(Gatekeeper::new(
        chain.get_block_count(),
        api_config.slots,
        api_config.duration,
        EXPIRY_DELTA,
        dbm.clone(),
    ));
    let responder =
        create_responder(&mut chain, gk.clone(), dbm.clone(), bitcoind_mock.url()).await;
    let (watcher, stopper) = create_watcher(
        &mut chain,
        Arc::new(responder),
        gk.clone(),
        bitcoind_mock,
        dbm.clone(),
    )
    .await;

    let bitcoind_reachable = Arc::new((Mutex::new(api_config.bitcoind_reachable), Condvar::new()));
    let (shutdown_trigger, _) = triggered::trigger();
    (
        Arc::new(InternalAPI::new(
            Arc::new(watcher),
            vec![msgs::NetworkAddress::from_ipv4("address".to_string(), 21)],
            bitcoind_reachable,
            shutdown_trigger,
        )),
        stopper,
    )
}

pub(crate) async fn create_api() -> (Arc<InternalAPI>, BitcoindStopper) {
    create_api_with_config(ApiConfig::default()).await
}

#[derive(Clone)]
pub struct BitcoindStopper {
    close_handle: CloseHandle,
}

impl BitcoindStopper {
    pub fn new(close_handle: CloseHandle) -> Self {
        Self { close_handle }
    }

    pub fn close_handle(&self) -> CloseHandle {
        self.close_handle.clone()
    }
}

impl Drop for BitcoindStopper {
    fn drop(&mut self) {
        self.close_handle().close()
    }
}

pub(crate) struct BitcoindMock {
    pub url: String,
    pub server: Server,
    stopper: BitcoindStopper,
}

#[derive(Default)]
pub(crate) struct MockOptions {
    error_code: Option<i64>,
    in_mempool: bool,
}

impl MockOptions {
    pub fn with_error(error_code: i64) -> Self {
        Self {
            error_code: Some(error_code),
            in_mempool: false,
        }
    }

    pub fn in_mempool() -> Self {
        Self {
            error_code: None,
            in_mempool: true,
        }
    }
}

impl BitcoindMock {
    pub fn new(options: MockOptions) -> Self {
        let mut io = IoHandler::default();

        if let Some(error) = options.error_code {
            io.add_sync_method("error", move |_params: Params| {
                Err(JsonRpcError::new(JsonRpcErrorCode::ServerError(error)))
            });
            io.add_alias("sendrawtransaction", "error");
            io.add_alias("getrawtransaction", "error");
        } else {
            BitcoindMock::add_sendrawtransaction(&mut io);
            BitcoindMock::add_getrawtransaction(&mut io, options.in_mempool);
        }

        let server = ServerBuilder::new(io)
            .threads(3)
            .start_http(&"127.0.0.1:0".parse().unwrap())
            .unwrap();

        Self {
            url: format!("http://{}", server.address()),
            stopper: BitcoindStopper::new(server.close_handle()),
            server,
        }
    }

    fn add_sendrawtransaction(io: &mut IoHandler) {
        io.add_method("sendrawtransaction", |_params: Params| async {
            Ok(Value::String(TXID_HEX.to_owned()))
        });
    }

    fn add_getrawtransaction(io: &mut IoHandler, in_mempool: bool) {
        io.add_sync_method("getrawtransaction", move |_params: Params|  {
            if !in_mempool {
                Err(JsonRpcError::new(JsonRpcErrorCode::ServerError(rpc_errors::RPC_INVALID_ADDRESS_OR_KEY as i64)))
            } else {
                match _params {
                    Params::Array(x) => match x[1] {
                        Value::Bool(x) => {
                            if x {
                                Ok(serde_json::json!({"hex": TX_HEX, "txid": TXID_HEX, "hash": TXID_HEX, "size": 0, 
                                "vsize": 0, "version": 1, "locktime": 0, "vin": [], "vout": [] }))
                            } else {
                                Ok(Value::String(TX_HEX.to_owned()))
                            }
                        }
                        _ => panic!("Boolean param not found"),
                    },
                    _ => panic!("No params found"),
                }
            }
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

pub(crate) fn start_server(server: Server) {
    thread::spawn(move || {
        server.wait();
    });
}
