//! Logic related to the ChainMonitor, the component in charge of querying block data from `bitcoind`.
//!

use std::ops::Deref;
use std::sync::{Arc, Condvar, Mutex};
use std::time;
use tokio::time::timeout;
use triggered::Listener;

use lightning::chain;
use lightning_block_sync::poll::{ChainTip, Poll, ValidatedBlockHeader};
use lightning_block_sync::{BlockSourceErrorKind, Cache, SpvClient};

use crate::dbm::DBM;

/// Component in charge of monitoring the chain for new blocks.
///
/// Takes care of polling `bitcoind` for new tips and hand it to subscribers.
/// It is mainly a wrapper around [chain::Listen] that provides some logging.
pub struct ChainMonitor<'a, P, C, L>
where
    P: Poll,
    C: Cache,
    L: Deref,
    L::Target: chain::Listen,
{
    /// A bitcoin client to poll best tips from.
    spv_client: SpvClient<'a, P, C, L>,
    /// The last known block header by the [ChainMonitor].
    last_known_block_header: ValidatedBlockHeader,
    /// A [DBM] (database manager) instance. Used to persist block data into disk.
    dbm: Arc<Mutex<DBM>>,
    /// The time between polls.
    polling_delta: time::Duration,
    /// A signal from the main thread indicating the tower is shuting down.
    shutdown_signal: Listener,
    /// A flag that indicates wether bitcoind is reachable or not.
    bitcoind_reachable: Arc<(Mutex<bool>, Condvar)>,
}

impl<'a, P, C, L> ChainMonitor<'a, P, C, L>
where
    P: Poll,
    C: Cache,
    L: Deref,
    L::Target: chain::Listen,
{
    /// Creates a new [ChainMonitor] instance.
    pub async fn new(
        spv_client: SpvClient<'a, P, C, L>,
        last_known_block_header: ValidatedBlockHeader,
        dbm: Arc<Mutex<DBM>>,
        polling_delta_sec: u16,
        shutdown_signal: Listener,
        bitcoind_reachable: Arc<(Mutex<bool>, Condvar)>,
    ) -> ChainMonitor<'a, P, C, L> {
        ChainMonitor {
            spv_client,
            last_known_block_header,
            dbm,
            polling_delta: time::Duration::from_secs(polling_delta_sec as u64),
            shutdown_signal,
            bitcoind_reachable,
        }
    }

    /// Polls the best chain tip from bitcoind. Serves the data to its listeners (through [chain::Listen]) and logs data about the polled tips.
    pub async fn poll_best_tip(&mut self) {
        let (reachable, notifier) = &*self.bitcoind_reachable;
        match self.spv_client.poll_best_tip().await {
            Ok((chain_tip, _)) => {
                match chain_tip {
                    ChainTip::Common => log::debug!("No new best tip found"),

                    ChainTip::Better(new_best) => {
                        log::debug!("Updating best tip: {}", new_best.header.block_hash());
                        self.last_known_block_header = new_best;
                        self.dbm
                            .lock()
                            .unwrap()
                            .store_last_known_block(&new_best.header.block_hash())
                            .unwrap();
                    }
                    ChainTip::Worse(worse) => {
                        // This would happen both if a block has less chainwork than the previous one, or if it has the same chainwork
                        // but it forks from the parent. In both cases, it'll be detected as a reorg once (if) the new chain grows past
                        // the current tip.
                        log::warn!("Worse tip found: {:?}", worse.header.block_hash());

                        if worse.chainwork == self.last_known_block_header.chainwork {
                            log::warn!("New tip has the same work as the previous one")
                        } else {
                            log::warn!("New tip has less work than the previous one")
                        }
                    }
                }
                *reachable.lock().unwrap() = true;
                notifier.notify_all();
            }
            Err(e) => match e.kind() {
                BlockSourceErrorKind::Persistent => {
                    // FIXME: This may need finer catching
                    log::error!("Unexpected persistent error: {e:?}");
                }
                BlockSourceErrorKind::Transient => {
                    // Treating all transient as connection errors at least for now.
                    log::error!("Connection lost with bitcoind");
                    *reachable.lock().unwrap() = false;
                }
            },
        };
    }

    /// Monitors `bitcoind` polling the best chain tip every [polling_delta](Self::polling_delta).
    pub async fn monitor_chain(&mut self) {
        loop {
            self.poll_best_tip().await;
            // Sleep for self.polling_delta seconds or shutdown if the signal is received.
            if timeout(self.polling_delta, self.shutdown_signal.clone())
                .await
                .is_ok()
            {
                log::debug!("Received shutting down signal. Shutting down");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::iter::FromIterator;
    use std::thread;

    use bitcoin::BlockHash;
    use bitcoin::Network;
    use lightning_block_sync::{poll::ChainPoller, SpvClient, UnboundedCache};

    use crate::test_utils::{Blockchain, START_HEIGHT};

    pub(crate) struct DummyListener {
        pub connected_blocks: RefCell<HashSet<BlockHash>>,
        pub disconnected_blocks: RefCell<HashSet<BlockHash>>,
    }

    impl DummyListener {
        fn new() -> Self {
            Self {
                connected_blocks: RefCell::new(HashSet::new()),
                disconnected_blocks: RefCell::new(HashSet::new()),
            }
        }
    }

    impl chain::Listen for DummyListener {
        fn filtered_block_connected(
            &self,
            header: &bitcoin::block::Header,
            _: &chain::transaction::TransactionData,
            _: u32,
        ) {
            self.connected_blocks
                .borrow_mut()
                .insert(header.block_hash());
        }

        fn block_disconnected(&self, header: &bitcoin::block::Header, _: u32) {
            self.disconnected_blocks
                .borrow_mut()
                .insert(header.block_hash());
        }
    }

    #[tokio::test]
    async fn test_poll_best_tip_common() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let tip = chain.tip();

        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let (_, shutdown_signal) = triggered::trigger();
        let listener = DummyListener::new();

        let poller = ChainPoller::new(&mut chain, Network::Bitcoin);
        let cache = &mut UnboundedCache::new();
        let spv_client = SpvClient::new(tip, poller, cache, &listener);
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));

        let mut cm =
            ChainMonitor::new(spv_client, tip, dbm, 1, shutdown_signal, bitcoind_reachable).await;

        // If there's no new block nothing gets connected nor disconnected
        cm.poll_best_tip().await;
        assert!(listener.connected_blocks.borrow().is_empty());
        assert!(listener.disconnected_blocks.borrow().is_empty());
    }

    #[tokio::test]
    async fn test_poll_best_tip_better() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let new_tip = chain.tip();
        let old_tip = chain.at_height(START_HEIGHT - 1);

        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let (_, shutdown_signal) = triggered::trigger();
        let listener = DummyListener::new();

        let poller = ChainPoller::new(&mut chain, Network::Bitcoin);
        let cache = &mut UnboundedCache::new();
        let spv_client = SpvClient::new(old_tip, poller, cache, &listener);
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));

        let mut cm = ChainMonitor::new(
            spv_client,
            old_tip,
            dbm,
            1,
            shutdown_signal,
            bitcoind_reachable,
        )
        .await;

        // If a new (best) block gets mined, it should be connected
        cm.poll_best_tip().await;
        assert_eq!(cm.last_known_block_header, new_tip);
        assert_eq!(
            cm.dbm.lock().unwrap().load_last_known_block().unwrap(),
            new_tip.deref().header.block_hash()
        );
        assert!(listener
            .connected_blocks
            .borrow()
            .contains(&new_tip.deref().header.block_hash()));
        assert!(listener.disconnected_blocks.borrow().is_empty());
    }

    #[tokio::test]
    async fn test_poll_best_tip_worse() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let best_tip = chain.tip();
        chain.disconnect_tip();

        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let (_, shutdown_signal) = triggered::trigger();
        let listener = DummyListener::new();

        let poller = ChainPoller::new(&mut chain, Network::Bitcoin);
        let cache = &mut UnboundedCache::new();
        let spv_client = SpvClient::new(best_tip, poller, cache, &listener);
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));

        let mut cm = ChainMonitor::new(
            spv_client,
            best_tip,
            dbm,
            1,
            shutdown_signal,
            bitcoind_reachable,
        )
        .await;

        // If a new (worse, just one) block gets mined, nothing gets connected nor disconnected
        cm.poll_best_tip().await;
        assert_eq!(cm.last_known_block_header, best_tip);
        assert!(cm.dbm.lock().unwrap().load_last_known_block().is_none());
        assert!(listener.connected_blocks.borrow().is_empty());
        assert!(listener.disconnected_blocks.borrow().is_empty());
    }

    #[tokio::test]
    async fn test_poll_best_tip_reorg() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let old_best = chain.tip();
        // Reorg
        chain.disconnect_tip();
        let new_blocks = (0..2)
            .map(|_| chain.generate(None).block_hash())
            .collect::<HashSet<BlockHash>>();

        let new_best = chain.tip();

        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let (_, shutdown_signal) = triggered::trigger();
        let listener = DummyListener::new();

        let poller = ChainPoller::new(&mut chain, Network::Bitcoin);
        let cache = &mut UnboundedCache::new();
        let spv_client = SpvClient::new(old_best, poller, cache, &listener);
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));

        let mut cm = ChainMonitor::new(
            spv_client,
            old_best,
            dbm,
            1,
            shutdown_signal,
            bitcoind_reachable,
        )
        .await;

        // If a a reorg is found (tip is disconnected and a new best is found), both data should be connected and disconnected
        cm.poll_best_tip().await;
        assert_eq!(cm.last_known_block_header, new_best);
        assert_eq!(
            cm.dbm.lock().unwrap().load_last_known_block().unwrap(),
            new_best.deref().header.block_hash()
        );
        assert_eq!(*listener.connected_blocks.borrow(), new_blocks);
        assert_eq!(
            *listener.disconnected_blocks.borrow(),
            HashSet::from_iter([old_best.deref().header.block_hash()])
        );
    }

    #[tokio::test]
    async fn test_poll_best_tip_bitcoind_unreachable() {
        let mut chain = Blockchain::default().unreachable();
        let chain_offline = chain.unreachable.clone();
        let tip = chain.tip();

        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let (_, shutdown_signal) = triggered::trigger();
        let listener = DummyListener::new();

        let poller = ChainPoller::new(&mut chain, Network::Bitcoin);
        let cache = &mut UnboundedCache::new();
        let spv_client = SpvClient::new(tip, poller, cache, &listener);
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));

        let mut cm = ChainMonitor::new(
            spv_client,
            tip,
            dbm,
            1,
            shutdown_signal,
            bitcoind_reachable.clone(),
        )
        .await;

        // Our block source was defined as unreachable (bitcoind is off). Check that the unreachable flag is set after polling.
        cm.poll_best_tip().await;
        let (reachable, _) = &*bitcoind_reachable.clone();
        assert!(!*reachable.lock().unwrap());

        // Set a thread to block on bitcoind unreachable to check that it gets notified once bitcoind comes back online
        let t = thread::spawn(move || {
            let (lock, notifier) = &*bitcoind_reachable;
            let mut reachable = lock.lock().unwrap();
            while !*reachable {
                reachable = notifier.wait(reachable).unwrap();
            }
        });

        // Set bitcoind as reachable again and check back
        *chain_offline.lock().unwrap() = false;
        cm.poll_best_tip().await;
        assert!(*reachable.lock().unwrap());

        // This would hang if the cm didn't notify their subscribers about the bitcoind status, so it serves as out assert.
        t.join().unwrap();
    }
}
