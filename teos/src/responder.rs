//! Logic related to the Responder, the components in charge of making sure breaches get properly punished.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use bitcoin::{consensus, BlockHash};
use bitcoin::{Transaction, Txid};
use lightning::chain;
use lightning::util::ser::Writeable;
use lightning_block_sync::poll::ValidatedBlock;

use teos_common::constants;
use teos_common::protos as common_msgs;
use teos_common::UserId;

use crate::carrier::Carrier;
use crate::dbm::DBM;
use crate::extended_appointment::UUID;
use crate::gatekeeper::Gatekeeper;
use crate::tx_index::TxIndex;
use crate::watcher::Breach;

/// Number of missed confirmations to wait before rebroadcasting a transaction.
const CONFIRMATIONS_BEFORE_RETRY: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The confirmation status of a given penalty transaction.
pub enum ConfirmationStatus {
    ConfirmedIn(u32),
    InMempoolSince(u32),
    IrrevocablyResolved,
    Rejected(i32),
}

impl ConfirmationStatus {
    /// Builds a [ConfirmationStatus] from data loaded from the database.
    /// Only trackers that are confirmed or accepted to mempool are stored.
    pub fn from_db_data(height: u32, confirmed: bool) -> Self {
        if confirmed {
            ConfirmationStatus::ConfirmedIn(height)
        } else {
            ConfirmationStatus::InMempoolSince(height)
        }
    }

    /// Converts a confirmation status into a tuple ready to be stored in the database.
    /// Only trackers that are confirmed or accepted to mempool are stored.
    pub fn to_db_data(&self) -> Option<(u32, bool)> {
        if let ConfirmationStatus::ConfirmedIn(h) = self {
            Some((*h, true))
        } else if let ConfirmationStatus::InMempoolSince(h) = self {
            Some((*h, false))
        } else {
            None
        }
    }

    /// Whether the transaction was accepted by the underlying node.
    pub fn accepted(&self) -> bool {
        matches!(
            self,
            ConfirmationStatus::ConfirmedIn(_) | &ConfirmationStatus::InMempoolSince(_)
        )
    }
}

/// Structure to keep track of triggered appointments.
///
/// It is analogous to [ExtendedAppointment](crate::extended_appointment::ExtendedAppointment) for the [`Watcher`](crate::watcher::Watcher).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransactionTracker {
    /// Matches the corresponding [Breach] `dispute_tx` field.
    pub dispute_tx: Transaction,
    /// Matches the corresponding [Breach] penalty_tx field.
    pub penalty_tx: Transaction,
    /// The confirmation status of a given tracker. Reflects the penalty transaction status.
    pub status: ConfirmationStatus,
    /// [UserId] the original [ExtendedAppointment](crate::extended_appointment::ExtendedAppointment) belongs to.
    pub user_id: UserId,
}

impl TransactionTracker {
    /// Creates a new [TransactionTracker] instance.
    pub fn new(breach: Breach, user_id: UserId, status: ConfirmationStatus) -> Self {
        Self {
            dispute_tx: breach.dispute_tx,
            penalty_tx: breach.penalty_tx,
            status,
            user_id,
        }
    }
}

impl From<TransactionTracker> for common_msgs::Tracker {
    fn from(t: TransactionTracker) -> Self {
        common_msgs::Tracker {
            dispute_txid: t.dispute_tx.compute_txid().encode(),
            penalty_txid: t.penalty_tx.compute_txid().encode(),
            penalty_rawtx: consensus::serialize(&t.penalty_tx),
        }
    }
}

/// A struct that packages the summary of a tracker's penalty transaction.
#[derive(Debug, PartialEq)]
pub(crate) struct PenaltySummary {
    pub penalty_txid: Txid,
    pub status: ConfirmationStatus,
}

impl PenaltySummary {
    pub fn new(penalty_txid: Txid, status: ConfirmationStatus) -> Self {
        PenaltySummary {
            penalty_txid,
            status,
        }
    }
}

/// Component in charge of keeping track of triggered appointments.
///
/// The [Responder] receives data from the [Watcher](crate::watcher::Watcher) in form of a [Breach].
/// From there, a [TransactionTracker] is created and the penalty transaction is sent to the network via the [Carrier].
/// The [Transaction] is then monitored to make sure it makes it to a block and it gets [irrevocably resolved](https://github.com/lightning/bolts/blob/master/05-onchain.md#general-nomenclature).
#[derive(Debug)]
pub struct Responder {
    /// A local, pruned, [TxIndex] used to avoid the need of `txindex=1`.
    tx_index: Mutex<TxIndex<Txid, BlockHash>>,
    /// A [Carrier] instance. Data is sent to the `bitcoind` through it.
    carrier: Mutex<Carrier>,
    /// A [Gatekeeper] instance. Data regarding users is requested to it.
    gatekeeper: Arc<Gatekeeper>,
    /// A [DBM] (database manager) instance. Used to persist tracker data into disk.
    dbm: Arc<Mutex<DBM>>,
    /// A list of all the reorged trackers that might need to be republished after reorg resolution.
    reorged_trackers: Mutex<HashSet<UUID>>,
}

impl Responder {
    /// Creates a new [Responder] instance.
    pub fn new(
        last_n_blocs: &[ValidatedBlock],
        last_known_block_height: u32,
        carrier: Carrier,
        gatekeeper: Arc<Gatekeeper>,
        dbm: Arc<Mutex<DBM>>,
    ) -> Self {
        Responder {
            carrier: Mutex::new(carrier),
            tx_index: Mutex::new(TxIndex::new(last_n_blocs, last_known_block_height)),
            dbm,
            gatekeeper,
            reorged_trackers: Mutex::new(HashSet::new()),
        }
    }

    /// Returns whether the [Responder] has been created from scratch (fresh) or from backed-up data.
    pub fn is_fresh(&self) -> bool {
        self.get_trackers_count() == 0
    }

    /// Gets the total number of trackers in the [Responder].
    pub(crate) fn get_trackers_count(&self) -> usize {
        self.dbm.lock().unwrap().get_trackers_count()
    }

    /// Checks whether the [Responder] has gone through a reorg and some transactions should to be resent.
    fn coming_from_reorg(&self) -> bool {
        !self.reorged_trackers.lock().unwrap().is_empty()
    }

    /// Data entry point for the [Responder]. Handles a [Breach] provided by the [Watcher](crate::watcher::Watcher).
    ///
    /// Breaches can either be added to the [Responder] in the form of a [TransactionTracker] if the [penalty transaction](Breach::penalty_tx)
    /// is accepted by the `bitcoind` or rejected otherwise.
    pub(crate) fn handle_breach(
        &self,
        uuid: UUID,
        breach: Breach,
        user_id: UserId,
    ) -> ConfirmationStatus {
        let mut carrier = self.carrier.lock().unwrap();
        let tx_index = self.tx_index.lock().unwrap();

        // Check whether the transaction is in mempool or part of our internal txindex. Send it to our node otherwise.
        let status = if let Some(block_hash) = tx_index.get(&breach.penalty_tx.compute_txid()) {
            ConfirmationStatus::ConfirmedIn(tx_index.get_height(block_hash).unwrap() as u32)
        } else if carrier.in_mempool(&breach.penalty_tx.compute_txid()) {
            // If it's in mempool we assume it was just included
            ConfirmationStatus::InMempoolSince(carrier.block_height())
        } else {
            carrier.send_transaction(&breach.penalty_tx)
        };

        if status.accepted() {
            self.add_tracker(uuid, breach, user_id, status);
        }

        status
    }

    /// Adds a [TransactionTracker] to the [Responder] from a given [Breach].
    ///
    /// From this point on, transactions are accepted as valid. They may not end up being confirmed, but they
    /// have been checked syntactically by the [Watcher](crate::watcher::Watcher) and against consensus / network
    /// acceptance rules by the [Carrier].
    ///
    /// Some transaction may already be confirmed by the time the tower tries to send them to the network. If that's the case,
    /// the [Responder] will simply continue tracking the job until its completion.
    pub(crate) fn add_tracker(
        &self,
        uuid: UUID,
        breach: Breach,
        user_id: UserId,
        status: ConfirmationStatus,
    ) {
        if self
            .dbm
            .lock()
            .unwrap()
            .store_tracker(uuid, &TransactionTracker::new(breach, user_id, status))
            .is_ok()
        {
            log::info!("New tracker added (uuid={uuid})");
        } else {
            log::error!(
                "Failed to store tracker in database (uuid={uuid}). It might be already stored."
            );
        }
    }

    /// Checks whether a given tracker can be found in the [Responder].
    pub(crate) fn has_tracker(&self, uuid: UUID) -> bool {
        self.dbm.lock().unwrap().tracker_exists(uuid)
    }

    /// Checks the confirmation count for the [TransactionTracker]s.
    ///
    /// For unconfirmed transactions, it checks whether they have been confirmed or keep missing confirmations.
    /// For confirmed transactions, nothing is done until they are completed (confirmation count reaches [IRREVOCABLY_RESOLVED](constants::IRREVOCABLY_RESOLVED))
    /// Returns the set of completed trackers or [None] if none were completed.
    fn check_confirmations(&self, txids: HashSet<Txid>, current_height: u32) -> Option<Vec<UUID>> {
        let mut completed_trackers = Vec::new();
        let mut reorged_trackers = self.reorged_trackers.lock().unwrap();
        let dbm = self.dbm.lock().unwrap();

        for (uuid, penalty_summary) in dbm.load_penalties_summaries() {
            if txids.contains(&penalty_summary.penalty_txid) {
                // First confirmation was received
                dbm.update_tracker_status(uuid, &ConfirmationStatus::ConfirmedIn(current_height))
                    .unwrap();
                // Remove that uuid from reorged trackers if it was confirmed.
                reorged_trackers.remove(&uuid);
            // TODO: We won't need this check when we persist the correct tracker status
            // in the DB after migrations are supported.
            } else if reorged_trackers.contains(&uuid) {
                // Don't consider reorged trackers since they have wrong DB status.
                continue;
            } else if let ConfirmationStatus::ConfirmedIn(h) = penalty_summary.status {
                let confirmations = current_height - h;
                if confirmations == constants::IRREVOCABLY_RESOLVED {
                    // Tracker is deep enough in the chain, it can be deleted
                    completed_trackers.push(uuid);
                } else {
                    log::info!("{uuid} received a confirmation (count={confirmations})");
                }
            } else if let ConfirmationStatus::InMempoolSince(h) = penalty_summary.status {
                // Log all transactions that have missed confirmations
                log::info!(
                    "Transaction missed a confirmation: {} (missed conf count: {})",
                    penalty_summary.penalty_txid,
                    current_height - h
                );
            }
        }

        (!completed_trackers.is_empty()).then_some(completed_trackers)
    }

    /// Handles the reorged out trackers when we start connecting to the stronger chain.
    ///
    /// This is called in the first block connection after a bunch of block disconnections.
    /// It tries to publish the dispute and penalty transactions of reorged trackers to the blockchain.
    ///
    /// Returns a vector of rejected trackers during rebroadcast if any were rejected, [None] otherwise.
    fn handle_reorged_txs(&self, height: u32) -> Option<Vec<UUID>> {
        // NOTE: We are draining the reorged trackers set, meaning that we won't try sending these disputes again.
        let reorged_trackers: Vec<UUID> = self.reorged_trackers.lock().unwrap().drain().collect();
        let mut carrier = self.carrier.lock().unwrap();
        let dbm = self.dbm.lock().unwrap();

        let mut rejected = Vec::new();
        // Republish all the dispute transactions of the reorged trackers.
        for uuid in reorged_trackers {
            let tracker = dbm.load_tracker(uuid).unwrap();
            let dispute_txid = tracker.dispute_tx.compute_txid();
            // Try to publish the dispute transaction.
            let should_publish_penalty = match carrier.send_transaction(&tracker.dispute_tx) {
                ConfirmationStatus::InMempoolSince(_) => {
                    log::info!(
                        "Reorged dispute tx (txid={}) is in the mempool now",
                        dispute_txid
                    );
                    true
                }
                // NOTE: We aren't fully synced with the bitcoind backend so can't check if the dispute tx is in our txindex.
                ConfirmationStatus::IrrevocablyResolved => {
                    log::info!(
                        "Reorged dispute tx (txid={}) is already on the strong chain",
                        dispute_txid
                    );
                    true
                }
                ConfirmationStatus::Rejected(e) => {
                    log::error!(
                        "Reorged dispute tx (txid={}) rejected during rebroadcast (reason: {e:?})",
                        dispute_txid
                    );
                    false
                }
                x => unreachable!(
                    "`Carrier::send_transaction` shouldn't return this variant: {:?}",
                    x
                ),
            };

            if should_publish_penalty {
                // Try to rebroadcast the penalty tx.
                if let ConfirmationStatus::Rejected(_) =
                    carrier.send_transaction(&tracker.penalty_tx)
                {
                    rejected.push(uuid)
                } else {
                    // The penalty might actually be confirmed (ConfirmationStatus::IrrevocablyResolved) since bitcoind
                    // is fully synced with the stronger chain already, but we won't know which block was it confirmed in.
                    // We should see the tracker appear in the blockchain in the next couple of connected blocks.
                    dbm.update_tracker_status(uuid, &ConfirmationStatus::InMempoolSince(height))
                        .unwrap()
                }
            } else {
                rejected.push(uuid)
            }
        }

        (!rejected.is_empty()).then_some(rejected)
    }

    /// Rebroadcasts a list of penalty transactions that have missed too many confirmations.
    ///
    /// This covers the case where a transaction is not getting confirmations (most likely due to low
    /// fess and needs to be bumped, but there is not much we can do until anchors).
    ///
    /// Returns a vector of rejected trackers during rebroadcast if any were rejected, [None] otherwise.
    fn rebroadcast_stale_txs(&self, height: u32) -> Option<Vec<UUID>> {
        let dbm = self.dbm.lock().unwrap();
        let mut carrier = self.carrier.lock().unwrap();
        let mut rejected = Vec::new();

        // Retry sending trackers which have been in the mempool since more than `CONFIRMATIONS_BEFORE_RETRY` blocks.
        let stale_confirmation_status =
            ConfirmationStatus::InMempoolSince(height - CONFIRMATIONS_BEFORE_RETRY as u32);
        // NOTE: Ideally this will only pull UUIDs which have been in mempool since `CONFIRMATIONS_BEFORE_RETRY`, but
        // might also return ones which have been there for a longer period. This can only happen if the tower missed
        // a couple of block connections due to a force update.
        for uuid in dbm
            .load_trackers_with_confirmation_status(stale_confirmation_status)
            .unwrap()
        {
            let tracker = dbm.load_tracker(uuid).unwrap();
            log::warn!(
                "Penalty transaction has missed many confirmations: {}",
                tracker.penalty_tx.compute_txid()
            );
            // Rebroadcast the penalty transaction.
            let status = carrier.send_transaction(&tracker.penalty_tx);
            if let ConfirmationStatus::Rejected(_) = status {
                rejected.push(uuid);
            } else {
                // DISCUSS: What if the tower was down for some time and was later force updated while this penalty got on-chain?
                // Sending it will yield `ConfirmationStatus::IrrevocablyResolved` which would panic here.
                // We might want to replace `ConfirmationStatus::IrrevocablyResolved` variant with
                // `ConfirmationStatus::ConfirmedIn(height - IRREVOCABLY_RESOLVED)
                dbm.update_tracker_status(uuid, &status).unwrap();
            }
        }

        (!rejected.is_empty()).then_some(rejected)
    }
}

/// Listen implementation by the [Responder]. Handles monitoring and reorgs.
impl chain::Listen for Responder {
    /// Handles the monitoring process by the [Responder].
    ///
    /// Watching is performed in a per-block basis. A [TransactionTracker] is tracked until:
    /// - It gets [irrevocably resolved](https://github.com/lightning/bolts/blob/master/05-onchain.md#general-nomenclature) or
    /// - The user subscription expires
    /// - The trackers becomes invalid (due to a reorg)
    ///
    /// Every time a block is received the tracking conditions are checked against the monitored [TransactionTracker]s and
    /// data deletion is performed accordingly. Moreover, lack of confirmations is check for the tracked transactions and
    /// rebroadcasting is performed for those that have missed too many.
    fn filtered_block_connected(
        &self,
        header: &bitcoin::block::Header,
        txdata: &chain::transaction::TransactionData,
        height: u32,
    ) {
        log::info!("New block received: {}", header.block_hash());
        self.carrier.lock().unwrap().update_height(height);

        let txs = txdata
            .iter()
            .map(|(_, tx)| (tx.compute_txid(), header.block_hash()))
            .collect();
        self.tx_index.lock().unwrap().update(*header, &txs);

        // Delete trackers completed at this height
        if let Some(trackers) = self.check_confirmations(txs.keys().cloned().collect(), height) {
            self.gatekeeper.delete_appointments(trackers, true);
        }

        let mut trackers_to_delete = Vec::new();
        // We might be connecting a new block after a disconnection (reorg).
        // We will need to update those trackers that have been reorged.
        if self.coming_from_reorg() {
            // Handle reorged transactions. This clears `self.reorged_trackers`.
            if let Some(trackers) = self.handle_reorged_txs(height) {
                trackers_to_delete.extend(trackers);
            }
        }

        // Rebroadcast those transactions that need to
        if let Some(trackers) = self.rebroadcast_stale_txs(height) {
            trackers_to_delete.extend(trackers);
        }

        if !trackers_to_delete.is_empty() {
            self.gatekeeper
                .delete_appointments(trackers_to_delete, false);
        }

        // Remove all receipts created in this block
        self.carrier.lock().unwrap().clear_receipts();
    }

    /// Handles reorgs in the [Responder].
    fn block_disconnected(&self, header: &bitcoin::block::Header, height: u32) {
        log::warn!("Block disconnected: {}", header.block_hash());
        // Update the carrier and our tx_index.
        self.carrier.lock().unwrap().update_height(height);
        self.tx_index
            .lock()
            .unwrap()
            .remove_disconnected_block(&header.block_hash());
        // And store the reorged transactions to be retried later.
        // TODO: Not only confirmed trackers need to be marked as reorged, but trackers that hasn't confirmed but their
        // dispute did confirm in the reorged block. We can pull dispute txids of non confirmed penalties and get their
        // confirmation block from our tx_index.
        self.reorged_trackers.lock().unwrap().extend(
            self.dbm
                .lock()
                .unwrap()
                .load_trackers_with_confirmation_status(ConfirmationStatus::ConfirmedIn(height))
                .unwrap(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightning::chain::Listen;
    use teos_common::appointment::Locator;

    use std::collections::HashMap;
    use std::iter::FromIterator;
    use std::sync::{Arc, Mutex};

    use crate::dbm::DBM;
    use crate::rpc_errors;
    use crate::test_utils::{
        create_carrier, generate_dummy_appointment, generate_dummy_appointment_with_user,
        generate_uuid, get_last_n_blocks, get_random_breach, get_random_tracker, get_random_tx,
        store_appointment_and_its_user, BitcoindStopper, Blockchain, MockedServerQuery, DURATION,
        EXPIRY_DELTA, SLOTS, START_HEIGHT,
    };

    use teos_common::constants::IRREVOCABLY_RESOLVED;
    use teos_common::test_utils::get_random_user_id;

    impl TransactionTracker {
        pub fn locator(&self) -> Locator {
            Locator::new(self.dispute_tx.compute_txid())
        }

        pub fn uuid(&self) -> UUID {
            UUID::new(self.locator(), self.user_id)
        }
    }

    impl PartialEq for Responder {
        fn eq(&self, other: &Self) -> bool {
            // Same in-memory data.
            *self.reorged_trackers.lock().unwrap() == *other.reorged_trackers.lock().unwrap() &&
            *self.tx_index.lock().unwrap() == *other.tx_index.lock().unwrap() &&
            // && Same DB data.
            self.get_trackers() == other.get_trackers()
        }
    }
    impl Eq for Responder {}

    impl Responder {
        pub(crate) fn get_trackers(&self) -> HashMap<UUID, TransactionTracker> {
            self.dbm.lock().unwrap().load_trackers(None)
        }

        pub(crate) fn get_carrier(&self) -> &Mutex<Carrier> {
            &self.carrier
        }

        pub(crate) fn add_random_tracker(&self, status: ConfirmationStatus) -> TransactionTracker {
            let user_id = get_random_user_id();
            let tracker = get_random_tracker(user_id, status);
            self.add_dummy_tracker(&tracker);

            tracker
        }

        pub(crate) fn add_dummy_tracker(&self, tracker: &TransactionTracker) {
            let (_, appointment) = generate_dummy_appointment_with_user(
                tracker.user_id,
                Some(&tracker.dispute_tx.compute_txid()),
            );
            store_appointment_and_its_user(&self.dbm.lock().unwrap(), &appointment);
            self.dbm
                .lock()
                .unwrap()
                .store_tracker(appointment.uuid(), tracker)
                .unwrap();
        }

        fn store_dummy_appointment_to_db(&self) -> (UserId, UUID) {
            let appointment = generate_dummy_appointment(None);
            let (uuid, user_id) = (appointment.uuid(), appointment.user_id);
            // Store the appointment and the user to the DB.
            store_appointment_and_its_user(&self.dbm.lock().unwrap(), &appointment);
            (user_id, uuid)
        }
    }

    async fn create_responder(
        chain: &mut Blockchain,
        gatekeeper: Arc<Gatekeeper>,
        dbm: Arc<Mutex<DBM>>,
        query: MockedServerQuery,
    ) -> (Responder, BitcoindStopper) {
        let height = if chain.tip().height < IRREVOCABLY_RESOLVED {
            chain.tip().height
        } else {
            IRREVOCABLY_RESOLVED
        };

        let last_n_blocks = get_last_n_blocks(chain, height as usize).await;

        let (carrier, bitcoind_stopper) = create_carrier(query, chain.tip().height);
        (
            Responder::new(&last_n_blocks, chain.tip().height, carrier, gatekeeper, dbm),
            bitcoind_stopper,
        )
    }

    async fn init_responder_with_chain_and_dbm(
        mocked_query: MockedServerQuery,
        chain: &mut Blockchain,
        dbm: Arc<Mutex<DBM>>,
    ) -> (Responder, BitcoindStopper) {
        let gk = Gatekeeper::new(
            chain.get_block_count(),
            SLOTS,
            DURATION,
            EXPIRY_DELTA,
            dbm.clone(),
        );
        create_responder(chain, Arc::new(gk), dbm, mocked_query).await
    }

    async fn init_responder(mocked_query: MockedServerQuery) -> (Responder, BitcoindStopper) {
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, 10);
        init_responder_with_chain_and_dbm(mocked_query, &mut chain, dbm).await
    }

    #[test]
    fn test_confirmation_status_from_db_data() {
        // These are pretty simple tests. The db can only store trackers with a confirmation status
        // that's either ConfirmedIn or InMempoolSince (Rejected and IrrevocablyResolved are never passed to store).
        let h = 21;

        assert_eq!(
            ConfirmationStatus::from_db_data(h, true),
            ConfirmationStatus::ConfirmedIn(h)
        );
        assert_eq!(
            ConfirmationStatus::from_db_data(h, false),
            ConfirmationStatus::InMempoolSince(h)
        );
    }

    #[test]
    fn test_confirmation_status_to_db_data() {
        // Analogous to the previous test, this will only construct ConfirmedIn and InMempolSince statuses.
        // The None case has to be threaten though.
        let h = 21;

        assert_eq!(
            ConfirmationStatus::ConfirmedIn(h).to_db_data(),
            Some((h, true))
        );
        assert_eq!(
            ConfirmationStatus::InMempoolSince(h).to_db_data(),
            Some((h, false))
        );
        assert_eq!(ConfirmationStatus::Rejected(0).to_db_data(), None);
        assert_eq!(ConfirmationStatus::IrrevocablyResolved.to_db_data(), None);
    }

    #[tokio::test]
    async fn test_responder_new() {
        // A fresh responder has no associated data
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let (responder, _s) =
            init_responder_with_chain_and_dbm(MockedServerQuery::Regular, &mut chain, dbm.clone())
                .await;
        assert!(responder.is_fresh());

        // If we add some trackers to the system and create a new Responder reusing the same db
        // (as if simulating a bootstrap from existing data), the data should be properly loaded.
        for i in 0..10 {
            let (user_id, uuid) = responder.store_dummy_appointment_to_db();
            let breach = get_random_breach();
            let s = if i % 2 == 0 {
                ConfirmationStatus::InMempoolSince(i)
            } else {
                ConfirmationStatus::ConfirmedIn(i)
            };
            responder.add_tracker(uuid, breach.clone(), user_id, s);
        }

        // Create a new Responder reusing the same DB and check that the data is loaded
        let (another_r, _) =
            init_responder_with_chain_and_dbm(MockedServerQuery::Regular, &mut chain, dbm).await;
        assert!(!responder.is_fresh());
        assert_eq!(responder, another_r);
    }

    #[tokio::test]
    async fn test_handle_breach_accepted() {
        let start_height = START_HEIGHT as u32;
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;

        let (user_id, uuid) = responder.store_dummy_appointment_to_db();
        let breach = get_random_breach();

        assert_eq!(
            responder.handle_breach(uuid, breach, user_id),
            ConfirmationStatus::InMempoolSince(start_height)
        );
        let tracker = responder.dbm.lock().unwrap().load_tracker(uuid).unwrap();
        assert_eq!(
            tracker.status,
            ConfirmationStatus::InMempoolSince(start_height)
        );

        // Breaches won't be overwritten once passed to the Responder. If the same UUID is
        // passed twice, the receipt corresponding to the first breach will be handed back.
        let another_breach = get_random_breach();
        assert_eq!(
            responder.handle_breach(uuid, another_breach, user_id),
            ConfirmationStatus::InMempoolSince(start_height)
        );
        // Getting the tracker should return the old one.
        assert_eq!(
            tracker,
            responder.dbm.lock().unwrap().load_tracker(uuid).unwrap()
        );
    }

    #[tokio::test]
    async fn test_handle_breach_accepted_in_mempool() {
        let start_height = START_HEIGHT as u32;
        let (responder, _s) = init_responder(MockedServerQuery::InMempoool).await;

        let (user_id, uuid) = responder.store_dummy_appointment_to_db();
        let breach = get_random_breach();

        assert_eq!(
            responder.handle_breach(uuid, breach, user_id),
            ConfirmationStatus::InMempoolSince(start_height)
        );
        let tracker = responder.dbm.lock().unwrap().load_tracker(uuid).unwrap();
        assert_eq!(
            tracker.status,
            ConfirmationStatus::InMempoolSince(start_height)
        );
    }

    #[tokio::test]
    async fn test_handle_breach_accepted_in_txindex() {
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;

        let (user_id, uuid) = responder.store_dummy_appointment_to_db();

        let breach = get_random_breach();
        let penalty_txid = breach.penalty_tx.compute_txid();

        // Add the tx to our txindex
        let target_block_hash = *responder.tx_index.lock().unwrap().blocks().get(2).unwrap();
        responder
            .tx_index
            .lock()
            .unwrap()
            .index_mut()
            .insert(penalty_txid, target_block_hash);
        let target_height = responder
            .tx_index
            .lock()
            .unwrap()
            .get_height(&target_block_hash)
            .unwrap() as u32;

        assert_eq!(
            responder.handle_breach(uuid, breach, user_id),
            ConfirmationStatus::ConfirmedIn(target_height)
        );
        let tracker = responder.dbm.lock().unwrap().load_tracker(uuid).unwrap();
        assert_eq!(
            tracker.status,
            ConfirmationStatus::ConfirmedIn(target_height)
        );
    }

    #[tokio::test]
    async fn test_handle_breach_rejected() {
        let (responder, _s) = init_responder(MockedServerQuery::Error(
            rpc_errors::RPC_VERIFY_ERROR as i64,
        ))
        .await;

        let user_id = get_random_user_id();
        let uuid = generate_uuid();
        let breach = get_random_breach();

        assert_eq!(
            responder.handle_breach(uuid, breach, user_id),
            ConfirmationStatus::Rejected(rpc_errors::RPC_VERIFY_ERROR)
        );
        assert!(!responder.has_tracker(uuid));
    }

    #[tokio::test]
    async fn test_add_tracker() {
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;
        let start_height = START_HEIGHT as u32;

        let (user_id, uuid) = responder.store_dummy_appointment_to_db();
        let mut breach = get_random_breach();
        responder.add_tracker(
            uuid,
            breach.clone(),
            user_id,
            ConfirmationStatus::InMempoolSince(start_height),
        );

        // Check that the data has been added to the responder.
        assert_eq!(
            responder.dbm.lock().unwrap().load_tracker(uuid).unwrap(),
            TransactionTracker::new(
                breach,
                user_id,
                ConfirmationStatus::InMempoolSince(start_height)
            )
        );

        // Adding a confirmed tracker should result in the same but with the height being set.

        let (user_id, uuid) = responder.store_dummy_appointment_to_db();
        breach = get_random_breach();
        responder.add_tracker(
            uuid,
            breach.clone(),
            user_id,
            ConfirmationStatus::ConfirmedIn(start_height - 1),
        );

        assert_eq!(
            responder.dbm.lock().unwrap().load_tracker(uuid).unwrap(),
            TransactionTracker::new(
                breach.clone(),
                user_id,
                ConfirmationStatus::ConfirmedIn(start_height - 1)
            )
        );

        // Adding another breach with the same penalty transaction (but different uuid)
        let (user_id, uuid) = responder.store_dummy_appointment_to_db();
        responder.add_tracker(
            uuid,
            breach.clone(),
            user_id,
            ConfirmationStatus::ConfirmedIn(start_height),
        );

        assert_eq!(
            responder.dbm.lock().unwrap().load_tracker(uuid).unwrap(),
            TransactionTracker::new(
                breach,
                user_id,
                ConfirmationStatus::ConfirmedIn(start_height)
            )
        );
    }

    #[tokio::test]
    async fn test_has_tracker() {
        // Has tracker should return true as long as the given tracker is held by the Responder.
        // As long as the tracker is in Responder.trackers and Responder.tx_tracker_map, the return
        // must be true.
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;

        // Add a new tracker
        let (user_id, uuid) = responder.store_dummy_appointment_to_db();
        let breach = get_random_breach();
        responder.add_tracker(
            uuid,
            breach,
            user_id,
            ConfirmationStatus::ConfirmedIn(START_HEIGHT as u32),
        );

        assert!(responder.has_tracker(uuid));

        // Delete the tracker and check again.
        responder.gatekeeper.delete_appointments(vec![uuid], false);
        assert!(!responder.has_tracker(uuid));
    }

    #[tokio::test]
    async fn test_get_tracker() {
        // Should return a tracker as long as it exists
        let start_height = START_HEIGHT as u32;
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;

        // Store the user and the appointment in the database so we can add the tracker later on (due to FK restrictions)
        let (user_id, uuid) = responder.store_dummy_appointment_to_db();

        // Data should not be there before adding it
        assert!(responder.dbm.lock().unwrap().load_tracker(uuid).is_none());

        // Data should be there now
        let breach = get_random_breach();
        responder.add_tracker(
            uuid,
            breach.clone(),
            user_id,
            ConfirmationStatus::InMempoolSince(start_height),
        );
        assert_eq!(
            responder.dbm.lock().unwrap().load_tracker(uuid).unwrap(),
            TransactionTracker::new(
                breach,
                user_id,
                ConfirmationStatus::InMempoolSince(start_height)
            )
        );

        // After deleting the data it should be gone
        responder.gatekeeper.delete_appointments(vec![uuid], false);
        assert!(responder.dbm.lock().unwrap().load_tracker(uuid).is_none());
    }

    #[tokio::test]
    async fn test_check_confirmations() {
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;
        let target_height = (START_HEIGHT * 2) as u32;

        // Unconfirmed transactions that miss a confirmation will be added to missed_confirmations (if not there) or their missed confirmation count till be increased
        let mut in_mempool = HashSet::new();
        let mut just_confirmed = HashSet::new();
        let mut confirmed = HashSet::new();
        let mut completed = HashSet::new();
        let mut txids = HashSet::new();

        for i in 0..40 {
            let (user_id, uuid) = responder.store_dummy_appointment_to_db();
            let breach = get_random_breach();

            match i % 4 {
                0 => {
                    responder.add_tracker(
                        uuid,
                        breach.clone(),
                        user_id,
                        ConfirmationStatus::InMempoolSince(21),
                    );
                    in_mempool.insert(uuid);
                }
                1 => {
                    responder.add_tracker(
                        uuid,
                        breach.clone(),
                        user_id,
                        ConfirmationStatus::InMempoolSince(i),
                    );
                    just_confirmed.insert(uuid);
                    txids.insert(breach.penalty_tx.compute_txid());
                }
                2 => {
                    responder.add_tracker(
                        uuid,
                        breach.clone(),
                        user_id,
                        ConfirmationStatus::ConfirmedIn(42),
                    );
                    confirmed.insert(uuid);
                }
                _ => {
                    responder.add_tracker(
                        uuid,
                        breach.clone(),
                        user_id,
                        ConfirmationStatus::ConfirmedIn(
                            target_height - constants::IRREVOCABLY_RESOLVED,
                        ),
                    );
                    completed.insert(uuid);
                }
            }
        }

        // The trackers that were completed should be returned
        assert_eq!(
            completed,
            HashSet::from_iter(responder.check_confirmations(txids, target_height).unwrap())
        );

        // The ones in mempool should still be there (at the same height)
        for uuid in in_mempool {
            assert_eq!(
                responder
                    .dbm
                    .lock()
                    .unwrap()
                    .load_tracker(uuid)
                    .unwrap()
                    .status,
                ConfirmationStatus::InMempoolSince(21)
            );
        }

        // The ones that just got confirmed should have been flagged so (at this height)
        for uuid in just_confirmed {
            assert_eq!(
                responder
                    .dbm
                    .lock()
                    .unwrap()
                    .load_tracker(uuid)
                    .unwrap()
                    .status,
                ConfirmationStatus::ConfirmedIn(target_height)
            );
        }

        // The ones that were already confirmed but have not reached the end should remain the same
        for uuid in confirmed {
            assert_eq!(
                responder
                    .dbm
                    .lock()
                    .unwrap()
                    .load_tracker(uuid)
                    .unwrap()
                    .status,
                ConfirmationStatus::ConfirmedIn(42)
            );
        }
    }

    #[tokio::test]
    async fn test_handle_reorged_txs() {
        let (responder, _s) = init_responder(MockedServerQuery::InMempoool).await;
        let mut trackers = Vec::new();

        for _ in 0..10 {
            let uuid = responder
                .add_random_tracker(ConfirmationStatus::ConfirmedIn(42))
                .uuid();
            responder.reorged_trackers.lock().unwrap().insert(uuid);
            trackers.push(uuid);
        }

        let height = 100;
        assert!(responder.handle_reorged_txs(height).is_none());
        // The reorged trackers buffer should be empty after this.
        assert!(responder.reorged_trackers.lock().unwrap().is_empty());

        // And all the reorged trackers should have in mempool since `height` status.
        for uuid in trackers {
            assert_eq!(
                responder
                    .dbm
                    .lock()
                    .unwrap()
                    .load_tracker(uuid)
                    .unwrap()
                    .status,
                ConfirmationStatus::InMempoolSince(height)
            );
        }
    }

    #[tokio::test]
    async fn test_handle_reorged_txs_rejected() {
        let (responder, _s) = init_responder(MockedServerQuery::Error(
            rpc_errors::RPC_VERIFY_REJECTED as i64,
        ))
        .await;
        let n_trackers = 10;
        let mut trackers = HashSet::new();

        for _ in 0..n_trackers {
            let uuid = responder
                .add_random_tracker(ConfirmationStatus::ConfirmedIn(42))
                .uuid();
            responder.reorged_trackers.lock().unwrap().insert(uuid);
            trackers.insert(uuid);
        }

        let height = 100;
        let rejected = HashSet::from_iter(responder.handle_reorged_txs(height).unwrap());
        // All the trackers should be returned as rejected.
        assert_eq!(trackers, rejected);
        // The reorged trackers buffer should be empty after this.
        assert!(responder.reorged_trackers.lock().unwrap().is_empty());

        // And all the reorged trackers statuses should be untouched.
        for uuid in trackers {
            assert_eq!(
                responder
                    .dbm
                    .lock()
                    .unwrap()
                    .load_tracker(uuid)
                    .unwrap()
                    .status,
                ConfirmationStatus::ConfirmedIn(42)
            );
        }
    }

    #[tokio::test]
    async fn test_rebroadcast_stale_txs_accepted() {
        let (responder, _s) = init_responder(MockedServerQuery::InMempoool).await;
        let mut statues = HashMap::new();
        let height = 100;

        for i in 0..height {
            let status = if i % 4 == 0 {
                ConfirmationStatus::ConfirmedIn(i)
            } else {
                ConfirmationStatus::InMempoolSince(i)
            };

            let uuid = responder.add_random_tracker(status).uuid();
            statues.insert(uuid, status);
        }

        // There should be no rejected tx.
        assert!(responder.rebroadcast_stale_txs(height).is_none());

        for (uuid, former_status) in statues {
            let status = responder
                .dbm
                .lock()
                .unwrap()
                .load_tracker(uuid)
                .unwrap()
                .status;
            if let ConfirmationStatus::InMempoolSince(h) = former_status {
                if height - h >= CONFIRMATIONS_BEFORE_RETRY as u32 {
                    // Transactions which stayed for more than `CONFIRMATIONS_BEFORE_RETRY` should have been rebroadcasted.
                    assert_eq!(status, ConfirmationStatus::InMempoolSince(height));
                } else {
                    // Others left untouched.
                    assert_eq!(status, former_status);
                }
            } else {
                // Confirmed transactions left untouched as well.
                assert_eq!(status, former_status);
            }
        }
    }

    #[tokio::test]
    async fn test_rebroadcast_stale_txs_rejected() {
        let (responder, _s) = init_responder(MockedServerQuery::Error(
            rpc_errors::RPC_VERIFY_ERROR as i64,
        ))
        .await;
        let mut statues = HashMap::new();
        let height = 100;

        for i in 0..height {
            let status = if i % 4 == 0 {
                ConfirmationStatus::ConfirmedIn(i)
            } else {
                ConfirmationStatus::InMempoolSince(i)
            };

            let uuid = responder.add_random_tracker(status).uuid();
            statues.insert(uuid, status);
        }

        // `rebroadcast_stale_txs` will broadcast txs which has been in mempool since `CONFIRMATIONS_BEFORE_RETRY` or more
        // blocks. Since our backend rejects all the txs, all these broadcasted txs should be returned from this method (rejected).
        let rejected = HashSet::from_iter(responder.rebroadcast_stale_txs(height).unwrap());
        let should_reject: HashSet<_> = statues
            .iter()
            .filter_map(|(&uuid, &status)| {
                if let ConfirmationStatus::InMempoolSince(h) = status {
                    (height - h >= CONFIRMATIONS_BEFORE_RETRY as u32).then_some(uuid)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(should_reject, rejected);

        for (uuid, former_status) in statues {
            let status = responder
                .dbm
                .lock()
                .unwrap()
                .load_tracker(uuid)
                .unwrap()
                .status;
            // All tracker statues shouldn't change since the submitted ones were all rejected.
            assert_eq!(status, former_status);
        }
    }

    #[tokio::test]
    async fn test_filtered_block_connected() {
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let start_height = START_HEIGHT * 2;
        let mut chain = Blockchain::default().with_height(start_height);
        let (responder, _s) =
            init_responder_with_chain_and_dbm(MockedServerQuery::Regular, &mut chain, dbm).await;

        // filtered_block_connected is used to keep track of the confirmation received (or missed) by the trackers the Responder
        // is keeping track of.
        //
        // If there are any trackers, the Responder will:
        // - Check if there is any tracker that has been completed
        // - Check if any tracker has been confirmed or add missing confirmations otherwise
        // - Rebroadcast all penalty transactions that need so
        // - Delete completed and invalid data (and update the data in the GK)
        // - Clear the Carrier issued_receipts cache
        //
        // We will also test that trackers for outdated users are removed by the GK.

        // Let's start by doing the data setup for each test (i.e. adding all the necessary data to the Responder and GK)
        let target_block_height = chain.get_block_count() + 1;
        let mut users = Vec::new();
        for _ in 0..21 {
            let user_id = get_random_user_id();
            responder.gatekeeper.add_update_user(user_id).unwrap();
            users.push(user_id);
        }

        // COMPLETED TRACKERS SETUP
        let mut completed_trackers = Vec::new();
        for i in 0..10 {
            // Add these trackers to the first two users
            let user_id = users[i % 2];
            let dispute_tx = get_random_tx();
            let (uuid, appointment) =
                generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.compute_txid()));

            responder
                .gatekeeper
                .add_update_appointment(user_id, uuid, &appointment)
                .unwrap();
            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            // Trackers complete in the next block.
            let breach = Breach::new(dispute_tx, get_random_tx());
            let status = ConfirmationStatus::ConfirmedIn(
                target_block_height - constants::IRREVOCABLY_RESOLVED,
            );
            responder.add_tracker(uuid, breach.clone(), user_id, status);
            completed_trackers.push(TransactionTracker::new(breach, user_id, status));
        }

        // OUTDATED TRACKER SETUP
        let mut outdated_trackers = Vec::new();
        for &user_id in users.iter().take(21).skip(11) {
            for _ in 0..3 {
                let dispute_tx = get_random_tx();
                let (uuid, appointment) =
                    generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.compute_txid()));
                responder
                    .gatekeeper
                    .add_update_appointment(user_id, uuid, &appointment)
                    .unwrap();
                responder
                    .dbm
                    .lock()
                    .unwrap()
                    .store_appointment(uuid, &appointment)
                    .unwrap();

                let breach = Breach::new(dispute_tx, get_random_tx());
                let status = ConfirmationStatus::InMempoolSince(target_block_height - 1);
                responder.add_tracker(uuid, breach.clone(), user_id, status);
                outdated_trackers.push(TransactionTracker::new(breach, user_id, status));
            }

            // Outdate this user so their trackers are deleted
            responder
                .gatekeeper
                .add_outdated_user(user_id, target_block_height);
        }

        // CONFIRMATIONS SETUP
        let standalone_user_id = get_random_user_id();
        responder
            .gatekeeper
            .add_update_user(standalone_user_id)
            .unwrap();

        let mut missed_confirmation_trackers = Vec::new();
        let mut just_confirmed_trackers = Vec::new();
        for i in 0..10 {
            let dispute_tx = get_random_tx();
            let (uuid, appointment) = generate_dummy_appointment_with_user(
                standalone_user_id,
                Some(&dispute_tx.compute_txid()),
            );
            responder
                .gatekeeper
                .add_update_appointment(standalone_user_id, uuid, &appointment)
                .unwrap();
            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            let breach = Breach::new(dispute_tx, get_random_tx());

            let status = ConfirmationStatus::InMempoolSince(target_block_height - 1);
            responder.add_tracker(uuid, breach.clone(), standalone_user_id, status);
            if i % 2 == 0 {
                just_confirmed_trackers.push(TransactionTracker::new(
                    breach,
                    standalone_user_id,
                    status,
                ));
            } else {
                missed_confirmation_trackers.push(TransactionTracker::new(
                    breach,
                    standalone_user_id,
                    status,
                ));
            }
        }

        // REBROADCAST SETUP
        let mut trackers_to_rebroadcast = Vec::new();
        for _ in 0..5 {
            let dispute_tx = get_random_tx();
            let (uuid, appointment) = generate_dummy_appointment_with_user(
                standalone_user_id,
                Some(&dispute_tx.compute_txid()),
            );
            responder
                .gatekeeper
                .add_update_appointment(standalone_user_id, uuid, &appointment)
                .unwrap();
            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            let breach = Breach::new(dispute_tx, get_random_tx());
            let status = ConfirmationStatus::InMempoolSince(
                target_block_height - CONFIRMATIONS_BEFORE_RETRY as u32,
            );
            responder.add_tracker(uuid, breach.clone(), standalone_user_id, status);
            trackers_to_rebroadcast.push(TransactionTracker::new(
                breach,
                standalone_user_id,
                status,
            ));
        }

        // CARRIER CACHE SETUP
        // Add some dummy data in the cache to check that it gets cleared
        responder
            .carrier
            .lock()
            .unwrap()
            .get_issued_receipts()
            .insert(
                get_random_tx().compute_txid(),
                ConfirmationStatus::ConfirmedIn(21),
            );

        // Connecting a block should trigger all the state transitions
        let block = chain.generate(Some(
            just_confirmed_trackers
                .iter()
                .map(|t| t.penalty_tx.clone())
                .collect(),
        ));
        let height = chain.get_block_count();
        // We connect the gatekeeper first so it deletes the outdated users.
        responder.gatekeeper.block_connected(&block, height);
        responder.block_connected(&block, height);

        // CARRIER CHECKS
        assert!(responder
            .carrier
            .lock()
            .unwrap()
            .get_issued_receipts()
            .is_empty());

        // Check that the carrier last_known_block_height has been updated
        assert_eq!(
            responder.carrier.lock().unwrap().get_height(),
            target_block_height
        );

        // COMPLETED TRACKERS CHECKS
        // Data should have been removed
        for tracker in completed_trackers {
            assert!(responder
                .dbm
                .lock()
                .unwrap()
                .load_tracker(tracker.uuid())
                .is_none());
            let (_, user_locators) = responder.gatekeeper.get_user_info(tracker.user_id).unwrap();
            assert!(!user_locators.contains(&tracker.locator()));
        }

        // OUTDATED TRACKERS CHECKS
        // Data should have been removed (tracker not found nor the user)
        for tracker in outdated_trackers {
            assert!(responder
                .dbm
                .lock()
                .unwrap()
                .load_tracker(tracker.uuid())
                .is_none());
            assert!(responder
                .gatekeeper
                .get_user_info(tracker.user_id)
                .is_none());
        }

        // CONFIRMATIONS CHECKS
        // The transaction confirmation count / confirmation missed should have been updated
        for tracker in just_confirmed_trackers {
            assert_eq!(
                responder
                    .dbm
                    .lock()
                    .unwrap()
                    .load_tracker(tracker.uuid())
                    .unwrap()
                    .status,
                ConfirmationStatus::ConfirmedIn(target_block_height)
            );
        }
        for tracker in missed_confirmation_trackers {
            assert_eq!(
                responder
                    .dbm
                    .lock()
                    .unwrap()
                    .load_tracker(tracker.uuid())
                    .unwrap()
                    .status,
                ConfirmationStatus::InMempoolSince(target_block_height - 1)
            );
        }

        // REBROADCAST CHECKS
        for tracker in trackers_to_rebroadcast {
            assert_eq!(
                responder
                    .dbm
                    .lock()
                    .unwrap()
                    .load_tracker(tracker.uuid())
                    .unwrap()
                    .status,
                ConfirmationStatus::InMempoolSince(target_block_height),
            );
        }
    }

    #[tokio::test]
    async fn test_block_disconnected() {
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, 10);
        let (responder, _s) =
            init_responder_with_chain_and_dbm(MockedServerQuery::Regular, &mut chain, dbm).await;

        // Add user to the database
        let user_id = get_random_user_id();
        responder.gatekeeper.add_update_user(user_id).unwrap();

        let mut reorged = Vec::new();
        let block_range = START_HEIGHT - 10..START_HEIGHT;

        for i in block_range.clone() {
            // Generate appointment and also add it to the DB
            let dispute_tx = get_random_tx();
            let (uuid, appointment) =
                generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.compute_txid()));
            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            let breach = Breach::new(dispute_tx, get_random_tx());
            responder.add_tracker(
                uuid,
                breach,
                user_id,
                ConfirmationStatus::ConfirmedIn(i as u32),
            );
            reorged.push(uuid);
        }

        // Check that trackers are flagged as reorged if the height they were included at gets disconnected
        for (i, uuid) in block_range.clone().zip(reorged.iter()).rev() {
            // The header doesn't really matter, just the height
            responder.block_disconnected(&chain.tip().header, i as u32);
            // Check that the proper tracker gets reorged at the proper height
            assert!(responder.reorged_trackers.lock().unwrap().contains(uuid));
            // Check that the carrier block_height has been updated
            assert_eq!(responder.carrier.lock().unwrap().get_height(), i as u32);
        }

        // Check that all reorged trackers are still reorged
        for uuid in reorged.iter() {
            assert!(responder.reorged_trackers.lock().unwrap().contains(uuid));
        }

        // But should be clear after the first block connection
        responder.block_connected(&chain.generate(None), block_range.start as u32);
        assert!(responder.reorged_trackers.lock().unwrap().is_empty());
    }
}
