//! Logic related to the Watcher, the components in charge of watching for breaches on chain.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use bitcoin::block::Header;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Transaction;
use lightning::chain;
use lightning_block_sync::poll::ValidatedBlock;

use teos_common::appointment::{Appointment, Locator};
use teos_common::cryptography;
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::{TowerId, UserId};

use crate::dbm::DBM;
use crate::extended_appointment::{ExtendedAppointment, UUID};
use crate::gatekeeper::{Gatekeeper, MaxSlotsReached, UserInfo};
use crate::responder::{ConfirmationStatus, Responder, TransactionTracker};
use crate::tx_index::TxIndex;

/// Structure holding data regarding a breach.
///
/// Breaches are computed after spotting a [Locator] on chain and
/// using the resulting dispute transaction id to decipher the encrypted blob of an ongoing [Appointment].
/// Breaches are passed to the [Responder] once created.
#[derive(Debug, Clone)]
pub(crate) struct Breach {
    /// Transaction that triggered the breach.
    pub dispute_tx: Transaction,
    /// Transaction that will be used as a response to the breach.
    pub penalty_tx: Transaction,
}

impl Breach {
    /// Creates a new [Breach] instance.
    pub fn new(dispute_tx: Transaction, penalty_tx: Transaction) -> Self {
        Breach {
            dispute_tx,
            penalty_tx,
        }
    }
}

/// Packs the reasons why trying to add an appointment may fail.
// TODO: It may be nice to create richer errors so the API can return richer rejection
#[derive(Debug)]
pub(crate) enum AddAppointmentFailure {
    AuthenticationFailure,
    NotEnoughSlots,
    SubscriptionExpired(u32),
    AlreadyTriggered,
}

/// Packs the reasons why trying to query an appointment may fail.
#[derive(Debug)]
pub(crate) enum GetAppointmentFailure {
    AuthenticationFailure,
    SubscriptionExpired(u32),
    NotFound,
}

/// Packs the reasons why trying to query a subscription info may fail.
#[derive(Debug)]
pub(crate) enum GetSubscriptionInfoFailure {
    AuthenticationFailure,
    SubscriptionExpired(u32),
}

/// Wraps the returning information regarding a queried appointment.
///
/// Either an [Appointment] or a [TransactionTracker] can be
/// returned depending on whether the appointment can be found in the [Watcher] or in the [Responder].
#[derive(Debug)]
pub(crate) enum AppointmentInfo {
    Appointment(Appointment),
    Tracker(TransactionTracker),
}

/// Types of new appointments stored in the [Watcher].
#[derive(Debug, PartialEq, Eq)]
enum StoredAppointment {
    New,
    Update,
}

/// Types of new triggered appointments handled by the [Watcher].
#[derive(Debug, PartialEq, Eq)]
enum TriggeredAppointment {
    Accepted,
    Rejected,
    Invalid,
}

/// Component in charge of watching for triggers in the chain (aka channel breaches for lightning).
#[derive(Debug)]
pub struct Watcher {
    /// A cache of the [Locator]s computed for the transactions in the last few blocks.
    locator_cache: Mutex<TxIndex<Locator, Transaction>>,
    /// A [Responder] instance. Data will be passed to it once triggered (if valid).
    responder: Arc<Responder>,
    /// A [Gatekeeper] instance. Data regarding users is requested to it.
    gatekeeper: Arc<Gatekeeper>,
    /// The last known block height.
    last_known_block_height: AtomicU32,
    /// The tower signing key. Used to sign messages going to users.
    signing_key: SecretKey,
    /// The tower identifier.
    pub tower_id: TowerId,
    /// A [DBM] (database manager) instance. Used to persist appointment data into disk.
    dbm: Arc<Mutex<DBM>>,
}

impl Watcher {
    /// Creates a new [Watcher] instance.
    pub fn new(
        gatekeeper: Arc<Gatekeeper>,
        responder: Arc<Responder>,
        last_n_blocks: &[ValidatedBlock],
        last_known_block_height: u32,
        signing_key: SecretKey,
        tower_id: TowerId,
        dbm: Arc<Mutex<DBM>>,
    ) -> Self {
        Watcher {
            locator_cache: Mutex::new(TxIndex::new(last_n_blocks, last_known_block_height)),
            responder,
            gatekeeper,
            last_known_block_height: AtomicU32::new(last_known_block_height),
            signing_key,
            tower_id,
            dbm,
        }
    }

    /// Returns whether the [Watcher] has been created from scratch (fresh) or from backed-up data.
    pub fn is_fresh(&self) -> bool {
        self.get_appointments_count() == 0
    }

    /// Registers a new user within the [Watcher]. This request is passed to the [Gatekeeper], who is in
    /// charge of managing users.
    pub(crate) fn register(&self, user_id: UserId) -> Result<RegistrationReceipt, MaxSlotsReached> {
        let mut receipt = self.gatekeeper.add_update_user(user_id)?;
        receipt.sign(&self.signing_key);

        Ok(receipt)
    }

    /// Adds a new [Appointment] to the tower.
    ///
    /// Appointments are only added provided:
    /// - The user is registered into the system
    /// - The user subscription has not expired
    /// - The user has enough available slots to fit the appointment
    /// - The appointment hasn't been responded to yet (data cannot be found in the [Responder])
    ///
    /// If an appointment is accepted, an [ExtendedAppointment] (constructed from the [Appointment]) will be persisted on disk.
    /// In case the locator for the given appointment can be found in the cache (meaning the appointment has been
    /// triggered recently) the data will be passed to the [Responder] straightaway (modulo it being valid).
    pub(crate) fn add_appointment(
        &self,
        appointment: Appointment,
        user_signature: String,
    ) -> Result<(AppointmentReceipt, u32, u32), AddAppointmentFailure> {
        let user_id = self
            .gatekeeper
            .authenticate_user(&appointment.to_vec(), &user_signature)
            .map_err(|_| AddAppointmentFailure::AuthenticationFailure)?;

        let (has_subscription_expired, expiry) =
            self.gatekeeper.has_subscription_expired(user_id).unwrap();

        if has_subscription_expired {
            return Err(AddAppointmentFailure::SubscriptionExpired(expiry));
        }

        let extended_appointment = ExtendedAppointment::new(
            appointment,
            user_id,
            user_signature,
            self.last_known_block_height.load(Ordering::Acquire),
        );

        let uuid = extended_appointment.uuid();

        if self.responder.has_tracker(uuid) {
            log::info!("Tracker for {uuid} already found in Responder");
            return Err(AddAppointmentFailure::AlreadyTriggered);
        }

        // TODO: This is not atomic, we update the users slots and THEN add their appointment
        // this means it can happen that we update the slots but some failure happens before we insert their appointment.
        let available_slots = self
            .gatekeeper
            .add_update_appointment(user_id, uuid, &extended_appointment)
            .map_err(|_| AddAppointmentFailure::NotEnoughSlots)?;

        // FIXME: There's an edge case here if store_triggered_appointment is called and bitcoind is unreachable.
        // This will hang, the request will timeout but be accepted. However, the user will not be handed the receipt.
        // This could be fixed adding a thread to take care of storing while the main thread returns the receipt.
        // Not fixing this atm since working with threads that call self.method is surprisingly non-trivial.
        match self
            .locator_cache
            .lock()
            .unwrap()
            .get(&extended_appointment.locator())
        {
            // Appointments that were triggered in blocks held in the cache
            Some(dispute_tx) => {
                self.store_triggered_appointment(uuid, &extended_appointment, user_id, dispute_tx);
            }
            // Regular appointments that have not been triggered (or, at least, not recently)
            None => {
                self.store_appointment(uuid, &extended_appointment);
            }
        };

        let mut receipt = AppointmentReceipt::new(
            extended_appointment.user_signature,
            extended_appointment.start_block,
        );
        receipt.sign(&self.signing_key);

        Ok((receipt, available_slots, expiry))
    }

    /// Stores an appointment in the database (or updates it if it already exists).
    fn store_appointment(
        &self,
        uuid: UUID,
        appointment: &ExtendedAppointment,
    ) -> StoredAppointment {
        let dbm = self.dbm.lock().unwrap();
        if dbm.appointment_exists(uuid) {
            log::debug!(
                "User {} is updating appointment {uuid}",
                appointment.user_id
            );
            dbm.update_appointment(uuid, appointment).unwrap();
            StoredAppointment::Update
        } else {
            dbm.store_appointment(uuid, appointment).unwrap();
            StoredAppointment::New
        }
    }

    /// Stores and already triggered appointment in the database and hands it to the [Responder].
    ///
    /// If the appointment is rejected by the [Responder] (i.e. for being invalid), the data is wiped
    /// from the database but the slot is not freed.
    fn store_triggered_appointment(
        &self,
        uuid: UUID,
        appointment: &ExtendedAppointment,
        user_id: UserId,
        dispute_tx: &Transaction,
    ) -> TriggeredAppointment {
        log::info!(
            "Trigger for locator {} found in cache",
            appointment.locator()
        );
        match cryptography::decrypt(appointment.encrypted_blob(), &dispute_tx.compute_txid()) {
            Ok(penalty_tx) => {
                // Data needs to be added the database straightaway since appointments are
                // FKs to trackers. If handle breach fails, data will be deleted later.
                self.dbm
                    .lock()
                    .unwrap()
                    .store_appointment(uuid, appointment)
                    // TODO: Don't unwrap, or better, make this insertion atomic with the
                    // `responder.has_tracker` that might cause the unwrap in the first place.
                    // ref: https://github.com/talaia-labs/rust-teos/pull/190#discussion_r1218235632
                    .unwrap();

                if let ConfirmationStatus::Rejected(reason) = self.responder.handle_breach(
                    uuid,
                    Breach::new(dispute_tx.clone(), penalty_tx),
                    user_id,
                ) {
                    log::warn!("Appointment bounced in the Responder. Reason: {reason:?}");
                    self.gatekeeper.delete_appointments(vec![uuid], false);
                    TriggeredAppointment::Rejected
                } else {
                    log::info!("Appointment went straight to the Responder");
                    TriggeredAppointment::Accepted
                }
            }

            // DISCUSS: Check if this makes sense or if we should just drop the data altogether
            // If data inside the encrypted blob is invalid, the appointment is accepted but the data is dropped.
            // (same as with data that bounces in the Responder). This reduces the appointment slot count so it
            // could be used to discourage user misbehavior.
            Err(_) => {
                log::info!(
                    "The appointment contained invalid data {}",
                    appointment.locator()
                );
                TriggeredAppointment::Invalid
            }
        }
    }

    /// Retrieves an [Appointment] from the tower.
    ///
    /// Appointments can only be retrieved provided:
    /// - The user is registered into the system
    /// - The user subscription has not expired
    /// - The appointment belongs to the user
    /// - The appointment exists within the system (either in the [Watcher] or the [Responder])
    pub(crate) fn get_appointment(
        &self,
        locator: Locator,
        user_signature: &str,
    ) -> Result<AppointmentInfo, GetAppointmentFailure> {
        let message = format!("get appointment {locator}");

        let user_id = self
            .gatekeeper
            .authenticate_user(message.as_bytes(), user_signature)
            .map_err(|_| GetAppointmentFailure::AuthenticationFailure)?;

        let (has_subscription_expired, expiry) =
            self.gatekeeper.has_subscription_expired(user_id).unwrap();

        if has_subscription_expired {
            return Err(GetAppointmentFailure::SubscriptionExpired(expiry));
        }

        let uuid = UUID::new(locator, user_id);
        let dbm = self.dbm.lock().unwrap();
        dbm.load_tracker(uuid)
            .map(AppointmentInfo::Tracker)
            .or_else(|| {
                dbm.load_appointment(uuid)
                    .map(|ext_app| AppointmentInfo::Appointment(ext_app.inner))
            })
            .ok_or_else(|| {
                log::info!("Cannot find {locator}");
                GetAppointmentFailure::NotFound
            })
    }

    /// Gets a map of breaches provided a map between locators and transactions.
    ///
    /// The provided map if intersected with the map of all locators monitored by [Watcher] and the result
    /// is considered the list of all breaches. This is queried on a per-block basis with all the
    /// `(locator, transaction)` pairs computed from the transaction data.
    fn get_breaches(
        &self,
        locator_tx_map: HashMap<Locator, Transaction>,
    ) -> HashMap<Locator, Transaction> {
        let breaches: HashMap<Locator, Transaction> = self
            .dbm
            .lock()
            .unwrap()
            .batch_check_locators_exist(locator_tx_map.keys().collect())
            .iter()
            .map(|locator| (*locator, locator_tx_map[locator].clone()))
            .collect();

        if breaches.is_empty() {
            log::info!("No breaches found")
        } else {
            log::debug!("List of breaches: {:?}", breaches.keys());
        }

        breaches
    }

    /// Responds to breaches.
    ///
    /// Decrypts triggered appointments using the dispute transaction ID and publishes them.
    /// If the decryption fails for some appointments or if it succeeds but they get rejected when sent to the network,
    /// they are marked as an invalid breaches and returned.
    /// [None] is returned if none of these breaches are invalid.
    fn handle_breaches(&self, breaches: HashMap<Locator, Transaction>) -> Option<Vec<UUID>> {
        let mut invalid_breaches = Vec::new();

        for (locator, dispute_tx) in breaches.into_iter() {
            // WARNING(deadlock): Don't lock `self.dbm` over the loop since `Responder::handle_breach` uses it as well.
            let uuids = self.dbm.lock().unwrap().load_uuids(locator);
            for uuid in uuids {
                let appointment = self.dbm.lock().unwrap().load_appointment(uuid).unwrap();
                match cryptography::decrypt(
                    appointment.encrypted_blob(),
                    &dispute_tx.compute_txid(),
                ) {
                    Ok(penalty_tx) => {
                        if let ConfirmationStatus::Rejected(_) = self.responder.handle_breach(
                            uuid,
                            Breach::new(dispute_tx.clone(), penalty_tx),
                            appointment.user_id,
                        ) {
                            invalid_breaches.push(uuid);
                        }
                    }
                    Err(_) => {
                        invalid_breaches.push(uuid);
                    }
                }
            }
        }

        (!invalid_breaches.is_empty()).then_some(invalid_breaches)
    }

    /// Ges the number of users currently registered with the tower.
    pub(crate) fn get_registered_users_count(&self) -> usize {
        self.gatekeeper.get_registered_users_count()
    }

    /// Gets the total number of appointments excluding trackers.
    pub(crate) fn get_appointments_count(&self) -> usize {
        self.dbm.lock().unwrap().get_appointments_count()
    }

    /// Gets the total number of trackers in the [Responder].
    pub(crate) fn get_trackers_count(&self) -> usize {
        self.responder.get_trackers_count()
    }

    /// Gets all the appointments stored in the [Watcher] (from the database).
    pub(crate) fn get_all_watcher_appointments(&self) -> HashMap<UUID, ExtendedAppointment> {
        self.dbm.lock().unwrap().load_appointments(None)
    }

    /// Gets all the appointments matching a specific locator from the [Watcher] (from the database).
    pub(crate) fn get_watcher_appointments_with_locator(
        &self,
        locator: Locator,
    ) -> HashMap<UUID, ExtendedAppointment> {
        self.dbm.lock().unwrap().load_appointments(Some(locator))
    }

    /// Gets all the trackers stored in the [Responder] (from the database).
    pub(crate) fn get_all_responder_trackers(&self) -> HashMap<UUID, TransactionTracker> {
        self.dbm.lock().unwrap().load_trackers(None)
    }

    /// Gets all the trackers matching s specific locator from the [Responder] (from the database).
    pub(crate) fn get_responder_trackers_with_locator(
        &self,
        locator: Locator,
    ) -> HashMap<UUID, TransactionTracker> {
        self.dbm.lock().unwrap().load_trackers(Some(locator))
    }

    /// Gets the list of all registered user ids.
    pub(crate) fn get_user_ids(&self) -> Vec<UserId> {
        self.gatekeeper.get_user_ids()
    }

    /// Gets the data held by the tower about a given user.
    pub(crate) fn get_user_info(&self, user_id: UserId) -> Option<(UserInfo, Vec<Locator>)> {
        self.gatekeeper.get_user_info(user_id)
    }

    /// Gets information about a user's subscription.
    pub(crate) fn get_subscription_info(
        &self,
        signature: &str,
    ) -> Result<(UserInfo, Vec<Locator>), GetSubscriptionInfoFailure> {
        let message = "get subscription info".to_string();

        let user_id = self
            .gatekeeper
            .authenticate_user(message.as_bytes(), signature)
            .map_err(|_| GetSubscriptionInfoFailure::AuthenticationFailure)?;

        let (has_subscription_expired, expiry) =
            self.gatekeeper.has_subscription_expired(user_id).unwrap();

        if has_subscription_expired {
            return Err(GetSubscriptionInfoFailure::SubscriptionExpired(expiry));
        }

        let (subscription_info, locators) = self.gatekeeper.get_user_info(user_id).unwrap();
        Ok((subscription_info, locators))
    }
}

/// Listen implementation by the [Watcher]. Handles monitoring and reorgs.
impl chain::Listen for Watcher {
    /// Handles the monitoring process by the [Watcher].
    ///
    /// Watching is performed in a per-block basis. Therefore, a breach is only considered (and detected) if seen
    /// in a block.
    ///
    /// Every time a new block is received a list of all potential locators is computed using the transaction data.
    /// Then, the potential locators are checked against the data being monitored by the [Watcher] and passed to the
    /// [Responder] if valid. Otherwise data is removed from the tower.
    ///
    /// This also takes care of updating the [LocatorCache] and removing outdated data from the [Watcher] when
    /// told by the [Gatekeeper].
    fn filtered_block_connected(
        &self,
        header: &Header,
        txdata: &chain::transaction::TransactionData,
        height: u32,
    ) {
        log::info!("New block received: {}", header.block_hash());

        let locator_tx_map = txdata
            .iter()
            .map(|(_, tx)| (Locator::new(tx.compute_txid()), (*tx).clone()))
            .collect();

        self.locator_cache
            .lock()
            .unwrap()
            .update(*header, &locator_tx_map);

        // Get the breaches found in this block, handle them, and delete invalid ones.
        if let Some(invalid_breaches) = self.handle_breaches(self.get_breaches(locator_tx_map)) {
            self.gatekeeper.delete_appointments(invalid_breaches, false);
        }

        // Update last known block
        self.last_known_block_height
            .store(height, Ordering::Release);
    }

    /// Handle reorgs in the [Watcher].
    ///
    /// Fixes the [LocatorCache] by removing the disconnected data and updates the last_known_block_height.
    fn block_disconnected(&self, header: &Header, height: u32) {
        log::warn!("Block disconnected: {}", header.block_hash());
        self.locator_cache
            .lock()
            .unwrap()
            .remove_disconnected_block(&header.block_hash());
        self.last_known_block_height
            .store(height - 1, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::iter::FromIterator;
    use std::ops::Deref;
    use std::sync::{Arc, Mutex};

    use crate::dbm::DBM;
    use crate::responder::ConfirmationStatus;
    use crate::rpc_errors;
    use crate::test_utils::{
        create_carrier, create_responder, create_watcher, generate_dummy_appointment,
        generate_dummy_appointment_with_user, get_random_tx, BitcoindMock, BitcoindStopper,
        Blockchain, MockOptions, MockedServerQuery, DURATION, EXPIRY_DELTA, SLOTS, START_HEIGHT,
    };
    use teos_common::cryptography::get_random_keypair;

    use bitcoin::secp256k1::{PublicKey, Secp256k1};

    use lightning::chain::Listen;

    impl PartialEq for Watcher {
        fn eq(&self, other: &Self) -> bool {
            // Same in-memory data.
            self.last_known_block_height.load(Ordering::Relaxed) == other.last_known_block_height.load(Ordering::Relaxed) &&
            *self.locator_cache.lock().unwrap() == *other.locator_cache.lock().unwrap() &&
            // && Same DB data.
            self.get_all_watcher_appointments() == other.get_all_watcher_appointments()
        }
    }
    impl Eq for Watcher {}

    impl Watcher {
        pub(crate) fn add_dummy_tracker_to_responder(&self, tracker: &TransactionTracker) {
            self.responder.add_dummy_tracker(tracker)
        }

        pub(crate) fn add_random_tracker_to_responder(&self) -> TransactionTracker {
            // The confirmation status can be whatever here. Using the most common.
            self.responder
                .add_random_tracker(ConfirmationStatus::ConfirmedIn(100))
        }
    }

    async fn init_watcher(chain: &mut Blockchain) -> (Watcher, BitcoindStopper) {
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        init_watcher_with_db(chain, dbm).await
    }

    async fn init_watcher_with_db(
        chain: &mut Blockchain,
        dbm: Arc<Mutex<DBM>>,
    ) -> (Watcher, BitcoindStopper) {
        let bitcoind_mock = BitcoindMock::new(MockOptions::default());

        let gk = Arc::new(Gatekeeper::new(
            chain.get_block_count(),
            SLOTS,
            DURATION,
            EXPIRY_DELTA,
            dbm.clone(),
        ));
        let responder = create_responder(chain, gk.clone(), dbm.clone(), bitcoind_mock.url()).await;
        create_watcher(
            chain,
            Arc::new(responder),
            gk.clone(),
            bitcoind_mock,
            dbm.clone(),
        )
        .await
    }

    fn assert_appointment_added(
        slots: u32,
        expected_slots: u32,
        expiry: u32,
        receipt: AppointmentReceipt,
        expected_user_signature: &str,
        tower_id: TowerId,
    ) {
        assert_eq!(slots, expected_slots);
        assert_eq!(expiry, START_HEIGHT as u32 + DURATION);
        assert_eq!(receipt.start_block(), START_HEIGHT as u32);
        assert_eq!(receipt.user_signature(), expected_user_signature);
        let recovered_pk =
            cryptography::recover_pk(&receipt.to_vec(), &receipt.signature().unwrap()).unwrap();
        assert_eq!(TowerId(recovered_pk), tower_id);
    }

    #[tokio::test]
    async fn test_new() {
        // A fresh watcher has no associated data
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let (watcher, _s) = init_watcher_with_db(&mut chain, dbm.clone()).await;
        assert!(watcher.is_fresh());

        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();

        // If we add some appointments to the system and create a new Watcher reusing the same db
        // (as if simulating a bootstrap from existing data), the data should be properly loaded.
        for _ in 0..10 {
            let appointment = generate_dummy_appointment(None).inner;
            let user_sig = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();
            watcher
                .add_appointment(appointment.clone(), user_sig.clone())
                .unwrap();
        }

        // Create a new Responder reusing the same DB and check that the data is loaded
        let (another_w, _as) = init_watcher_with_db(&mut chain, dbm).await;
        assert!(!another_w.is_fresh());
        assert_eq!(watcher, another_w);
    }

    #[tokio::test]
    async fn test_register() {
        // register calls Gatekeeper::add_update_user and signs the UserInfo returned by it.
        // Not testing the update / rejection logic, since that's already covered in the Gatekeeper, just that the data makes
        // sense and the signature verifies.
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let (watcher, _s) = init_watcher(&mut chain).await;
        let tower_pk = watcher.tower_id.0;

        let (_, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        let receipt = watcher.register(user_id).unwrap();

        assert_eq!(receipt.user_id(), user_id);
        assert_eq!(receipt.available_slots(), SLOTS);
        assert_eq!(
            receipt.subscription_expiry(),
            START_HEIGHT as u32 + DURATION
        );

        assert!(cryptography::verify(
            &receipt.to_vec(),
            &receipt.signature().unwrap(),
            &tower_pk
        ));
    }

    #[tokio::test]
    async fn test_add_appointment() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, 10);
        let tip_txs = chain.blocks.last().unwrap().txdata.clone();
        let (watcher, _s) = init_watcher(&mut chain).await;

        // add_appointment should add a given appointment to the Watcher given the following logic:
        //      - if the appointment does not exist for a given user, add the appointment
        //      - if the appointment already exists for a given user, update the data
        //      - if the appointment is already in the Responder, reject
        //      - if the trigger for the appointment is in the cache, trigger straightaway
        // In any of the cases where the appointment should be added to the Watcher, the appointment will be rejected if:
        //      - the user does not have enough slots (either to add or update)
        //      - the subscription has expired

        let tower_id = TowerId(PublicKey::from_secret_key(
            &Secp256k1::new(),
            &watcher.signing_key,
        ));
        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();
        let appointment = generate_dummy_appointment(None).inner;
        let user_sig = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();

        // Add the appointment for a new user (twice so we can check that updates work)
        for _ in 0..2 {
            let (receipt, slots, expiry) = watcher
                .add_appointment(appointment.clone(), user_sig.clone())
                .unwrap();

            assert_appointment_added(slots, SLOTS - 1, expiry, receipt, &user_sig, tower_id);
        }

        // Add the same appointment but for another user
        let (user2_sk, user2_pk) = get_random_keypair();
        let user2_id = UserId(user2_pk);
        watcher.register(user2_id).unwrap();

        let user2_sig = cryptography::sign(&appointment.to_vec(), &user2_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(appointment.clone(), user2_sig.clone())
            .unwrap();

        assert_appointment_added(slots, SLOTS - 1, expiry, receipt, &user2_sig, tower_id);

        // There should be now two appointments in the Watcher
        assert_eq!(watcher.get_appointments_count(), 2);
        assert_eq!(watcher.responder.get_trackers_count(), 0);

        // If an appointment is already in the Responder, it should bounce
        let dispute_tx = get_random_tx();
        let (uuid, triggered_appointment) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.compute_txid()));
        let signature =
            cryptography::sign(&triggered_appointment.inner.to_vec(), &user_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(triggered_appointment.inner.clone(), signature.clone())
            .unwrap();

        assert_appointment_added(slots, SLOTS - 2, expiry, receipt, &signature, tower_id);
        assert_eq!(watcher.get_appointments_count(), 3);
        assert_eq!(watcher.responder.get_trackers_count(), 0);

        let breach = Breach::new(dispute_tx, get_random_tx());
        watcher.responder.add_tracker(
            uuid,
            breach,
            user_id,
            ConfirmationStatus::InMempoolSince(chain.get_block_count()),
        );
        let receipt = watcher.add_appointment(triggered_appointment.inner, signature);

        assert!(matches!(
            receipt,
            Err(AddAppointmentFailure::AlreadyTriggered)
        ));
        assert_eq!(watcher.get_appointments_count(), 2);
        assert_eq!(watcher.responder.get_trackers_count(), 1);

        // If the trigger is already in the cache, the appointment will go straight to the Responder
        let dispute_tx = tip_txs.last().unwrap();
        let (uuid, appointment_in_cache) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.compute_txid()));
        let user_sig = cryptography::sign(&appointment_in_cache.inner.to_vec(), &user_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(appointment_in_cache.inner, user_sig.clone())
            .unwrap();

        // The appointment should have been accepted, slots should have been decreased, and a new tracker should be found in the Responder
        assert_appointment_added(slots, SLOTS - 3, expiry, receipt, &user_sig, tower_id);
        assert_eq!(watcher.get_appointments_count(), 2);
        assert_eq!(watcher.responder.get_trackers_count(), 2);
        // Data should be in the database
        assert!(watcher.responder.has_tracker(uuid));

        // If an appointment is rejected by the Responder, it is considered misbehavior and the slot count is kept
        // Wrong penalty
        let dispute_tx = &tip_txs[tip_txs.len() - 2];
        let (uuid, mut invalid_appointment) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.compute_txid()));
        invalid_appointment.inner.encrypted_blob.reverse();
        let user_sig = cryptography::sign(&invalid_appointment.inner.to_vec(), &user_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(invalid_appointment.inner, user_sig.clone())
            .unwrap();

        assert_appointment_added(slots, SLOTS - 4, expiry, receipt, &user_sig, tower_id);
        assert_eq!(watcher.get_appointments_count(), 2);
        assert_eq!(watcher.responder.get_trackers_count(), 2);
        // Data should not be in the database
        assert!(!watcher.responder.has_tracker(uuid));
        assert!(!watcher.dbm.lock().unwrap().appointment_exists(uuid));

        // Transaction rejected
        // Update the Responder with a new Carrier
        let (carrier, _as) = create_carrier(
            MockedServerQuery::Error(rpc_errors::RPC_VERIFY_ERROR as i64),
            chain.tip().deref().height,
        );
        *watcher.responder.get_carrier().lock().unwrap() = carrier;

        let dispute_tx = &tip_txs[tip_txs.len() - 2];
        let (uuid, invalid_appointment) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.compute_txid()));
        let user_sig = cryptography::sign(&invalid_appointment.inner.to_vec(), &user_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(invalid_appointment.inner, user_sig.clone())
            .unwrap();

        assert_appointment_added(slots, SLOTS - 5, expiry, receipt, &user_sig, tower_id);
        assert_eq!(watcher.get_appointments_count(), 2);
        assert_eq!(watcher.responder.get_trackers_count(), 2);
        // Data should not be in the database
        assert!(!watcher.responder.has_tracker(uuid));
        assert!(!watcher.dbm.lock().unwrap().appointment_exists(uuid));

        // FAIL cases (non-registered, subscription expired and not enough slots)

        // If the user is not registered, trying to add an appointment should fail. Since user_ids are
        // computed using ECRecovery, we can simulate a non-registered user by creating a "random" signature
        let user3_sig = String::from_utf8((0..65).collect()).unwrap();

        assert!(matches!(
            watcher.add_appointment(appointment, user3_sig),
            Err(AddAppointmentFailure::AuthenticationFailure)
        ));
        // Data should not be in the database
        assert!(!watcher.dbm.lock().unwrap().appointment_exists(uuid));

        // If the user has no enough slots, the appointment is rejected. We do not test all possible cases since updates are
        // already tested int he Gatekeeper. Testing that it is  rejected if the condition is met should suffice.
        watcher
            .gatekeeper
            .get_registered_users()
            .lock()
            .unwrap()
            .get_mut(&user_id)
            .unwrap()
            .available_slots = 0;

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        let signature = cryptography::sign(&appointment.inner.to_vec(), &user_sk).unwrap();

        assert!(matches!(
            watcher.add_appointment(appointment.inner, signature),
            Err(AddAppointmentFailure::NotEnoughSlots)
        ));
        // Data should not be in the database
        assert!(!watcher.dbm.lock().unwrap().appointment_exists(uuid));

        // If the user subscription has expired, the appointment should be rejected.
        watcher
            .gatekeeper
            .add_outdated_user(user2_id, START_HEIGHT as u32);

        let (uuid, appointment) = generate_dummy_appointment_with_user(user2_id, None);
        let signature = cryptography::sign(&appointment.inner.to_vec(), &user2_sk).unwrap();

        assert!(matches!(
            watcher.add_appointment(appointment.inner, signature),
            Err(AddAppointmentFailure::SubscriptionExpired { .. })
        ));
        // Data should not be in the database
        assert!(!watcher.dbm.lock().unwrap().appointment_exists(uuid));
    }

    #[tokio::test]
    async fn test_store_appointment() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let (watcher, _s) = init_watcher(&mut chain).await;

        // Register the user
        let (_, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();
        let dispute_txid = get_random_tx().compute_txid();

        let (uuid, appointment) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_txid));

        // Storing a new appointment should return New
        assert_eq!(
            watcher.store_appointment(uuid, &appointment),
            StoredAppointment::New,
        );
        assert_eq!(
            watcher.get_all_watcher_appointments(),
            HashMap::from_iter([(uuid, appointment)])
        );

        // Adding an appointment with the same UUID should be seen as an updated
        // We are using a common dispute txid here to get the same uuid.
        let (new_uuid, appointment) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_txid));
        assert_eq!(new_uuid, uuid);
        assert_eq!(
            watcher.store_appointment(uuid, &appointment),
            StoredAppointment::Update,
        );
        assert_eq!(
            watcher.get_all_watcher_appointments(),
            HashMap::from_iter([(uuid, appointment)])
        );
    }

    #[tokio::test]
    async fn test_store_triggered_appointment() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let (watcher, _s) = init_watcher(&mut chain).await;

        // Register the user
        let (_, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();

        let dispute_tx = get_random_tx();
        let (uuid, appointment) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.compute_txid()));

        // Valid triggered appointments should be accepted by the Responder
        assert_eq!(
            watcher.store_triggered_appointment(uuid, &appointment, user_id, &dispute_tx),
            TriggeredAppointment::Accepted,
        );
        // In this case the appointment is kept in the Responder and, therefore, in the database
        assert!(watcher.responder.has_tracker(uuid));
        assert!(watcher.dbm.lock().unwrap().appointment_exists(uuid));

        // A properly formatted but invalid transaction should be rejected by the Responder
        // Update the Responder with a new Carrier that will reject the transaction
        let (carrier, _as) = create_carrier(
            MockedServerQuery::Error(rpc_errors::RPC_VERIFY_ERROR as i64),
            chain.tip().deref().height,
        );
        *watcher.responder.get_carrier().lock().unwrap() = carrier;
        let dispute_tx = get_random_tx();
        let (uuid, appointment) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.compute_txid()));
        assert_eq!(
            watcher.store_triggered_appointment(uuid, &appointment, user_id, &dispute_tx),
            TriggeredAppointment::Rejected,
        );
        // In this case the appointment is not kept in the Responder nor in the database
        assert!(!watcher.responder.has_tracker(uuid));
        assert!(!watcher.dbm.lock().unwrap().appointment_exists(uuid));

        // Invalid triggered appointments should not be passed to the Responder
        // Use a dispute_tx that does not match the appointment to replicate a decryption error
        // (the same applies to invalid formatted transactions)
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        assert_eq!(
            watcher.store_triggered_appointment(uuid, &appointment, user_id, &dispute_tx),
            TriggeredAppointment::Invalid,
        );
        // The appointment is not kept anywhere
        assert!(!watcher.responder.has_tracker(uuid));
        assert!(!watcher.dbm.lock().unwrap().appointment_exists(uuid));
    }

    #[tokio::test]
    async fn test_get_appointment() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let (watcher, _s) = init_watcher(&mut chain).await;

        let dispute_tx = get_random_tx();
        let appointment = generate_dummy_appointment(Some(&dispute_tx.compute_txid())).inner;

        // If the user cannot be properly identified, the request will fail. This can be simulated by providing a wrong signature
        let wrong_sig = String::from_utf8((0..65).collect()).unwrap();
        assert!(matches!(
            watcher.get_appointment(appointment.locator, &wrong_sig),
            Err(GetAppointmentFailure::AuthenticationFailure)
        ));

        // If the user does exist and there's an appointment with the given locator belonging to him, it will be returned
        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();
        watcher
            .add_appointment(
                appointment.clone(),
                cryptography::sign(&appointment.to_vec(), &user_sk).unwrap(),
            )
            .unwrap();

        let message = format!("get appointment {}", appointment.locator);
        let signature = cryptography::sign(message.as_bytes(), &user_sk).unwrap();
        let info = watcher
            .get_appointment(appointment.locator, &signature)
            .unwrap();

        match info {
            AppointmentInfo::Appointment(a) => assert_eq!(a, appointment),
            AppointmentInfo::Tracker { .. } => {
                panic!("Should have received an appointment, not a tracker")
            }
        }

        // If the appointment is in the Responder (in the form of a Tracker), data should be also returned

        // Remove the data from the Watcher memory first.
        let uuid = UUID::new(appointment.locator, user_id);

        // Add data to the Responder
        let breach = Breach::new(dispute_tx, get_random_tx());
        let status = ConfirmationStatus::InMempoolSince(chain.get_block_count());
        watcher
            .responder
            .add_tracker(uuid, breach.clone(), user_id, status);
        let tracker = TransactionTracker::new(breach, user_id, status);

        let tracker_message = format!("get appointment {}", appointment.locator);
        let tracker_signature = cryptography::sign(tracker_message.as_bytes(), &user_sk).unwrap();
        let info = watcher
            .get_appointment(appointment.locator, &tracker_signature)
            .unwrap();

        match info {
            AppointmentInfo::Appointment { .. } => {
                panic!("Should have received an tracker, not an appointment")
            }
            AppointmentInfo::Tracker(t) => assert_eq!(t, tracker),
        }

        // If the user does exists but the requested locator does not belong to any of their associated appointments,
        // NotFound should be returned.
        let (user2_sk, user2_pk) = get_random_keypair();
        let user2_id = UserId(user2_pk);
        watcher.register(user2_id).unwrap();

        let signature2 = cryptography::sign(message.as_bytes(), &user2_sk).unwrap();
        assert!(matches!(
            watcher.get_appointment(appointment.locator, &signature2),
            Err(GetAppointmentFailure::NotFound { .. })
        ));

        // If the user subscription has expired, the request will fail
        watcher
            .gatekeeper
            .add_outdated_user(user_id, START_HEIGHT as u32);

        assert!(matches!(
            watcher.get_appointment(appointment.locator, &signature),
            Err(GetAppointmentFailure::SubscriptionExpired { .. })
        ));
    }

    #[tokio::test]
    async fn test_get_breaches() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, 10);
        let (watcher, _s) = init_watcher(&mut chain).await;

        // Let's create some locators based on the transactions in the last block
        let locator_tx_map: HashMap<_, _> = (0..10)
            .map(|_| get_random_tx())
            .map(|tx| (Locator::new(tx.compute_txid()), tx))
            .collect();

        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();

        // Add some of them to the Watcher
        let mut breaches = HashMap::new();
        for (i, (l, tx)) in locator_tx_map.iter().enumerate() {
            // Track some of the these transactions.
            if i % 2 == 0 {
                let appointment = generate_dummy_appointment(Some(&tx.compute_txid())).inner;
                let signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();
                watcher.add_appointment(appointment, signature).unwrap();
                breaches.insert(*l, tx.clone());
            }
        }

        // Check that breaches are correctly detected
        assert_eq!(watcher.get_breaches(locator_tx_map), breaches);
    }

    #[tokio::test]
    async fn test_handle_breaches_accepted() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, 10);
        let (watcher, _s) = init_watcher(&mut chain).await;

        // Let's create some locators based on the transactions in the last block
        let breaches: HashMap<_, _> = (0..10)
            .map(|_| get_random_tx())
            .map(|tx| (Locator::new(tx.compute_txid()), tx))
            .collect();

        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();

        // Let the watcher track these breaches.
        for (_, tx) in breaches.iter() {
            let appointment = generate_dummy_appointment(Some(&tx.compute_txid())).inner;
            let signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();
            watcher.add_appointment(appointment, signature).unwrap();
        }

        assert!(watcher.handle_breaches(breaches).is_none())
    }

    #[tokio::test]
    async fn test_handle_breaches_rejected_decryption() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, 10);
        let (watcher, _s) = init_watcher(&mut chain).await;

        // Let's create some locators based on the transactions in the last block
        let breaches: HashMap<_, _> = (0..10)
            .map(|_| get_random_tx())
            .map(|tx| (Locator::new(tx.compute_txid()), tx))
            .collect();

        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();

        let mut rejected = HashSet::new();
        // Let the watcher track these breaches.
        for (i, (_, tx)) in breaches.iter().enumerate() {
            let (uuid, appointment) =
                generate_dummy_appointment_with_user(user_id, Some(&tx.compute_txid()));
            let mut appointment = appointment.inner;
            if i % 2 == 0 {
                // Mal-format some appointments
                appointment.encrypted_blob.reverse();
                rejected.insert(uuid);
            };
            let signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();
            watcher.add_appointment(appointment, signature).unwrap();
        }

        assert_eq!(
            rejected,
            HashSet::from_iter(watcher.handle_breaches(breaches).unwrap())
        );
    }

    #[tokio::test]
    async fn test_handle_breaches_rejected_by_responder_backend() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, 10);
        let (watcher, _s) = init_watcher(&mut chain).await;

        // Replace the carrier with an erroneous one
        let (carrier, _s) = create_carrier(
            MockedServerQuery::Error(rpc_errors::RPC_VERIFY_ERROR as i64),
            chain.tip().deref().height,
        );
        *watcher.responder.get_carrier().lock().unwrap() = carrier;

        // Let's create some locators based on the transactions in the last block
        let breaches: HashMap<_, _> = (0..10)
            .map(|_| get_random_tx())
            .map(|tx| (Locator::new(tx.compute_txid()), tx))
            .collect();

        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();

        let mut uuids = HashSet::new();
        // Let the watcher track these breaches.
        for tx in breaches.values() {
            let (uuid, appointment) =
                generate_dummy_appointment_with_user(user_id, Some(&tx.compute_txid()));
            let appointment = appointment.inner;
            let signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();
            watcher.add_appointment(appointment, signature).unwrap();
            uuids.insert(uuid);
        }

        assert_eq!(
            uuids,
            HashSet::from_iter(watcher.handle_breaches(breaches).unwrap())
        );
    }

    #[tokio::test]
    async fn test_handle_breaches_rejected_by_responder_malformed() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, 10);
        let (watcher, _s) = init_watcher(&mut chain).await;

        // Let's create some locators based on the transactions in the last block
        let breaches: HashMap<_, _> = (0..10)
            .map(|_| get_random_tx())
            .map(|tx| (Locator::new(tx.compute_txid()), tx))
            .collect();

        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();

        let mut rejected_breaches = HashSet::new();
        // Let the watcher track these breaches.
        for (i, (_, tx)) in breaches.iter().enumerate() {
            let (uuid, appointment) =
                generate_dummy_appointment_with_user(user_id, Some(&tx.compute_txid()));
            let mut appointment = appointment.inner;
            if i % 2 == 0 {
                // Mal-format some appointments, they should be returned as rejected.
                appointment.encrypted_blob.reverse();
                rejected_breaches.insert(uuid);
            };
            let signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();
            watcher.add_appointment(appointment, signature).unwrap();
        }

        assert_eq!(
            rejected_breaches,
            HashSet::from_iter(watcher.handle_breaches(breaches).unwrap())
        );
    }

    #[tokio::test]
    async fn test_filtered_block_connected() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let (watcher, _s) = init_watcher(&mut chain).await;

        // block_connected for the Watcher is used to keep track of what new transactions has been mined whose may be potential
        // channel breaches.

        // If the Watcher is not watching any appointment, block_connected will only be used to keep track of the last known block
        // by the Watcher.
        assert_eq!(
            watcher.last_known_block_height.load(Ordering::Relaxed),
            chain.get_block_count()
        );
        watcher.block_connected(&chain.generate(None), chain.get_block_count());
        assert_eq!(
            watcher.last_known_block_height.load(Ordering::Relaxed),
            chain.get_block_count()
        );

        // If there are appointments to watch, the Watcher will:
        //  - Check if any new transaction is a trigger
        //      - Check if a trigger is valid, if so pass the data to the Responder
        //  - Delete invalid appointments (decryption error or rejection by responder).
        //  - Delete appointments that have been outdated (i.e. have expired without a trigger)
        //  - Delete invalid appointments also from the Gatekeeper
        //
        // We will also test that appointments for outdated users are removed by the GK.

        // Let's first check how data gets outdated (create two users, add an appointment to both and outdate only one)
        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        let (user2_sk, user2_pk) = get_random_keypair();
        let user2_id = UserId(user2_pk);
        watcher.register(user_id).unwrap();
        watcher.register(user2_id).unwrap();

        let appointment = generate_dummy_appointment(None).inner;
        let uuid1 = UUID::new(appointment.locator, user_id);
        let uuid2 = UUID::new(appointment.locator, user2_id);

        let user_sig = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();
        watcher
            .add_appointment(appointment.clone(), user_sig)
            .unwrap();
        let user2_sig = cryptography::sign(&appointment.to_vec(), &user2_sk).unwrap();
        watcher.add_appointment(appointment, user2_sig).unwrap();

        // Outdate the first user's registration.
        watcher
            .gatekeeper
            .add_outdated_user(user_id, chain.get_block_count());

        // Both appointments can be found before mining a block, only the user's 2 can be found afterwards
        for &uuid in &[uuid1, uuid2] {
            assert!(watcher.dbm.lock().unwrap().appointment_exists(uuid));
        }

        // We always need to connect the gatekeeper first so it cleans up outdated users and their data.
        let block = chain.generate(None);
        watcher
            .gatekeeper
            .block_connected(&block, chain.get_block_count());
        watcher.block_connected(&block, chain.get_block_count());

        // uuid1 and user1 should have been deleted while uuid2 and user2 still exists.
        assert!(!watcher.dbm.lock().unwrap().appointment_exists(uuid1));
        assert!(!watcher
            .gatekeeper
            .get_registered_users()
            .lock()
            .unwrap()
            .contains_key(&user_id));
        assert!(watcher.dbm.lock().unwrap().appointment_exists(uuid2));
        assert!(watcher
            .gatekeeper
            .get_registered_users()
            .lock()
            .unwrap()
            .contains_key(&user2_id));

        // Check triggers. Add a new appointment and trigger it with valid data.
        let dispute_tx = get_random_tx();
        let (uuid, appointment) =
            generate_dummy_appointment_with_user(user2_id, Some(&dispute_tx.compute_txid()));
        let sig = cryptography::sign(&appointment.inner.to_vec(), &user2_sk).unwrap();
        watcher.add_appointment(appointment.inner, sig).unwrap();

        assert!(watcher.dbm.lock().unwrap().appointment_exists(uuid));

        let block = chain.generate(Some(vec![dispute_tx]));
        watcher
            .gatekeeper
            .block_connected(&block, chain.get_block_count());
        watcher.block_connected(&block, chain.get_block_count());

        // Data should have been kept in the database
        assert!(watcher.responder.has_tracker(uuid));

        // Checks invalid triggers. Add a new appointment and trigger it with invalid data.
        let dispute_tx = get_random_tx();
        let (uuid, mut appointment) =
            generate_dummy_appointment_with_user(user2_id, Some(&dispute_tx.compute_txid()));
        // Modify the encrypted blob so the data is invalid.
        appointment.inner.encrypted_blob.reverse();
        let sig = cryptography::sign(&appointment.inner.to_vec(), &user2_sk).unwrap();
        watcher.add_appointment(appointment.inner, sig).unwrap();

        let block = chain.generate(Some(vec![dispute_tx]));
        watcher
            .gatekeeper
            .block_connected(&block, chain.get_block_count());
        watcher.block_connected(&block, chain.get_block_count());

        // Data should have been wiped from the database
        assert!(!watcher.responder.has_tracker(uuid));
        assert!(!watcher.dbm.lock().unwrap().appointment_exists(uuid));

        // Check triggering with a valid formatted transaction but that is rejected by the Responder.
        let dispute_tx = get_random_tx();
        let (uuid, appointment) =
            generate_dummy_appointment_with_user(user2_id, Some(&dispute_tx.compute_txid()));
        let sig = cryptography::sign(&appointment.inner.to_vec(), &user2_sk).unwrap();
        watcher.add_appointment(appointment.inner, sig).unwrap();

        // Set the carrier response
        // Both non-decryptable blobs and blobs with invalid transactions will yield an invalid trigger.
        let (carrier, _s) = create_carrier(
            MockedServerQuery::Error(rpc_errors::RPC_VERIFY_ERROR as i64),
            chain.tip().deref().height,
        );
        *watcher.responder.get_carrier().lock().unwrap() = carrier;

        let block = chain.generate(Some(vec![dispute_tx]));
        watcher
            .gatekeeper
            .block_connected(&block, chain.get_block_count());
        watcher.block_connected(&block, chain.get_block_count());

        // Data should have been wiped from the database
        assert!(!watcher.responder.has_tracker(uuid));
        assert!(!watcher.dbm.lock().unwrap().appointment_exists(uuid));
    }

    #[tokio::test]
    async fn test_block_disconnected() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let start_height = START_HEIGHT as u32;
        let (watcher, _s) = init_watcher(&mut chain).await;

        // block_disconnected for the Watcher fixes the locator cache by removing the disconnected block
        // and updates the last_known_block_height to the previous block height
        let last_block_header = chain.tip().deref().header;
        assert!(watcher
            .locator_cache
            .lock()
            .unwrap()
            .blocks()
            .contains(&last_block_header.block_hash()));

        watcher.block_disconnected(&last_block_header, start_height);

        assert_eq!(
            watcher.last_known_block_height.load(Ordering::Relaxed),
            start_height - 1
        );
        assert!(!watcher
            .locator_cache
            .lock()
            .unwrap()
            .blocks()
            .contains(&last_block_header.block_hash()));
    }
}
