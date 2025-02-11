//! Logic related to the Gatekeeper, the component in charge of managing access to the tower resources.

use lightning::chain;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use teos_common::appointment::{compute_appointment_slots, Locator};
use teos_common::constants::ENCRYPTED_BLOB_MAX_SIZE;
use teos_common::cryptography;
use teos_common::receipts::RegistrationReceipt;
use teos_common::UserId;

use crate::dbm::DBM;
use crate::extended_appointment::{ExtendedAppointment, UUID};

/// Data regarding a user subscription with the tower.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UserInfo {
    /// Number of appointment slots available for a given user.
    pub(crate) available_slots: u32,
    /// Block height where the user subscription starts.
    pub(crate) subscription_start: u32,
    /// Block height where the user subscription expires.
    pub(crate) subscription_expiry: u32,
}

impl UserInfo {
    /// Creates a new [UserInfo] instance.
    pub fn new(available_slots: u32, subscription_start: u32, subscription_expiry: u32) -> Self {
        UserInfo {
            available_slots,
            subscription_start,
            subscription_expiry,
        }
    }
}

/// Error raised if the user cannot be authenticated.
#[derive(Debug, PartialEq)]
pub(crate) struct AuthenticationFailure<'a>(&'a str);

/// Error raised if the user subscription has not enough slots to fit a new appointment.
#[derive(Debug, PartialEq)]
pub(crate) struct NotEnoughSlots;

/// Error raised if the user subscription slots limit has been reached.
///
/// This is currently set to [u32::MAX].
#[derive(Debug, PartialEq)]
pub(crate) struct MaxSlotsReached;

/// Component in charge of managing access to the tower resources.
///
/// The [Gatekeeper] keeps track of user subscriptions and allow users to interact with the tower based on it.
/// A user is only allowed to send/request data to/from the tower given they have an ongoing subscription with
/// available slots.
/// This is the only component in the system that has some knowledge regarding users, all other components do query the
/// [Gatekeeper] for such information.
#[derive(Debug)]
pub struct Gatekeeper {
    /// last known block header by the [Gatekeeper].
    last_known_block_height: AtomicU32,
    /// Number of slots new subscriptions get by default.
    subscription_slots: u32,
    /// Expiry time new subscription get by default, in blocks (starting from the block the subscription is requested).
    subscription_duration: u32,
    /// Grace period given to renew subscriptions, in blocks.
    expiry_delta: u32,
    /// Map of users registered within the tower.
    registered_users: Mutex<HashMap<UserId, UserInfo>>,
    /// A [DBM] (database manager) instance. Used to persist appointment data into disk.
    dbm: Arc<Mutex<DBM>>,
}

impl Gatekeeper {
    /// Creates a new [Gatekeeper] instance.
    pub fn new(
        last_known_block_height: u32,
        subscription_slots: u32,
        subscription_duration: u32,
        expiry_delta: u32,
        dbm: Arc<Mutex<DBM>>,
    ) -> Self {
        let registered_users = dbm.lock().unwrap().load_all_users();
        Gatekeeper {
            last_known_block_height: AtomicU32::new(last_known_block_height),
            subscription_slots,
            subscription_duration,
            expiry_delta,
            registered_users: Mutex::new(registered_users),
            dbm,
        }
    }

    /// Returns whether the [Gatekeeper] has been created from scratch (fresh) or from backed-up data.
    pub fn is_fresh(&self) -> bool {
        self.registered_users.lock().unwrap().is_empty()
    }

    /// Ges the number of users currently registered to the tower.
    pub(crate) fn get_registered_users_count(&self) -> usize {
        self.registered_users.lock().unwrap().len()
    }

    /// Gets the list of all registered user ids.
    pub(crate) fn get_user_ids(&self) -> Vec<UserId> {
        self.registered_users
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    /// Gets the data held by the tower about a given user.
    pub(crate) fn get_user_info(&self, user_id: UserId) -> Option<(UserInfo, Vec<Locator>)> {
        let info = self.registered_users.lock().unwrap().get(&user_id).cloned();
        info.map(|info| (info, self.dbm.lock().unwrap().load_user_locators(user_id)))
    }

    /// Authenticates a user.
    ///
    /// User authentication is performed using ECRecover against fixed messages (one for each command).
    /// Notice all interaction with the tower should be guarded by this.
    pub(crate) fn authenticate_user(
        &self,
        message: &[u8],
        signature: &str,
    ) -> Result<UserId, AuthenticationFailure> {
        let user_id = UserId(
            cryptography::recover_pk(message, signature)
                .map_err(|_| AuthenticationFailure("Wrong message or signature."))?,
        );

        if self.registered_users.lock().unwrap().contains_key(&user_id) {
            Ok(user_id)
        } else {
            Err(AuthenticationFailure("User not found."))
        }
    }

    /// Adds a new user to the tower (or updates its subscription if already registered).
    pub(crate) fn add_update_user(
        &self,
        user_id: UserId,
    ) -> Result<RegistrationReceipt, MaxSlotsReached> {
        let block_count = self.last_known_block_height.load(Ordering::Acquire);

        // TODO: For now, new calls to `add_update_user` add subscription_slots to the current count and reset the expiry time
        let mut registered_users = self.registered_users.lock().unwrap();
        let user_info = match registered_users.get_mut(&user_id) {
            // User already exists, updating the info
            Some(user_info) => {
                user_info.available_slots = user_info
                    .available_slots
                    .checked_add(self.subscription_slots)
                    .ok_or(MaxSlotsReached)?;
                user_info.subscription_expiry = user_info
                    .subscription_expiry
                    .checked_add(self.subscription_duration)
                    .unwrap_or(u32::MAX);
                self.dbm.lock().unwrap().update_user(user_id, user_info);

                user_info
            }
            // New user
            None => {
                let user_info = UserInfo::new(
                    self.subscription_slots,
                    block_count,
                    block_count + self.subscription_duration,
                );
                self.dbm
                    .lock()
                    .unwrap()
                    .store_user(user_id, &user_info)
                    .unwrap();

                registered_users.insert(user_id, user_info);
                registered_users.get_mut(&user_id).unwrap()
            }
        };

        Ok(RegistrationReceipt::new(
            user_id,
            user_info.available_slots,
            user_info.subscription_start,
            user_info.subscription_expiry,
        ))
    }

    /// Adds an appointment to a given user, or updates it if already present in the system (and belonging to the requester).
    pub(crate) fn add_update_appointment(
        &self,
        user_id: UserId,
        uuid: UUID,
        appointment: &ExtendedAppointment,
    ) -> Result<u32, NotEnoughSlots> {
        // For updates, the difference between the existing appointment size and the update is computed.
        let mut registered_users = self.registered_users.lock().unwrap();
        let user_info = registered_users.get_mut(&user_id).unwrap();
        let used_blob_size = self
            .dbm
            .lock()
            .unwrap()
            .get_appointment_length(uuid)
            .unwrap_or(0);
        let used_slots = compute_appointment_slots(used_blob_size, ENCRYPTED_BLOB_MAX_SIZE);

        let required_slots =
            compute_appointment_slots(appointment.encrypted_blob().len(), ENCRYPTED_BLOB_MAX_SIZE);

        let diff = required_slots as i64 - used_slots as i64;
        if diff <= user_info.available_slots as i64 {
            // Filling / freeing slots depending on whether this is an update or not, and if it is bigger or smaller
            // than the old appointment
            user_info.available_slots = (user_info.available_slots as i64 - diff) as u32;

            self.dbm.lock().unwrap().update_user(user_id, user_info);

            Ok(user_info.available_slots)
        } else {
            Err(NotEnoughSlots)
        }
    }

    /// Checks whether a subscription has expired.
    pub(crate) fn has_subscription_expired(
        &self,
        user_id: UserId,
    ) -> Result<(bool, u32), AuthenticationFailure<'_>> {
        self.registered_users.lock().unwrap().get(&user_id).map_or(
            Err(AuthenticationFailure("User not found.")),
            |user_info| {
                Ok((
                    self.last_known_block_height.load(Ordering::Acquire)
                        >= user_info.subscription_expiry,
                    user_info.subscription_expiry,
                ))
            },
        )
    }

    /// Gets a map of outdated users. Outdated users are those whose subscription has expired and the renewal grace period
    /// has already passed ([expiry_delta](Self::expiry_delta)).
    pub(crate) fn get_outdated_users(&self, block_height: u32) -> Vec<UserId> {
        self.registered_users
            .lock()
            .unwrap()
            .iter()
            // NOTE: Ideally there won't be a user with `block_height > subscription_expiry + expiry_delta`, but
            // this might happen if we skip a couple of block connections due to a force update.
            .filter(|(_, info)| block_height >= info.subscription_expiry + self.expiry_delta)
            .map(|(user_id, _)| *user_id)
            .collect()
    }

    /// Deletes these appointments from the database and updates the user's information.
    ///
    /// If `refund` is set, the appointments owners will get their slots refunded back.
    ///
    /// DISCUSS: When `refund` is `false` we don't give back the slots to the user for the deleted appointments.
    /// This is to discourage misbehavior (sending bad appointments, either non-decryptable or rejected by the network).
    pub(crate) fn delete_appointments(&self, appointments: Vec<UUID>, refund: bool) {
        let mut dbm = self.dbm.lock().unwrap();

        let updated_users = if refund {
            let mut updated_users = HashMap::new();
            let mut registered_users = self.registered_users.lock().unwrap();
            // Give back the consumed slots to each user.
            for uuid in appointments.iter() {
                let (user_id, blob_size) = dbm.get_appointment_user_and_length(*uuid).unwrap();
                registered_users.get_mut(&user_id).unwrap().available_slots +=
                    compute_appointment_slots(blob_size, ENCRYPTED_BLOB_MAX_SIZE);
                updated_users.insert(user_id, registered_users[&user_id]);
            }
            updated_users
        } else {
            // No updated users.
            HashMap::new()
        };

        // An optimization for the case when only one appointment is being deleted without refunding.
        // This avoids creating a DB transaction for a single query.
        if appointments.len() == 1 && updated_users.is_empty() {
            dbm.remove_appointment(appointments[0])
        } else {
            dbm.batch_remove_appointments(&appointments, &updated_users);
        }
    }
}

impl chain::Listen for Gatekeeper {
    /// Handles the monitoring process by the [Gatekeeper].
    ///
    /// This is mainly used to keep track of time and expire / outdate subscriptions when needed.
    fn filtered_block_connected(
        &self,
        header: &bitcoin::block::Header,
        _: &chain::transaction::TransactionData,
        height: u32,
    ) {
        log::info!("New block received: {}", header.block_hash());

        // Expired user deletion is delayed. Users are deleted when their subscription is outdated, not expired.
        let outdated_users = self.get_outdated_users(height);
        if !outdated_users.is_empty() {
            // Remove the outdated users from memory first.
            {
                let mut registered_users = self.registered_users.lock().unwrap();
                // Removing each outdated user in a loop is more efficient than retaining non-outdated users
                // because retaining would loop over all the available users which is always more than the outdated ones.
                for outdated_user in outdated_users.iter() {
                    registered_users.remove(outdated_user);
                }
            }
            self.dbm.lock().unwrap().batch_remove_users(&outdated_users);
        }

        // Update last known block height
        self.last_known_block_height
            .store(height, Ordering::Release);
    }

    /// Handles reorgs in the [Gatekeeper]. Simply updates the last_known_block_height.
    fn block_disconnected(&self, header: &bitcoin::block::Header, height: u32) {
        log::warn!("Block disconnected: {}", header.block_hash());
        // There's nothing to be done here but updating the last known block
        self.last_known_block_height
            .store(height - 1, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils::{generate_dummy_appointment_with_user, get_random_tracker, Blockchain};
    use lightning::chain::Listen;
    use teos_common::cryptography::{get_random_bytes, get_random_keypair};
    use teos_common::test_utils::get_random_user_id;

    use crate::responder::ConfirmationStatus;

    const SLOTS: u32 = 21;
    const DURATION: u32 = 500;
    const EXPIRY_DELTA: u32 = 42;
    const START_HEIGHT: usize = 100;

    impl PartialEq for Gatekeeper {
        fn eq(&self, other: &Self) -> bool {
            self.subscription_slots == other.subscription_slots
                && self.subscription_duration == other.subscription_duration
                && self.expiry_delta == other.expiry_delta
                && *self.registered_users.lock().unwrap() == *other.registered_users.lock().unwrap()
                && self.last_known_block_height.load(Ordering::Relaxed)
                    == other.last_known_block_height.load(Ordering::Relaxed)
        }
    }
    impl Eq for Gatekeeper {}

    impl Gatekeeper {
        pub(crate) fn get_registered_users(&self) -> &Mutex<HashMap<UserId, UserInfo>> {
            &self.registered_users
        }

        pub(crate) fn add_outdated_user(&self, user_id: UserId, outdates_at: u32) {
            self.add_update_user(user_id).unwrap();
            let mut registered_users = self.registered_users.lock().unwrap();
            let user = registered_users.get_mut(&user_id).unwrap();
            user.subscription_expiry = outdates_at - self.expiry_delta;
        }
    }

    fn init_gatekeeper(chain: &Blockchain) -> Gatekeeper {
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        Gatekeeper::new(chain.get_block_count(), SLOTS, DURATION, EXPIRY_DELTA, dbm)
    }

    #[test]
    fn test_new() {
        // A fresh gatekeeper has no associated data
        let chain = Blockchain::default().with_height(START_HEIGHT);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));

        let gatekeeper = Gatekeeper::new(
            chain.get_block_count(),
            SLOTS,
            DURATION,
            EXPIRY_DELTA,
            dbm.clone(),
        );
        assert!(gatekeeper.is_fresh());

        // If we add some users and appointments to the system and create a new Gatekeeper reusing the same db
        // (as if simulating a bootstrap from existing data), the data should be properly loaded.
        for _ in 0..10 {
            let user_id = get_random_user_id();
            gatekeeper.add_update_user(user_id).unwrap();

            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            gatekeeper
                .add_update_appointment(user_id, uuid, &appointment)
                .unwrap();
            // Add the appointment to the database. This is normally done by the Watcher.
            gatekeeper
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();
        }

        // Create a new GK reusing the same DB and check that the data is loaded
        let another_gk =
            Gatekeeper::new(chain.get_block_count(), SLOTS, DURATION, EXPIRY_DELTA, dbm);
        assert!(!another_gk.is_fresh());
        assert_eq!(gatekeeper, another_gk);
    }

    #[test]
    fn test_authenticate_user() {
        let gatekeeper = init_gatekeeper(&Blockchain::default().with_height(START_HEIGHT));

        // Authenticate user returns the UserId if the user is found in the system, or an AuthenticationError otherwise.

        // Let's first check with an unknown user
        let message = "message".as_bytes();
        let wrong_signature = "signature";
        assert_eq!(
            gatekeeper.authenticate_user(message, wrong_signature),
            Err(AuthenticationFailure("Wrong message or signature."))
        );

        // Let's now provide data generated by an actual user, still the user is unknown
        let (user_sk, user_pk) = get_random_keypair();
        let signature = cryptography::sign(message, &user_sk).unwrap();
        assert_eq!(
            gatekeeper.authenticate_user(message, &signature),
            Err(AuthenticationFailure("User not found."))
        );

        // Last, let's add the user to the Gatekeeper and try again.
        let user_id = UserId(user_pk);
        gatekeeper.add_update_user(user_id).unwrap();
        assert_eq!(
            gatekeeper.authenticate_user(message, &signature),
            Ok(user_id)
        );
    }

    #[test]
    fn test_add_update_user() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let gatekeeper = init_gatekeeper(&chain);

        // add_update_user adds a user to the system if it is not still registered, otherwise it add slots to the user subscription
        // and refreshes the subscription expiry. Slots are added up to u32:MAX, further call will return an MaxSlotsReached error.

        // Let's start by adding new user
        let user_id = get_random_user_id();
        let receipt = gatekeeper.add_update_user(user_id).unwrap();
        // The data should have been also added to the database
        assert_eq!(
            gatekeeper.dbm.lock().unwrap().load_user(user_id).unwrap(),
            UserInfo::new(
                receipt.available_slots(),
                receipt.subscription_start(),
                receipt.subscription_expiry()
            )
        );

        // Let generate a new block and add the user again to check that both the slots and expiry are updated.
        chain.generate(None);
        gatekeeper
            .last_known_block_height
            .store(chain.get_block_count(), Ordering::Relaxed);
        let updated_receipt = gatekeeper.add_update_user(user_id).unwrap();

        assert_eq!(updated_receipt.available_slots(), SLOTS * 2);
        assert_eq!(
            updated_receipt.subscription_expiry(),
            START_HEIGHT as u32 + DURATION * 2
        );

        // Data in the database should have been updated too
        assert_eq!(
            gatekeeper.dbm.lock().unwrap().load_user(user_id).unwrap(),
            UserInfo::new(
                updated_receipt.available_slots(),
                updated_receipt.subscription_start(),
                updated_receipt.subscription_expiry()
            )
        );

        // If the slot count reaches u32::MAX we should receive an error
        gatekeeper
            .registered_users
            .lock()
            .unwrap()
            .get_mut(&user_id)
            .unwrap()
            .available_slots = u32::MAX;

        assert!(matches!(
            gatekeeper.add_update_user(user_id),
            Err(MaxSlotsReached)
        ));

        // Data in the database remains untouched
        assert_eq!(
            gatekeeper.dbm.lock().unwrap().load_user(user_id).unwrap(),
            UserInfo::new(
                updated_receipt.available_slots(),
                updated_receipt.subscription_start(),
                updated_receipt.subscription_expiry()
            )
        );
    }

    #[test]
    fn test_add_update_appointment() {
        let gatekeeper = init_gatekeeper(&Blockchain::default().with_height(START_HEIGHT));

        // if a given appointment is not associated with a given user, add_update_appointment adds the appointment user appointments alongside the number os slots it consumes. If the appointment
        // is already associated with the user, it will update it (both data and slot count).

        // Let's first add the a user to the Gatekeeper (inputs are always sanitized here, so we don't need tests for non-registered users)
        let user_id = get_random_user_id();
        gatekeeper.add_update_user(user_id).unwrap();

        // Now let's add a new appointment
        let slots_before = gatekeeper
            .registered_users
            .lock()
            .unwrap()
            .get(&user_id)
            .unwrap()
            .available_slots;
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        let available_slots = gatekeeper
            .add_update_appointment(user_id, uuid, &appointment)
            .unwrap();
        // Simulate the watcher adding the appointment in the database.
        gatekeeper
            .dbm
            .lock()
            .unwrap()
            .store_appointment(uuid, &appointment)
            .unwrap();

        let (_, user_locators) = gatekeeper.get_user_info(user_id).unwrap();
        assert!(user_locators.contains(&appointment.locator()));
        assert_eq!(slots_before, available_slots + 1);

        // Slots should have been updated in the database too.
        let mut loaded_user = gatekeeper.dbm.lock().unwrap().load_user(user_id).unwrap();
        assert_eq!(loaded_user.available_slots, available_slots);

        // Adding the exact same appointment should leave the slots count unchanged.
        // We don't really need to update the appointment in the DB since it's the very same appointment.
        let mut updated_slot_count = gatekeeper
            .add_update_appointment(user_id, uuid, &appointment)
            .unwrap();

        let (_, user_locators) = gatekeeper.get_user_info(user_id).unwrap();
        assert!(user_locators.contains(&appointment.locator()));
        assert_eq!(updated_slot_count, available_slots);

        loaded_user = gatekeeper.dbm.lock().unwrap().load_user(user_id).unwrap();
        assert_eq!(loaded_user.available_slots, updated_slot_count);

        // If we add an update to an existing appointment with a bigger data blob (modulo ENCRYPTED_BLOB_MAX_SIZE), additional slots should be taken
        let mut bigger_appointment = appointment.clone();
        bigger_appointment.inner.encrypted_blob = get_random_bytes(ENCRYPTED_BLOB_MAX_SIZE + 1);
        updated_slot_count = gatekeeper
            .add_update_appointment(user_id, uuid, &bigger_appointment)
            .unwrap();
        // Simulate the watcher updating the appointment in the database.
        gatekeeper
            .dbm
            .lock()
            .unwrap()
            .update_appointment(uuid, &bigger_appointment)
            .unwrap();

        let (_, user_locators) = gatekeeper.get_user_info(user_id).unwrap();
        assert!(user_locators.contains(&appointment.locator()));
        assert_eq!(updated_slot_count, available_slots - 1);

        loaded_user = gatekeeper.dbm.lock().unwrap().load_user(user_id).unwrap();
        assert_eq!(loaded_user.available_slots, updated_slot_count);

        // Adding back a smaller update (modulo ENCRYPTED_BLOB_MAX_SIZE) should reduce the count
        updated_slot_count = gatekeeper
            .add_update_appointment(user_id, uuid, &appointment)
            .unwrap();
        // Simulate the watcher updating the appointment in the database.
        gatekeeper
            .dbm
            .lock()
            .unwrap()
            .update_appointment(uuid, &appointment)
            .unwrap();

        let (_, user_locators) = gatekeeper.get_user_info(user_id).unwrap();
        assert!(user_locators.contains(&appointment.locator()));
        assert_eq!(updated_slot_count, available_slots);

        loaded_user = gatekeeper.dbm.lock().unwrap().load_user(user_id).unwrap();
        assert_eq!(loaded_user.available_slots, updated_slot_count);

        // Adding an appointment with a different uuid should not count as an update
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        updated_slot_count = gatekeeper
            .add_update_appointment(user_id, uuid, &appointment)
            .unwrap();
        // Simulate the watcher adding the appointment in the database.
        gatekeeper
            .dbm
            .lock()
            .unwrap()
            .store_appointment(uuid, &appointment)
            .unwrap();

        let (_, user_locators) = gatekeeper.get_user_info(user_id).unwrap();
        assert!(user_locators.contains(&appointment.locator()));
        assert_eq!(updated_slot_count, available_slots - 1);

        loaded_user = gatekeeper.dbm.lock().unwrap().load_user(user_id).unwrap();
        assert_eq!(loaded_user.available_slots, updated_slot_count);

        // Finally, trying to add an appointment when the user has no enough slots should fail
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        gatekeeper
            .registered_users
            .lock()
            .unwrap()
            .get_mut(&user_id)
            .unwrap()
            .available_slots = 0;
        assert!(matches!(
            gatekeeper.add_update_appointment(user_id, uuid, &appointment),
            Err(NotEnoughSlots)
        ));

        // The entry in the database should remain unchanged in this case
        loaded_user = gatekeeper.dbm.lock().unwrap().load_user(user_id).unwrap();
        assert_eq!(loaded_user.available_slots, updated_slot_count);
    }

    #[test]
    fn test_has_subscription_expired() {
        let gatekeeper = init_gatekeeper(&Blockchain::default().with_height(START_HEIGHT));

        // If the user is not registered, querying for a subscription expiry check should return an error
        let user_id = get_random_user_id();
        assert!(matches!(
            gatekeeper.has_subscription_expired(user_id),
            Err(AuthenticationFailure { .. })
        ));

        // If the user is registered and the subscription is active we should get (false, expiry)
        gatekeeper.add_update_user(user_id).unwrap();
        assert_eq!(
            gatekeeper.has_subscription_expired(user_id),
            Ok((false, DURATION + START_HEIGHT as u32))
        );

        // If the subscription has expired, we should get (true, expiry). Let's modify the user entry
        let expiry = START_HEIGHT as u32;
        gatekeeper
            .registered_users
            .lock()
            .unwrap()
            .get_mut(&user_id)
            .unwrap()
            .subscription_expiry = expiry;
        assert_eq!(
            gatekeeper.has_subscription_expired(user_id),
            Ok((true, expiry))
        );
    }

    #[test]
    fn test_get_outdated_users() {
        let start_height = START_HEIGHT as u32 + EXPIRY_DELTA;
        let gatekeeper = init_gatekeeper(&Blockchain::default().with_height(start_height as usize));

        // Initially, there are not outdated users, so querying any block height should return an empty map
        for i in 0..start_height {
            assert_eq!(gatekeeper.get_outdated_users(i), vec![]);
        }

        // Adding a user whose subscription is outdated should return an entry
        let user_id = get_random_user_id();
        gatekeeper.add_update_user(user_id).unwrap();

        // Check that data is not yet outdated
        assert_eq!(gatekeeper.get_outdated_users(start_height), vec![]);

        // Add an outdated user and check again
        gatekeeper.add_outdated_user(user_id, start_height);
        assert_eq!(gatekeeper.get_outdated_users(start_height), vec![user_id]);
    }

    #[test]
    fn test_delete_appointments_without_refund() {
        let gatekeeper = init_gatekeeper(&Blockchain::default().with_height(START_HEIGHT));
        let n_users = 100;
        let n_apps = 10;
        let mut uuids_to_delete = Vec::new();
        let mut rest = Vec::new();
        let mut trackers = Vec::new();
        let mut users_info = HashMap::new();

        for _ in 0..n_users {
            let user_id = get_random_user_id();
            gatekeeper.add_update_user(user_id).unwrap();
            for i in 0..n_apps {
                let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
                gatekeeper
                    .add_update_appointment(user_id, uuid, &appointment)
                    .unwrap();
                // Add the appointment to the database. This is normally done by the Watcher.
                gatekeeper
                    .dbm
                    .lock()
                    .unwrap()
                    .store_appointment(uuid, &appointment)
                    .unwrap();
                if i % 2 == 0 {
                    uuids_to_delete.push(uuid);
                } else {
                    rest.push(uuid);
                }
                // Also trigger some of these appointments as trackers.
                if i % 5 == 0 {
                    gatekeeper
                        .dbm
                        .lock()
                        .unwrap()
                        .store_tracker(
                            uuid,
                            &get_random_tracker(user_id, ConfirmationStatus::ConfirmedIn(42)),
                        )
                        .unwrap();
                    trackers.push(uuid);
                }
            }
            users_info.insert(user_id, gatekeeper.get_user_info(user_id).unwrap().0);
        }

        // Delete these appointments without refunding their owners.
        gatekeeper.delete_appointments(uuids_to_delete.clone(), false);

        for uuid in uuids_to_delete.clone() {
            assert!(!gatekeeper.dbm.lock().unwrap().appointment_exists(uuid));
        }
        for uuid in rest {
            assert!(gatekeeper.dbm.lock().unwrap().appointment_exists(uuid));
        }
        for uuid in trackers {
            if uuids_to_delete.contains(&uuid) {
                // The tracker should be deleted as well.
                assert!(!gatekeeper.dbm.lock().unwrap().tracker_exists(uuid));
            } else {
                assert!(gatekeeper.dbm.lock().unwrap().tracker_exists(uuid));
            }
        }

        for (user_id, user_info_before_deletion) in users_info {
            // Since `refund` was false, the users' slots should not have changed after deleting appointments.
            let (user_info_after_deletion, _) = gatekeeper.get_user_info(user_id).unwrap();
            assert_eq!(user_info_after_deletion, user_info_before_deletion);
        }
    }

    #[test]
    fn test_delete_appointments_with_refund() {
        let gatekeeper = init_gatekeeper(&Blockchain::default().with_height(START_HEIGHT));
        let n_users = 100;
        let n_apps = 10;
        let mut uuids_to_delete = Vec::new();
        let mut rest = Vec::new();
        let mut trackers = Vec::new();
        let mut users_remaining_slots = HashMap::new();

        for _ in 0..n_users {
            let user_id = get_random_user_id();
            gatekeeper.add_update_user(user_id).unwrap();
            let mut user_remaining_slots =
                gatekeeper.get_user_info(user_id).unwrap().0.available_slots;
            for i in 0..n_apps {
                let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
                gatekeeper
                    .add_update_appointment(user_id, uuid, &appointment)
                    .unwrap();
                // Add the appointment to the database. This is normally done by the Watcher.
                gatekeeper
                    .dbm
                    .lock()
                    .unwrap()
                    .store_appointment(uuid, &appointment)
                    .unwrap();
                if i % 2 == 0 {
                    // We don't reduce the remaining slots for the appointments which are
                    // going to delete since we will refund their owners.
                    uuids_to_delete.push(uuid);
                } else {
                    rest.push(uuid);
                    user_remaining_slots -= compute_appointment_slots(
                        appointment.encrypted_blob().len(),
                        ENCRYPTED_BLOB_MAX_SIZE,
                    );
                }
                // Also trigger some of these appointments as trackers.
                if i % 5 == 0 {
                    gatekeeper
                        .dbm
                        .lock()
                        .unwrap()
                        .store_tracker(
                            uuid,
                            &get_random_tracker(user_id, ConfirmationStatus::ConfirmedIn(42)),
                        )
                        .unwrap();
                    trackers.push(uuid);
                }
            }
            users_remaining_slots.insert(user_id, user_remaining_slots);
        }

        // Delete these appointments and refund their owners their slots back.
        gatekeeper.delete_appointments(uuids_to_delete.clone(), true);

        for uuid in uuids_to_delete.clone() {
            assert!(!gatekeeper.dbm.lock().unwrap().appointment_exists(uuid));
        }
        for uuid in rest {
            assert!(gatekeeper.dbm.lock().unwrap().appointment_exists(uuid));
        }
        for uuid in trackers {
            if uuids_to_delete.contains(&uuid) {
                // The tracker should be deleted as well.
                assert!(!gatekeeper.dbm.lock().unwrap().tracker_exists(uuid));
            } else {
                assert!(gatekeeper.dbm.lock().unwrap().tracker_exists(uuid));
            }
        }

        for (user_id, correct_remaining_slots) in users_remaining_slots {
            let remaining_slots_from_db =
                gatekeeper.get_user_info(user_id).unwrap().0.available_slots;
            assert_eq!(remaining_slots_from_db, correct_remaining_slots);
            assert_eq!(
                gatekeeper.registered_users.lock().unwrap()[&user_id].available_slots,
                correct_remaining_slots
            );
        }
    }

    #[test]
    fn test_filtered_block_connected() {
        // block_connected in the Gatekeeper is used to keep track of time in order to manage the users' subscription expiry.
        // Remove users that get outdated at the new block's height from registered_users and the database.
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let gatekeeper = init_gatekeeper(&chain);

        // Check that users are outdated when the expected height if hit
        let user1_id = get_random_user_id();
        let user2_id = get_random_user_id();
        let user3_id = get_random_user_id();

        for user_id in &[user1_id, user2_id, user3_id] {
            gatekeeper.add_outdated_user(*user_id, chain.tip().height + 1)
        }

        // Connect a new block. Outdated users are deleted
        gatekeeper.block_connected(&chain.generate(None), chain.get_block_count());

        // Check that users have been removed from registered_users and the database
        for user_id in &[user1_id, user2_id, user3_id] {
            assert!(!gatekeeper
                .registered_users
                .lock()
                .unwrap()
                .contains_key(user_id));
            assert!(gatekeeper.dbm.lock().unwrap().load_user(*user_id).is_none());
        }

        // Check that the last_known_block_header has been properly updated
        assert_eq!(
            gatekeeper.last_known_block_height.load(Ordering::Relaxed),
            chain.get_block_count()
        );
    }

    #[test]
    fn test_block_disconnected() {
        // Block disconnected simply updates the last known block
        let chain = Blockchain::default().with_height(START_HEIGHT);
        let gatekeeper = init_gatekeeper(&chain);
        let height = chain.get_block_count();

        let last_known_block_header = chain.tip();
        let prev_block_header = chain.at_height((height - 1) as usize);

        gatekeeper.block_disconnected(&last_known_block_header.header, height);
        assert_eq!(
            gatekeeper.last_known_block_height.load(Ordering::Relaxed),
            prev_block_header.height
        );
    }
}
