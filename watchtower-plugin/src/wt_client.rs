use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::path::PathBuf;
use tokio::fs;
use tokio::sync::mpsc::UnboundedSender;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use teos_common::appointment::{Appointment, Locator};
use teos_common::cryptography;
use teos_common::dbm::Error as DBError;
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::{TowerId, UserId};

use crate::dbm::DBM;
use crate::net::ProxyInfo;
use crate::retrier::RetrierStatus;
use crate::{MisbehaviorProof, SubscriptionError, TowerInfo, TowerStatus, TowerSummary};

#[derive(Eq, PartialEq)]
pub enum RevocationData {
    Fresh(Locator),
    Stale(HashSet<Locator>),
    None,
}

impl RevocationData {
    pub fn is_none(&self) -> bool {
        *self == RevocationData::None
    }
}

impl From<RevocationData> for HashSet<Locator> {
    fn from(r: RevocationData) -> Self {
        match r {
            RevocationData::Fresh(l) => HashSet::from_iter(vec![l]),
            RevocationData::Stale(hs) => hs,
            RevocationData::None => HashSet::new(),
        }
    }
}

impl std::fmt::Debug for RevocationData {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                RevocationData::Fresh(l) => format!("Fresh: {l}"),
                RevocationData::Stale(hs) => format!(
                    "Stale: {:?}",
                    hs.iter().map(|l| l.to_string()).collect::<Vec<_>>()
                ),
                RevocationData::None => "None".to_owned(),
            }
        )
    }
}

/// Represents the watchtower client that is being used as the CoreLN plugin state.
pub struct WTClient {
    /// A [DBM] instance.
    pub dbm: DBM,
    /// A collection of towers the client is registered to.
    pub towers: HashMap<TowerId, TowerSummary>,
    /// Queue of unreachable towers.
    pub unreachable_towers: UnboundedSender<(TowerId, RevocationData)>,
    // Map of existing retriers and its state.
    pub retriers: HashMap<TowerId, RetrierStatus>,
    /// The user secret key.
    pub user_sk: SecretKey,
    /// The user identifier.
    pub user_id: UserId,
    /// Optional proxy
    pub proxy: Option<ProxyInfo>,
}

impl WTClient {
    pub async fn new(
        data_dir: PathBuf,
        unreachable_towers: UnboundedSender<(TowerId, RevocationData)>,
    ) -> Self {
        Self::with_proxy(data_dir, unreachable_towers, None).await
    }

    pub async fn with_proxy(
        data_dir: PathBuf,
        unreachable_towers: UnboundedSender<(TowerId, RevocationData)>,
        proxy: Option<ProxyInfo>,
    ) -> Self {
        // Create data dir if it does not exist
        fs::create_dir_all(&data_dir).await.unwrap_or_else(|e| {
            log::error!("Cannot create data dir: {e:?}");
            std::process::exit(1);
        });

        let dbm = DBM::new(&data_dir.join("watchtowers_db.sql3")).unwrap();

        let (user_sk, user_id) = if let Some(sk) = dbm.load_client_key() {
            (
                sk,
                UserId(PublicKey::from_secret_key(&Secp256k1::new(), &sk)),
            )
        } else {
            log::info!("Watchtower client keys not found. Creating a fresh set");
            let (sk, pk) = cryptography::get_random_keypair();
            dbm.store_client_key(&sk).unwrap();
            (sk, UserId(pk))
        };

        let towers = dbm.load_towers();
        for (tower_id, tower) in towers.iter() {
            if tower.status.is_temporary_unreachable() {
                unreachable_towers
                    .send((
                        *tower_id,
                        RevocationData::Stale(tower.pending_appointments.iter().cloned().collect()),
                    ))
                    .unwrap();
            }
        }

        log::info!("Plugin watchtower client initialized. User id = {user_id}");

        WTClient {
            towers,
            unreachable_towers,
            retriers: HashMap::new(),
            dbm,
            user_sk,
            user_id,
            proxy,
        }
    }

    /// Adds or updates a tower entry.
    pub fn add_update_tower(
        &mut self,
        tower_id: TowerId,
        tower_net_addr: &str,
        receipt: &RegistrationReceipt,
    ) -> Result<(), SubscriptionError> {
        if let Some(tower) = self.towers.get(&tower_id) {
            // TODO: For now we're forcing updates to increase both slots and expiry. This is not mandatory and may
            // be changed in the future, but the tower is currently set to do this anyway so let's keep it simple.
            if receipt.subscription_expiry() <= tower.subscription_expiry {
                return Err(SubscriptionError::Expiry);
            } else {
                let tower_info = self.dbm.load_tower_record(tower_id).unwrap();
                if receipt.available_slots() <= tower_info.available_slots {
                    return Err(SubscriptionError::Slots);
                }
            }
        }

        self.dbm
            .store_tower_record(tower_id, tower_net_addr, receipt)
            .unwrap();

        if let Some(summary) = self.towers.get_mut(&tower_id) {
            summary.udpate(
                tower_net_addr.to_owned(),
                receipt.available_slots(),
                receipt.subscription_start(),
                receipt.subscription_expiry(),
            );
        } else {
            self.towers.insert(
                tower_id,
                TowerSummary::new(
                    tower_net_addr.to_owned(),
                    receipt.available_slots(),
                    receipt.subscription_start(),
                    receipt.subscription_expiry(),
                ),
            );
        };

        Ok(())
    }

    /// Gets the registration receipt(s) of a given tower in the given range.
    /// If no range is given then gets the latest registration receipt
    pub fn get_registration_receipt(
        &self,
        tower_id: TowerId,
        subscription_start: Option<u32>,
        subscription_expiry: Option<u32>,
    ) -> Option<Vec<RegistrationReceipt>> {
        self.dbm.load_registration_receipt(
            tower_id,
            self.user_id,
            subscription_start,
            subscription_expiry,
        )
    }

    /// Loads a tower record from the database.
    pub fn load_tower_info(&self, tower_id: TowerId) -> Option<TowerInfo> {
        self.dbm.load_tower_record(tower_id)
    }

    /// Gets the given tower status (identified by tower_id), if found.
    pub fn get_tower_status(&self, tower_id: &TowerId) -> Option<TowerStatus> {
        Some(self.towers.get(tower_id)?.status)
    }

    /// Sets the tower status to any of the `TowerStatus` variants.
    pub fn set_tower_status(&mut self, tower_id: TowerId, status: TowerStatus) {
        if let Some(tower) = self.towers.get_mut(&tower_id) {
            if tower.status != status {
                tower.status = status
            } else {
                log::debug!("{tower_id} status is already {status}")
            }
        } else {
            log::error!("Cannot change tower status to {status}. Unknown tower_id: {tower_id}");
        }
    }

    /// Gets the given tower status (identified by tower_id), if found.
    pub fn get_retrier_status(&self, tower_id: &TowerId) -> Option<&RetrierStatus> {
        self.retriers.get(tower_id)
    }

    /// Adds an appointment receipt to the tower record.
    pub fn add_appointment_receipt(
        &mut self,
        tower_id: TowerId,
        locator: Locator,
        available_slots: u32,
        receipt: &AppointmentReceipt,
    ) {
        if let Some(tower) = self.towers.get_mut(&tower_id) {
            // DISCUSS: It may be nice to independently compute the slots and compare
            tower.available_slots = available_slots;

            self.dbm
                .store_appointment_receipt(tower_id, locator, available_slots, receipt)
                .unwrap();
        } else {
            log::error!("Cannot add appointment receipt to tower. Unknown tower_id: {tower_id}");
        }
    }

    /// Gets an appointment receipt from the database (if found).
    pub fn get_appointment_receipt(
        &self,
        tower_id: TowerId,
        locator: Locator,
    ) -> Option<AppointmentReceipt> {
        self.dbm.load_appointment_receipt(tower_id, locator)
    }

    /// Adds a pending appointment to the tower record.
    pub fn add_pending_appointment(&mut self, tower_id: TowerId, appointment: &Appointment) {
        if let Some(tower) = self.towers.get_mut(&tower_id) {
            tower.pending_appointments.insert(appointment.locator);

            self.dbm
                .store_pending_appointment(tower_id, appointment)
                .unwrap();
        } else {
            log::error!("Cannot add pending appointment to tower. Unknown tower_id: {tower_id}");
        }
    }

    /// Removes a pending appointment from the tower record.
    pub fn remove_pending_appointment(&mut self, tower_id: TowerId, locator: Locator) {
        if let Some(tower) = self.towers.get_mut(&tower_id) {
            tower.pending_appointments.remove(&locator);

            self.dbm
                .delete_pending_appointment(tower_id, locator)
                .unwrap();
        } else {
            log::error!("Cannot remove pending appointment to tower. Unknown tower_id: {tower_id}");
        }
    }

    /// Adds an invalid appointment to the tower record.
    pub fn add_invalid_appointment(&mut self, tower_id: TowerId, appointment: &Appointment) {
        if let Some(tower) = self.towers.get_mut(&tower_id) {
            tower.invalid_appointments.insert(appointment.locator);

            self.dbm
                .store_invalid_appointment(tower_id, appointment)
                .unwrap();
        } else {
            log::error!("Cannot add invalid appointment to tower. Unknown tower_id: {tower_id}");
        }
    }

    /// Flags a given tower as misbehaving, storing the misbehaving proof in the database.
    pub fn flag_misbehaving_tower(&mut self, tower_id: TowerId, proof: MisbehaviorProof) {
        if let Some(tower) = self.towers.get_mut(&tower_id) {
            self.dbm.store_misbehaving_proof(tower_id, &proof).unwrap();
            tower.status = TowerStatus::Misbehaving;
        } else {
            log::error!("Cannot flag tower. Unknown tower_id: {tower_id}");
        }
    }

    /// Removes a tower from the client (both memory and database).
    ///
    /// Any data associated to the tower will be deleted (i.e. links to appointments)
    pub fn remove_tower(&mut self, tower_id: TowerId) -> Result<(), DBError> {
        if self.towers.contains_key(&tower_id) {
            self.towers.remove(&tower_id);
            self.dbm.remove_tower_record(tower_id)
        } else {
            Err(DBError::NotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempdir::TempDir;
    use tokio::sync::mpsc::unbounded_channel;

    use teos_common::test_utils::{
        generate_random_appointment, get_random_appointment_receipt,
        get_random_registration_receipt, get_random_user_id,
        get_registration_receipt_from_previous,
    };

    #[tokio::test]
    async fn test_add_update_load_tower() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let mut wt_client =
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await;

        // Adding a new tower will add a summary to towers and the full data to the
        let mut receipt = get_random_registration_receipt();
        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tower_info = TowerInfo::empty(
            "talaia.watch".to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );

        wt_client
            .add_update_tower(tower_id, &tower_info.net_addr, &receipt)
            .unwrap();
        assert_eq!(
            wt_client.towers.get(&tower_id),
            Some(&TowerSummary::from(tower_info.clone()))
        );
        assert_eq!(wt_client.load_tower_info(tower_id).unwrap(), tower_info);

        // Calling the method again with updated information should also updated the records in memory and the database
        receipt = get_registration_receipt_from_previous(&receipt);

        let updated_tower_info = TowerInfo::empty(
            "talaia.watch".to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );
        wt_client
            .add_update_tower(tower_id, &updated_tower_info.net_addr, &receipt)
            .unwrap();

        assert_eq!(
            wt_client.towers.get(&tower_id),
            Some(&TowerSummary::from(updated_tower_info.clone()))
        );
        assert_eq!(
            wt_client.load_tower_info(tower_id).unwrap(),
            updated_tower_info
        );

        // If we try to update without increasing both the end_time and the slots, this will fail
        let mut receipt_same_slots = RegistrationReceipt::new(
            receipt.user_id(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry() + 1,
        );
        receipt_same_slots.sign(&tower_sk);
        let mut receipt_same_expiry = RegistrationReceipt::new(
            receipt.user_id(),
            receipt.available_slots() + 1,
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );
        receipt_same_expiry.sign(&tower_sk);

        assert!(matches!(
            wt_client.add_update_tower(tower_id, &updated_tower_info.net_addr, &receipt),
            Err(SubscriptionError::Expiry)
        ));
        assert!(matches!(
            wt_client.add_update_tower(tower_id, &updated_tower_info.net_addr, &receipt_same_slots),
            Err(SubscriptionError::Slots)
        ));
        assert!(matches!(
            wt_client.add_update_tower(
                tower_id,
                &updated_tower_info.net_addr,
                &receipt_same_expiry
            ),
            Err(SubscriptionError::Expiry)
        ));

        // Decrease the slots count (simulate exhaustion) and update with more than the current count it should work
        let locator = generate_random_appointment(None).locator;
        wt_client.add_appointment_receipt(
            tower_id,
            locator,
            0,
            &get_random_appointment_receipt(tower_sk),
        );
        wt_client
            .add_update_tower(tower_id, &updated_tower_info.net_addr, &receipt_same_slots)
            .unwrap();
    }

    #[tokio::test]
    async fn test_get_tower_status() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let mut wt_client =
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await;

        // If the tower is unknown, get_tower_status returns None
        let tower_id = get_random_user_id();
        assert!(wt_client.get_tower_status(&tower_id).is_none());

        // Add a tower
        let receipt = get_random_registration_receipt();
        wt_client
            .add_update_tower(tower_id, "talaia.watch", &receipt)
            .unwrap();

        // If the tower is known, get_tower_status matches getting the same data from the towers collection
        assert_eq!(
            wt_client.towers.get(&tower_id).unwrap().status,
            wt_client.get_tower_status(&tower_id).unwrap()
        )
    }

    #[tokio::test]
    async fn test_set_tower_status() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let mut wt_client =
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await;

        // If the tower is unknown nothing will happen
        let unknown_tower = get_random_user_id();
        wt_client.set_tower_status(unknown_tower, TowerStatus::Reachable);
        assert!(!wt_client.towers.contains_key(&unknown_tower));

        // If the tower is known, the status will be updated.
        let receipt = get_random_registration_receipt();
        let tower_id = get_random_user_id();
        wt_client
            .add_update_tower(tower_id, "talaia.watch", &receipt)
            .unwrap();

        for status in [
            TowerStatus::Reachable,
            TowerStatus::TemporaryUnreachable,
            TowerStatus::Unreachable,
            TowerStatus::SubscriptionError,
            TowerStatus::Misbehaving,
        ] {
            wt_client.set_tower_status(tower_id, status);
            assert_eq!(status, wt_client.get_tower_status(&tower_id).unwrap());
        }
    }

    #[tokio::test]
    async fn test_add_appointment_receipt() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let mut wt_client =
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await;

        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);

        let locator = generate_random_appointment(None).locator;
        let registration_receipt = get_random_registration_receipt();
        let appointment_receipt = get_random_appointment_receipt(tower_sk);

        // If we call this on an unknown tower it will simply do nothing
        wt_client.add_appointment_receipt(
            tower_id,
            locator,
            registration_receipt.available_slots(),
            &appointment_receipt,
        );
        assert!(!wt_client.towers.contains_key(&tower_id));

        // Add the tower to the state and try again
        let tower_info = TowerInfo::new(
            "talaia.watch".to_owned(),
            registration_receipt.available_slots(),
            registration_receipt.subscription_start(),
            registration_receipt.subscription_expiry(),
            HashMap::from([(locator, appointment_receipt.signature().unwrap())]),
            Vec::new(),
            Vec::new(),
        );
        wt_client
            .add_update_tower(tower_id, &tower_info.net_addr, &registration_receipt)
            .unwrap();
        wt_client.add_appointment_receipt(
            tower_id,
            locator,
            registration_receipt.available_slots(),
            &appointment_receipt,
        );

        assert!(wt_client.towers.contains_key(&tower_id));
        assert_eq!(
            wt_client.towers.get(&tower_id).unwrap(),
            &TowerSummary::from(tower_info.clone())
        );
        assert_eq!(wt_client.load_tower_info(tower_id).unwrap(), tower_info);
    }

    #[tokio::test]
    async fn test_add_pending_appointment() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let mut wt_client =
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await;

        let tower_id = get_random_user_id();

        let registration_receipt = get_random_registration_receipt();
        let appointment = generate_random_appointment(None);

        // If we call this on an unknown tower it will simply do nothing
        wt_client.add_pending_appointment(tower_id, &appointment);
        assert!(!wt_client.towers.contains_key(&tower_id));

        // Add the tower to the state and try again
        let tower_info = TowerInfo::new(
            "talaia.watch".to_owned(),
            registration_receipt.available_slots(),
            registration_receipt.subscription_start(),
            registration_receipt.subscription_expiry(),
            HashMap::new(),
            vec![appointment.clone()],
            Vec::new(),
        );

        wt_client
            .add_update_tower(tower_id, &tower_info.net_addr, &registration_receipt)
            .unwrap();
        wt_client.add_pending_appointment(tower_id, &appointment);

        assert!(wt_client.towers.contains_key(&tower_id));
        assert_eq!(
            wt_client.towers.get(&tower_id).unwrap(),
            &TowerSummary::from(tower_info.clone())
        );
        // When towers data is loaded from the database, it is assumed to be reachable.
        assert_eq!(
            wt_client.load_tower_info(tower_id).unwrap(),
            tower_info.with_status(TowerStatus::TemporaryUnreachable)
        );
    }

    #[tokio::test]
    async fn test_remove_pending_appointment() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let mut wt_client =
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await;

        let tower_id = get_random_user_id();

        let registration_receipt = get_random_registration_receipt();
        let appointment = generate_random_appointment(None);

        // If we call this on an unknown tower it will simply do nothing
        wt_client.remove_pending_appointment(tower_id, appointment.locator);

        // Add the tower to the state and try again
        wt_client
            .add_update_tower(tower_id, "talaia.watch", &registration_receipt)
            .unwrap();
        wt_client.add_pending_appointment(tower_id, &appointment);

        wt_client.remove_pending_appointment(tower_id, appointment.locator);
        assert!(!wt_client
            .towers
            .get(&tower_id)
            .unwrap()
            .pending_appointments
            .contains(&appointment.locator));
        // This bit is tested exhaustively in the DBM.
        assert!(!wt_client.dbm.appointment_exists(appointment.locator));
    }

    #[tokio::test]
    async fn test_add_invalid_appointment() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let mut wt_client =
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await;

        let tower_id = get_random_user_id();

        let registration_receipt = get_random_registration_receipt();
        let appointment = generate_random_appointment(None);

        // If we call this on an unknown tower it will simply do nothing
        wt_client.add_invalid_appointment(tower_id, &appointment);
        assert!(!wt_client.towers.contains_key(&tower_id));

        // Add the tower to the state and try again
        let tower_info = TowerInfo::new(
            "talaia.watch".to_owned(),
            registration_receipt.available_slots(),
            registration_receipt.subscription_start(),
            registration_receipt.subscription_expiry(),
            HashMap::new(),
            Vec::new(),
            vec![appointment.clone()],
        );

        wt_client
            .add_update_tower(tower_id, &tower_info.net_addr, &registration_receipt)
            .unwrap();
        wt_client.add_invalid_appointment(tower_id, &appointment);

        assert!(wt_client.towers.contains_key(&tower_id));
        assert_eq!(
            wt_client.towers.get(&tower_id).unwrap(),
            &TowerSummary::from(tower_info.clone())
        );
        assert_eq!(wt_client.load_tower_info(tower_id).unwrap(), tower_info);
    }

    #[tokio::test]
    async fn test_move_pending_appointment_to_invalid() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let mut wt_client =
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await;

        let tower_id = get_random_user_id();

        let registration_receipt = get_random_registration_receipt();
        let appointment = generate_random_appointment(None);

        wt_client
            .add_update_tower(tower_id, "talaia.watch", &registration_receipt)
            .unwrap();
        wt_client.add_pending_appointment(tower_id, &appointment);

        // Check that the appointment can be moved from pending to invalid
        wt_client.add_invalid_appointment(tower_id, &appointment);
        wt_client.remove_pending_appointment(tower_id, appointment.locator);

        assert!(!wt_client
            .towers
            .get(&tower_id)
            .unwrap()
            .pending_appointments
            .contains(&appointment.locator));
        assert!(wt_client
            .towers
            .get(&tower_id)
            .unwrap()
            .invalid_appointments
            .contains(&appointment.locator));
        assert!(!wt_client
            .dbm
            .load_appointment_locators(tower_id, crate::AppointmentStatus::Pending)
            .contains(&appointment.locator));
        assert!(wt_client
            .dbm
            .load_appointment_locators(tower_id, crate::AppointmentStatus::Invalid)
            .contains(&appointment.locator));
        assert!(wt_client.dbm.appointment_exists(appointment.locator));
    }

    #[tokio::test]
    async fn test_move_pending_appointment_to_invalid_multiple_towers() {
        // Check that moving an appointment from pending to invalid can be done even if multiple towers have a reference to it
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let mut wt_client =
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await;

        let tower_id = get_random_user_id();
        let another_tower_id = get_random_user_id();
        let tower_net_addr = "talaia.watch";

        let registration_receipt = get_random_registration_receipt();
        let appointment = generate_random_appointment(None);

        wt_client
            .add_update_tower(tower_id, tower_net_addr, &registration_receipt)
            .unwrap();
        wt_client
            .add_update_tower(another_tower_id, tower_net_addr, &registration_receipt)
            .unwrap();
        wt_client.add_pending_appointment(tower_id, &appointment);
        wt_client.add_pending_appointment(another_tower_id, &appointment);

        // Check that the appointment can be moved from pending to invalid
        wt_client.add_invalid_appointment(tower_id, &appointment);
        wt_client.remove_pending_appointment(tower_id, appointment.locator);

        // TOWER_ID CHECKS
        assert!(!wt_client
            .towers
            .get(&tower_id)
            .unwrap()
            .pending_appointments
            .contains(&appointment.locator));
        assert!(wt_client
            .towers
            .get(&tower_id)
            .unwrap()
            .invalid_appointments
            .contains(&appointment.locator));
        assert!(!wt_client
            .dbm
            .load_appointment_locators(tower_id, crate::AppointmentStatus::Pending)
            .contains(&appointment.locator));
        assert!(wt_client
            .dbm
            .load_appointment_locators(tower_id, crate::AppointmentStatus::Invalid)
            .contains(&appointment.locator));

        // ANOTHER_TOWER_ID CHECKS
        assert!(wt_client
            .towers
            .get(&another_tower_id)
            .unwrap()
            .pending_appointments
            .contains(&appointment.locator));
        assert!(!wt_client
            .towers
            .get(&another_tower_id)
            .unwrap()
            .invalid_appointments
            .contains(&appointment.locator));
        assert!(wt_client
            .dbm
            .load_appointment_locators(another_tower_id, crate::AppointmentStatus::Pending)
            .contains(&appointment.locator));
        assert!(!wt_client
            .dbm
            .load_appointment_locators(another_tower_id, crate::AppointmentStatus::Invalid)
            .contains(&appointment.locator));

        // GENERAL
        assert!(wt_client.dbm.appointment_exists(appointment.locator));
    }

    #[tokio::test]
    async fn test_flag_misbehaving_tower() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let mut wt_client =
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await;

        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);

        // If we call this on an unknown tower it will simply do nothing
        let appointment = generate_random_appointment(None);
        let receipt = get_random_appointment_receipt(tower_sk);
        let proof = MisbehaviorProof::new(appointment.locator, receipt, get_random_user_id());
        wt_client.flag_misbehaving_tower(tower_id, proof.clone());
        assert!(!wt_client.towers.contains_key(&tower_id));

        // // Add the tower to the state and try again
        let registration_receipt = get_random_registration_receipt();
        wt_client
            .add_update_tower(tower_id, "talaia.watch", &registration_receipt)
            .unwrap();
        wt_client.flag_misbehaving_tower(tower_id, proof.clone());

        // Check data in memory
        let tower_summary = wt_client.towers.get(&tower_id);
        assert!(tower_summary.is_some());
        assert!(tower_summary.unwrap().status.is_misbehaving());

        // Check data in DB
        let loaded_info = wt_client.load_tower_info(tower_id).unwrap();
        assert!(loaded_info.status.is_misbehaving());
        assert_eq!(loaded_info.misbehaving_proof, Some(proof));
        assert!(loaded_info.appointments.contains_key(&appointment.locator));
    }

    #[tokio::test]
    async fn test_remove_tower() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let mut wt_client =
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await;

        let receipt = get_random_registration_receipt();
        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tower_info = TowerInfo::empty(
            "talaia.watch".to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );

        // Add the tower and check it is there
        wt_client
            .add_update_tower(tower_id, &tower_info.net_addr, &receipt)
            .unwrap();
        assert_eq!(
            wt_client.towers.get(&tower_id),
            Some(&TowerSummary::from(tower_info.clone()))
        );
        assert_eq!(wt_client.load_tower_info(tower_id).unwrap(), tower_info);

        // Remove the tower and check it is not there anymore
        wt_client.remove_tower(tower_id).unwrap();
        assert!(wt_client.load_tower_info(tower_id).is_none());
        assert!(!wt_client.towers.contains_key(&tower_id));

        // Try again but this time with an associated appointment to check that it also gets removed
        wt_client
            .add_update_tower(tower_id, &tower_info.net_addr, &receipt)
            .unwrap();

        let locator = generate_random_appointment(None).locator;
        let registration_receipt = get_random_registration_receipt();
        let appointment_receipt = get_random_appointment_receipt(tower_sk);

        // If we call this on an unknown tower it will simply do nothing
        wt_client.add_appointment_receipt(
            tower_id,
            locator,
            registration_receipt.available_slots(),
            &appointment_receipt,
        );
        assert!(wt_client.dbm.appointment_receipt_exists(locator, tower_id));

        // Remove and check both the tower and the appointment
        wt_client.remove_tower(tower_id).unwrap();
        assert!(wt_client.load_tower_info(tower_id).is_none());
        assert!(!wt_client.towers.contains_key(&tower_id));
        assert!(!wt_client.dbm.appointment_receipt_exists(locator, tower_id));
    }

    #[tokio::test]
    async fn test_remove_tower_shared_appointment() {
        // Lets test removing a tower that has associated data shared with another tower.
        // For instance, having an appointment that was sent to two towers, and then deleting one of them
        // should only remove the link between the tower and the appointment, but not delete the data.
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let mut wt_client =
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await;

        let receipt = get_random_registration_receipt();
        let (tower1_sk, tower1_pk) = cryptography::get_random_keypair();
        let tower1_id = TowerId(tower1_pk);
        let (tower2_sk, tower2_pk) = cryptography::get_random_keypair();
        let tower2_id = TowerId(tower2_pk);

        wt_client
            .add_update_tower(tower1_id, "talaia.watch", &receipt)
            .unwrap();
        wt_client
            .add_update_tower(tower2_id, "talaia.watch", &receipt)
            .unwrap();

        let locator = generate_random_appointment(None).locator;
        let registration_receipt = get_random_registration_receipt();
        let appointment_receipt_1 = get_random_appointment_receipt(tower1_sk);
        let appointment_receipt_2 = get_random_appointment_receipt(tower2_sk);

        wt_client.add_appointment_receipt(
            tower1_id,
            locator,
            registration_receipt.available_slots(),
            &appointment_receipt_1,
        );
        wt_client.add_appointment_receipt(
            tower2_id,
            locator,
            registration_receipt.available_slots(),
            &appointment_receipt_2,
        );

        // Check that the data exists in both towers
        assert!(wt_client.dbm.appointment_receipt_exists(locator, tower1_id));
        assert!(wt_client.dbm.appointment_receipt_exists(locator, tower2_id));

        // Remove tower1 and check that the appointment receipt can still be found for tower2
        wt_client.remove_tower(tower1_id).unwrap();
        assert!(wt_client.load_tower_info(tower1_id).is_none());

        assert!(!wt_client.dbm.appointment_receipt_exists(locator, tower1_id));
        assert!(wt_client.dbm.appointment_receipt_exists(locator, tower2_id));
    }

    #[tokio::test]
    async fn test_remove_inexistent_tower() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let mut wt_client =
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await;

        assert!(matches!(
            wt_client.remove_tower(get_random_user_id()),
            Err(DBError::NotFound)
        ));
    }
}
