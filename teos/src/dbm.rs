//! Logic related to the tower database manager (DBM), component in charge of persisting data on disk.
//!

use std::collections::HashMap;
use std::iter::FromIterator;
use std::path::PathBuf;
use std::str::FromStr;

use rusqlite::limits::Limit;
use rusqlite::{params, params_from_iter, Connection, Error as SqliteError};

use bitcoin::consensus;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::SecretKey;
use bitcoin::BlockHash;

use teos_common::appointment::{Appointment, Locator};
use teos_common::dbm::{DatabaseConnection, DatabaseManager, Error};
use teos_common::UserId;

use crate::extended_appointment::{ExtendedAppointment, UUID};
use crate::gatekeeper::UserInfo;
use crate::responder::{ConfirmationStatus, PenaltySummary, TransactionTracker};

const TABLES: [&str; 6] = [
    "CREATE TABLE IF NOT EXISTS users (
    user_id INT PRIMARY KEY,
    available_slots INT NOT NULL,
    subscription_start INT NOT NULL,
    subscription_expiry INT NOT NULL
)",
    "CREATE TABLE IF NOT EXISTS appointments (
    UUID INT PRIMARY KEY,
    locator INT NOT NULL,
    encrypted_blob BLOB NOT NULL,
    to_self_delay INT NOT NULL,
    user_signature BLOB NOT NULL,
    start_block INT NOT NULL,
    user_id INT NOT NULL,
    FOREIGN KEY(user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE
)",
    "CREATE TABLE IF NOT EXISTS trackers (
    UUID INT PRIMARY KEY,
    dispute_tx BLOB NOT NULL,
    penalty_tx BLOB NOT NULL,
    height INT NOT NULL,
    confirmed BOOL NOT NULL,
    FOREIGN KEY(UUID)
        REFERENCES appointments(UUID)
        ON DELETE CASCADE
)",
    "CREATE TABLE IF NOT EXISTS last_known_block (
    id INT PRIMARY KEY,
    block_hash INT NOT NULL
)",
    "CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key INT NOT NULL
)",
    "CREATE INDEX IF NOT EXISTS locators_index ON appointments (
        locator
)",
];

/// Component in charge of interacting with the underlying database.
///
/// Currently works for `SQLite`. `PostgreSQL` should also be added in the future.
#[derive(Debug)]
pub struct DBM {
    /// The underlying database connection.
    connection: Connection,
}

impl DatabaseConnection for DBM {
    fn get_connection(&self) -> &Connection {
        &self.connection
    }

    fn get_mut_connection(&mut self) -> &mut Connection {
        &mut self.connection
    }
}

impl DBM {
    /// Creates a new [DBM] instance.
    pub fn new(db_path: PathBuf) -> Result<Self, SqliteError> {
        let connection = Connection::open(db_path)?;
        connection.execute("PRAGMA foreign_keys=1;", [])?;
        let mut dbm = Self { connection };
        dbm.create_tables(Vec::from_iter(TABLES))?;

        Ok(dbm)
    }

    /// Stores a user ([UserInfo]) into the database.
    pub(crate) fn store_user(&self, user_id: UserId, user_info: &UserInfo) -> Result<(), Error> {
        let query =
        "INSERT INTO users (user_id, available_slots, subscription_start, subscription_expiry) VALUES (?1, ?2, ?3, ?4)";

        match self.store_data(
            query,
            params![
                user_id.to_vec(),
                user_info.available_slots,
                user_info.subscription_start,
                user_info.subscription_expiry,
            ],
        ) {
            Ok(x) => {
                log::debug!("User successfully stored: {user_id}");
                Ok(x)
            }
            Err(e) => {
                log::error!("Couldn't store user: {user_id}. Error: {e:?}");
                Err(e)
            }
        }
    }

    /// Updates an existing user ([UserInfo]) in the database.
    pub(crate) fn update_user(&self, user_id: UserId, user_info: &UserInfo) {
        let query =
        "UPDATE users SET available_slots=(?1), subscription_start=(?2), subscription_expiry=(?3) WHERE user_id=(?4)";
        match self.update_data(
            query,
            params![
                user_info.available_slots,
                user_info.subscription_start,
                user_info.subscription_expiry,
                user_id.to_vec(),
            ],
        ) {
            Ok(_) => {
                log::debug!("User's info successfully updated: {user_id}");
            }
            Err(_) => {
                log::error!("User not found, data cannot be updated: {user_id}");
            }
        }
    }

    /// Loads the associated locators ([Locator]) of a given user ([UserId]).
    pub(crate) fn load_user_locators(&self, user_id: UserId) -> Vec<Locator> {
        let mut stmt = self
            .connection
            .prepare("SELECT locator FROM appointments WHERE user_id=(?)")
            .unwrap();

        stmt.query_map([user_id.to_vec()], |row| {
            let raw_locator: Vec<u8> = row.get(0).unwrap();
            let locator = Locator::from_slice(&raw_locator).unwrap();
            Ok(locator)
        })
        .unwrap()
        .map(|res| res.unwrap())
        .collect()
    }

    /// Loads all users from the database.
    pub(crate) fn load_all_users(&self) -> HashMap<UserId, UserInfo> {
        let mut users = HashMap::new();
        let mut stmt = self
            .connection
            .prepare("SELECT user_id, available_slots, subscription_start, subscription_expiry FROM users")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let raw_userid: Vec<u8> = row.get(0).unwrap();
            let user_id = UserId::from_slice(&raw_userid).unwrap();
            let slots = row.get(1).unwrap();
            let start = row.get(2).unwrap();
            let expiry = row.get(3).unwrap();

            users.insert(user_id, UserInfo::new(slots, start, expiry));
        }

        users
    }

    /// Removes some users from the database in batch.
    pub(crate) fn batch_remove_users(&mut self, users: &[UserId]) -> usize {
        let limit = self.connection.limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER) as usize;
        let tx = self.connection.transaction().unwrap();
        let iter = users
            .iter()
            .map(|uuid| uuid.to_vec())
            .collect::<Vec<Vec<u8>>>();

        for chunk in iter.chunks(limit) {
            let query = "DELETE FROM users WHERE user_id IN ".to_owned();
            let placeholders = format!("(?{})", (", ?").repeat(chunk.len() - 1));

            match tx.execute(&format!("{query}{placeholders}"), params_from_iter(chunk)) {
                Ok(_) => log::debug!("Users deletion added to db transaction"),
                Err(e) => log::error!("Couldn't add deletion query to transaction. Error: {e:?}"),
            }
        }

        match tx.commit() {
            Ok(_) => log::debug!("Users successfully deleted"),
            Err(e) => log::error!("Couldn't delete users. Error: {e:?}"),
        }

        (users.len() as f64 / limit as f64).ceil() as usize
    }

    /// Get the number of stored appointments.
    pub(crate) fn get_appointments_count(&self) -> usize {
        let mut stmt = self
            .connection
            .prepare("SELECT COUNT(*) FROM appointments as a LEFT JOIN trackers as t ON a.UUID=t.UUID WHERE t.UUID IS NULL")
            .unwrap();
        stmt.query_row([], |row| row.get(0)).unwrap()
    }

    /// Get the number of stored trackers.
    pub(crate) fn get_trackers_count(&self) -> usize {
        let mut stmt = self
            .connection
            .prepare("SELECT COUNT(*) FROM trackers")
            .unwrap();
        stmt.query_row([], |row| row.get(0)).unwrap()
    }

    /// Stores an [Appointment] into the database.
    pub(crate) fn store_appointment(
        &self,
        uuid: UUID,
        appointment: &ExtendedAppointment,
    ) -> Result<(), Error> {
        let query = "INSERT INTO appointments (UUID, locator, encrypted_blob, to_self_delay, user_signature, start_block, user_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
        match self.store_data(
            query,
            params![
                uuid.to_vec(),
                appointment.locator().to_vec(),
                appointment.encrypted_blob(),
                appointment.to_self_delay(),
                appointment.user_signature,
                appointment.start_block,
                appointment.user_id.to_vec(),
            ],
        ) {
            Ok(x) => {
                log::debug!("Appointment successfully stored: {uuid}");
                Ok(x)
            }
            Err(e) => {
                log::error!("Couldn't store appointment: {uuid}. Error: {e:?}");
                Err(e)
            }
        }
    }

    /// Updates an existing [Appointment] in the database.
    pub(crate) fn update_appointment(
        &self,
        uuid: UUID,
        appointment: &ExtendedAppointment,
    ) -> Result<(), Error> {
        // DISCUSS: Check what fields we'd like to make updatable. e_blob and signature are the obvious, to_self_delay and start_block may not be necessary (or even risky)
        let query =
            "UPDATE appointments SET encrypted_blob=(?1), to_self_delay=(?2), user_signature=(?3), start_block=(?4) WHERE UUID=(?5)";
        match self.update_data(
            query,
            params![
                appointment.encrypted_blob(),
                appointment.to_self_delay(),
                appointment.user_signature,
                appointment.start_block,
                uuid.to_vec(),
            ],
        ) {
            Ok(_) => {
                log::debug!("Appointment successfully updated: {uuid}");
                Ok(())
            }
            Err(e) => {
                log::error!("Appointment not found, data cannot be updated: {uuid}. Error: {e:?}");
                Err(e)
            }
        }
    }

    /// Loads an [Appointment] from the database.
    pub(crate) fn load_appointment(&self, uuid: UUID) -> Option<ExtendedAppointment> {
        let key = uuid.to_vec();
        let mut stmt = self
            .connection
            .prepare(
                "SELECT locator, encrypted_blob, to_self_delay, user_signature, start_block, user_id
                    FROM appointments WHERE UUID=(?)"
            )
            .unwrap();

        stmt.query_row([key], |row| {
            let raw_locator: Vec<u8> = row.get(0).unwrap();
            let encrypted_blob = row.get(1).unwrap();
            let to_self_delay = row.get(2).unwrap();
            let user_signature = row.get(3).unwrap();
            let start_block = row.get(4).unwrap();
            let raw_userid: Vec<u8> = row.get(5).unwrap();

            let locator = Locator::from_slice(&raw_locator).unwrap();
            let user_id = UserId::from_slice(&raw_userid).unwrap();
            let appointment = Appointment::new(locator, encrypted_blob, to_self_delay);
            Ok(ExtendedAppointment::new(
                appointment,
                user_id,
                user_signature,
                start_block,
            ))
        })
        .ok()
    }

    /// Check if an appointment with `uuid` exists.
    pub(crate) fn appointment_exists(&self, uuid: UUID) -> bool {
        self.connection
            .prepare("SELECT UUID FROM appointments WHERE UUID=(?)")
            .unwrap()
            .exists([uuid.to_vec()])
            .unwrap()
    }

    /// Loads appointments from the database. If a locator is given, this method loads only the appointments
    /// matching this locator. If no locator is given, all the appointments in the database would be returned.
    pub(crate) fn load_appointments(
        &self,
        locator: Option<Locator>,
    ) -> HashMap<UUID, ExtendedAppointment> {
        let mut appointments = HashMap::new();

        let mut sql =
            "SELECT a.UUID, a.locator, a.encrypted_blob, a.to_self_delay, a.user_signature, a.start_block, a.user_id
                FROM appointments as a LEFT JOIN trackers as t ON a.UUID=t.UUID WHERE t.UUID IS NULL".to_string();
        // If a locator was passed, filter based on it.
        if locator.is_some() {
            sql.push_str(" AND a.locator=(?)");
        }
        let mut stmt = self.connection.prepare(&sql).unwrap();

        let mut rows = if let Some(locator) = locator {
            stmt.query([locator.to_vec()]).unwrap()
        } else {
            stmt.query([]).unwrap()
        };

        while let Ok(Some(row)) = rows.next() {
            let raw_uuid: Vec<u8> = row.get(0).unwrap();
            let uuid = UUID::from_slice(&raw_uuid[0..20]).unwrap();
            let raw_locator: Vec<u8> = row.get(1).unwrap();
            let locator = Locator::from_slice(&raw_locator).unwrap();
            let raw_userid: Vec<u8> = row.get(6).unwrap();
            let user_id = UserId::from_slice(&raw_userid).unwrap();

            let appointment = Appointment::new(locator, row.get(2).unwrap(), row.get(3).unwrap());

            appointments.insert(
                uuid,
                ExtendedAppointment::new(
                    appointment,
                    user_id,
                    row.get(4).unwrap(),
                    row.get(5).unwrap(),
                ),
            );
        }

        appointments
    }

    /// Gets the length of an appointment (the length of `appointment.encrypted_blob`).
    pub(crate) fn get_appointment_length(&self, uuid: UUID) -> Option<usize> {
        let mut stmt = self
            .connection
            .prepare("SELECT length(encrypted_blob) FROM appointments WHERE UUID=(?)")
            .unwrap();

        stmt.query_row([uuid.to_vec()], |row| row.get(0)).ok()
    }

    /// Gets the [`UserId`] of the owner of the appointment along with the appointment
    /// length (same as [DBM::get_appointment_length]) for `uuid`.
    pub(crate) fn get_appointment_user_and_length(&self, uuid: UUID) -> Option<(UserId, usize)> {
        let mut stmt = self
            .connection
            .prepare("SELECT user_id, length(encrypted_blob) FROM appointments WHERE UUID=(?)")
            .unwrap();

        stmt.query_row([uuid.to_vec()], |row| {
            let raw_userid: Vec<u8> = row.get(0).unwrap();
            let length = row.get(1).unwrap();
            Ok((UserId::from_slice(&raw_userid).unwrap(), length))
        })
        .ok()
    }

    /// Removes an [Appointment] from the database.
    pub(crate) fn remove_appointment(&self, uuid: UUID) {
        let query = "DELETE FROM appointments WHERE UUID=(?)";
        match self.remove_data(query, params![uuid.to_vec()]) {
            Ok(_) => {
                log::debug!("Appointment successfully removed: {uuid}");
            }
            Err(_) => {
                log::error!("Appointment not found, data cannot be removed: {uuid}");
            }
        }
    }

    /// Removes some appointments from the database in batch and updates the associated users
    /// (giving back freed appointment slots) in one transaction so that the deletion and the
    /// update is atomic.
    pub(crate) fn batch_remove_appointments(
        &mut self,
        appointments: &[UUID],
        updated_users: &HashMap<UserId, UserInfo>,
    ) -> usize {
        let limit = self.connection.limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER) as usize;
        let tx = self.connection.transaction().unwrap();
        let iter = appointments
            .iter()
            .map(|uuid| uuid.to_vec())
            .collect::<Vec<Vec<u8>>>();

        for chunk in iter.chunks(limit) {
            let query = "DELETE FROM appointments WHERE UUID IN ".to_owned();
            let placeholders = format!("(?{})", (", ?").repeat(chunk.len() - 1));

            match tx.execute(&format!("{query}{placeholders}"), params_from_iter(chunk)) {
                Ok(_) => log::debug!("Appointments deletion added to db transaction"),
                Err(e) => log::error!("Couldn't add deletion query to transaction. Error: {e:?}"),
            }
        }

        for (id, info) in updated_users.iter() {
            let query = "UPDATE users SET available_slots=(?1) WHERE user_id=(?2)";
            match tx.execute(query, params![info.available_slots, id.to_vec(),]) {
                Ok(_) => log::debug!("User update added to db transaction"),
                Err(e) => log::error!("Couldn't add update query to transaction. Error: {e:?}"),
            };
        }

        match tx.commit() {
            Ok(_) => log::debug!("Appointments successfully deleted"),
            Err(e) => log::error!("Couldn't delete appointments. Error: {e:?}"),
        }

        (appointments.len() as f64 / limit as f64).ceil() as usize
    }

    /// Loads the [`UUID`]s of appointments triggered by `locator`.
    pub(crate) fn load_uuids(&self, locator: Locator) -> Vec<UUID> {
        let mut stmt = self
            .connection
            .prepare("SELECT UUID from appointments WHERE locator=(?)")
            .unwrap();

        stmt.query_map([locator.to_vec()], |row| {
            let raw_uuid: Vec<u8> = row.get(0).unwrap();
            let uuid = UUID::from_slice(&raw_uuid).unwrap();
            Ok(uuid)
        })
        .unwrap()
        .map(|uuid_res| uuid_res.unwrap())
        .collect()
    }

    /// Filters the given set of [`Locator`]s by including only the ones which trigger any of our stored appointments.
    pub(crate) fn batch_check_locators_exist(&self, locators: Vec<&Locator>) -> Vec<Locator> {
        let mut registered_locators = Vec::new();
        let locators: Vec<Vec<u8>> = locators.iter().map(|l| l.to_vec()).collect();
        let limit = self.connection.limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER) as usize;

        for chunk in locators.chunks(limit) {
            let query = "SELECT locator FROM appointments WHERE locator IN ".to_owned();
            let placeholders = format!("(?{})", (", ?").repeat(chunk.len() - 1));

            let mut stmt = self
                .connection
                .prepare(&format!("{query}{placeholders}"))
                .unwrap();
            let known_locators = stmt
                .query_map(params_from_iter(chunk), |row| {
                    let raw_locator: Vec<u8> = row.get(0).unwrap();
                    let locator = Locator::from_slice(&raw_locator).unwrap();
                    Ok(locator)
                })
                .unwrap()
                .map(|locator_res| locator_res.unwrap());
            registered_locators.extend(known_locators);
        }

        registered_locators
    }

    /// Stores a [TransactionTracker] into the database.
    pub(crate) fn store_tracker(
        &self,
        uuid: UUID,
        tracker: &TransactionTracker,
    ) -> Result<(), Error> {
        let (height, confirmed) = tracker.status.to_db_data().ok_or(Error::MissingField)?;

        let query =
            "INSERT INTO trackers (UUID, dispute_tx, penalty_tx, height, confirmed) VALUES (?1, ?2, ?3, ?4, ?5)";
        match self.store_data(
            query,
            params![
                uuid.to_vec(),
                consensus::serialize(&tracker.dispute_tx),
                consensus::serialize(&tracker.penalty_tx),
                height,
                confirmed,
            ],
        ) {
            Ok(x) => {
                log::debug!("Tracker successfully stored: {uuid}");
                Ok(x)
            }
            Err(e) => {
                log::error!("Couldn't store tracker: {uuid}. Error: {e:?}");
                Err(e)
            }
        }
    }

    /// Updates the tracker status in the database.
    ///
    /// The only updatable fields are `height` and `confirmed`.
    pub(crate) fn update_tracker_status(
        &self,
        uuid: UUID,
        status: &ConfirmationStatus,
    ) -> Result<(), Error> {
        let (height, confirmed) = status.to_db_data().ok_or(Error::MissingField)?;

        let query = "UPDATE trackers SET height=(?1), confirmed=(?2) WHERE UUID=(?3)";
        match self.update_data(query, params![height, confirmed, uuid.to_vec(),]) {
            Ok(x) => {
                log::debug!("Tracker successfully updated: {uuid}");
                Ok(x)
            }
            Err(e) => {
                log::error!("Couldn't update tracker: {uuid}. Error: {e:?}");
                Err(e)
            }
        }
    }

    /// Loads a [TransactionTracker] from the database.
    pub(crate) fn load_tracker(&self, uuid: UUID) -> Option<TransactionTracker> {
        let key = uuid.to_vec();
        let mut stmt = self
            .connection.prepare(
                "SELECT t.dispute_tx, t.penalty_tx, t.height, t.confirmed, a.user_id
                    FROM trackers as t INNER JOIN appointments as a ON t.UUID=a.UUID WHERE t.UUID=(?)"
            )
            .unwrap();

        stmt.query_row([key], |row| {
            let raw_dispute_tx: Vec<u8> = row.get(0).unwrap();
            let raw_penalty_tx: Vec<u8> = row.get(1).unwrap();
            let height: u32 = row.get(2).unwrap();
            let confirmed: bool = row.get(3).unwrap();
            let raw_userid: Vec<u8> = row.get(4).unwrap();

            let dispute_tx = consensus::deserialize(&raw_dispute_tx).unwrap();
            let penalty_tx = consensus::deserialize(&raw_penalty_tx).unwrap();
            let user_id = UserId::from_slice(&raw_userid).unwrap();

            Ok(TransactionTracker {
                dispute_tx,
                penalty_tx,
                status: ConfirmationStatus::from_db_data(height, confirmed),
                user_id,
            })
        })
        .ok()
    }

    /// Check if a tracker with `uuid` exists.
    pub(crate) fn tracker_exists(&self, uuid: UUID) -> bool {
        self.connection
            .prepare("SELECT UUID FROM trackers WHERE UUID=(?)")
            .unwrap()
            .exists([uuid.to_vec()])
            .unwrap()
    }

    /// Loads trackers from the database. If a locator is given, this method loads only the trackers
    /// matching this locator. If no locator is given, all the trackers in the database would be returned.
    pub(crate) fn load_trackers(
        &self,
        locator: Option<Locator>,
    ) -> HashMap<UUID, TransactionTracker> {
        let mut trackers = HashMap::new();

        let mut sql = "SELECT t.UUID, t.dispute_tx, t.penalty_tx, t.height, t.confirmed, a.user_id
            FROM trackers as t INNER JOIN appointments as a ON t.UUID=a.UUID"
            .to_string();
        // If a locator was passed, filter based on it.
        if locator.is_some() {
            sql.push_str(" WHERE a.locator=(?)");
        }
        let mut stmt = self.connection.prepare(&sql).unwrap();

        let mut rows = if let Some(locator) = locator {
            stmt.query([locator.to_vec()]).unwrap()
        } else {
            stmt.query([]).unwrap()
        };

        while let Ok(Some(row)) = rows.next() {
            let raw_uuid: Vec<u8> = row.get(0).unwrap();
            let uuid = UUID::from_slice(&raw_uuid[0..20]).unwrap();
            let raw_dispute_tx: Vec<u8> = row.get(1).unwrap();
            let dispute_tx = consensus::deserialize(&raw_dispute_tx).unwrap();
            let raw_penalty_tx: Vec<u8> = row.get(2).unwrap();
            let penalty_tx = consensus::deserialize(&raw_penalty_tx).unwrap();
            let height: u32 = row.get(3).unwrap();
            let confirmed: bool = row.get(4).unwrap();
            let raw_userid: Vec<u8> = row.get(5).unwrap();
            let user_id = UserId::from_slice(&raw_userid).unwrap();

            trackers.insert(
                uuid,
                TransactionTracker {
                    dispute_tx,
                    penalty_tx,
                    status: ConfirmationStatus::from_db_data(height, confirmed),
                    user_id,
                },
            );
        }

        trackers
    }

    /// Loads trackers with the given confirmation status.
    ///
    /// Note that for [`ConfirmationStatus::InMempoolSince(height)`] variant, this pulls trackers
    /// with `h <= height` and not just `h = height`.
    pub(crate) fn load_trackers_with_confirmation_status(
        &self,
        status: ConfirmationStatus,
    ) -> Result<Vec<UUID>, Error> {
        let (height, confirmed) = status.to_db_data().ok_or(Error::MissingField)?;
        let sql = format!(
            "SELECT UUID FROM trackers WHERE confirmed=(?1) AND height{}(?2)",
            if confirmed { "=" } else { "<=" }
        );
        let mut stmt = self.connection.prepare(&sql).unwrap();

        Ok(stmt
            .query_map(params![confirmed, height], |row| {
                let raw_uuid: Vec<u8> = row.get(0).unwrap();
                let uuid = UUID::from_slice(&raw_uuid).unwrap();
                Ok(uuid)
            })
            .unwrap()
            .map(|uuid_res| uuid_res.unwrap())
            .collect())
    }

    /// Loads the transaction IDs of all the penalties and their status from the database.
    pub(crate) fn load_penalties_summaries(&self) -> HashMap<UUID, PenaltySummary> {
        let mut summaries = HashMap::new();

        let mut stmt = self
            .connection
            .prepare(
                "SELECT t.UUID, t.penalty_tx, t.height, t.confirmed
                    FROM trackers as t INNER JOIN appointments as a ON t.UUID=a.UUID",
            )
            .unwrap();
        let mut rows = stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let raw_uuid: Vec<u8> = row.get(0).unwrap();
            let raw_penalty_tx: Vec<u8> = row.get(1).unwrap();
            let height: u32 = row.get(2).unwrap();
            let confirmed: bool = row.get(3).unwrap();

            // DISCUSS: Should we store the txids to avoid pulling raw txs and deserializing then hashing them.
            let penalty_txid = consensus::deserialize::<bitcoin::Transaction>(&raw_penalty_tx)
                .unwrap()
                .compute_txid();
            summaries.insert(
                UUID::from_slice(&raw_uuid).unwrap(),
                PenaltySummary::new(
                    penalty_txid,
                    ConfirmationStatus::from_db_data(height, confirmed),
                ),
            );
        }
        summaries
    }

    /// Stores the last known block into the database.
    pub(crate) fn store_last_known_block(&self, block_hash: &BlockHash) -> Result<(), Error> {
        let query = "INSERT OR REPLACE INTO last_known_block (id, block_hash) VALUES (0, ?)";
        self.store_data(query, params![block_hash.to_byte_array().to_vec()])
    }

    /// Loads the last known block from the database.
    pub fn load_last_known_block(&self) -> Option<BlockHash> {
        let mut stmt = self
            .connection
            .prepare("SELECT block_hash FROM last_known_block WHERE id=0")
            .unwrap();

        stmt.query_row([], |row| {
            let raw_hash: Vec<u8> = row.get(0).unwrap();
            Ok(BlockHash::from_slice(&raw_hash).unwrap())
        })
        .ok()
    }

    /// Stores the tower secret key into the database.
    ///
    /// When a new key is generated, old keys are not overwritten but are not retrievable from the API either.
    pub fn store_tower_key(&self, sk: &SecretKey) -> Result<(), Error> {
        let query = "INSERT INTO keys (key) VALUES (?)";
        self.store_data(query, params![sk.display_secret().to_string()])
    }

    /// Loads the last known tower secret key from the database.
    ///
    /// Loads the key with higher id from the database. Old keys are not overwritten just in case a recovery is needed,
    /// but they are not accessible from the API either.
    pub fn load_tower_key(&self) -> Option<SecretKey> {
        let mut stmt = self
            .connection
            .prepare(
                "SELECT key FROM keys WHERE id = (SELECT seq FROM sqlite_sequence WHERE name=(?))",
            )
            .unwrap();

        stmt.query_row(["keys"], |row| {
            let sk: String = row.get(0).unwrap();
            Ok(SecretKey::from_str(&sk).unwrap())
        })
        .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::iter::FromIterator;

    use teos_common::cryptography::{get_random_bytes, get_random_keypair};
    use teos_common::test_utils::{get_random_locator, get_random_user_id};

    use crate::rpc_errors;
    use crate::test_utils::{
        generate_dummy_appointment, generate_dummy_appointment_with_user, generate_uuid,
        get_random_tracker, get_random_tx, AVAILABLE_SLOTS, SUBSCRIPTION_EXPIRY,
        SUBSCRIPTION_START,
    };

    impl DBM {
        pub(crate) fn in_memory() -> Result<Self, SqliteError> {
            let connection = Connection::open_in_memory()?;
            connection.execute("PRAGMA foreign_keys=1;", [])?;
            let mut dbm = Self { connection };
            dbm.create_tables(Vec::from_iter(TABLES))?;

            Ok(dbm)
        }

        pub(crate) fn load_user(&self, user_id: UserId) -> Option<UserInfo> {
            let key = user_id.to_vec();
            let mut stmt = self
                .connection
                .prepare(
                    "SELECT available_slots, subscription_start, subscription_expiry
                        FROM users WHERE user_id=(?)",
                )
                .unwrap();
            stmt.query_row([&key], |row| {
                let slots = row.get(0).unwrap();
                let start = row.get(1).unwrap();
                let expiry = row.get(2).unwrap();
                Ok(UserInfo::new(slots, start, expiry))
            })
            .ok()
        }
    }

    #[test]
    fn test_create_tables() {
        let connection = Connection::open_in_memory().unwrap();
        let mut dbm = DBM { connection };
        dbm.create_tables(Vec::from_iter(TABLES)).unwrap();
    }

    #[test]
    fn test_store_load_user() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let mut user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);

        assert!(matches!(dbm.store_user(user_id, &user), Ok { .. }));
        assert_eq!(dbm.load_user(user_id).unwrap(), user);

        // User info should be updatable but only via the update_user method
        user = UserInfo::new(AVAILABLE_SLOTS * 2, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        assert!(matches!(
            dbm.store_user(user_id, &user),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn test_load_nonexistent_user() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        assert!(dbm.load_user(user_id).is_none());
    }

    #[test]
    fn test_update_user() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let mut user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);

        dbm.store_user(user_id, &user).unwrap();
        assert_eq!(dbm.load_user(user_id).unwrap(), user);

        user.available_slots *= 2;
        dbm.update_user(user_id, &user);
        assert_eq!(dbm.load_user(user_id).unwrap(), user);
    }

    #[test]
    fn test_load_user_locators() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).unwrap();

        let mut locators = HashSet::new();

        // Add some appointments to the user
        for _ in 0..10 {
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            dbm.store_appointment(uuid, &appointment).unwrap();
            locators.insert(appointment.locator());
        }

        assert_eq!(dbm.load_user(user_id).unwrap(), user);
        assert_eq!(
            HashSet::from_iter(dbm.load_user_locators(user_id)),
            locators
        );
    }

    #[test]
    fn test_load_all_users() {
        let dbm = DBM::in_memory().unwrap();
        let mut users = HashMap::new();

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(
                AVAILABLE_SLOTS + i,
                SUBSCRIPTION_START + i,
                SUBSCRIPTION_EXPIRY + i,
            );
            users.insert(user_id, user);
            dbm.store_user(user_id, &user).unwrap();
        }

        assert_eq!(dbm.load_all_users(), users);
    }

    #[test]
    fn test_batch_remove_users() {
        let mut dbm = DBM::in_memory().unwrap();

        // Set a limit value for the maximum number of variables in SQLite so we can
        // test splitting big queries into chunks.
        let limit = 10;
        dbm.connection
            .set_limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER, limit);

        let mut to_be_deleted = Vec::new();
        let mut rest = HashSet::new();
        for i in 1..100 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
            dbm.store_user(user_id, &user).unwrap();

            if i % 2 == 0 {
                to_be_deleted.push(user_id);
            } else {
                rest.insert(user_id);
            }
        }

        // Check that the db transaction had 5 (100/2*10) queries on it
        assert_eq!(dbm.batch_remove_users(&to_be_deleted), 5);
        // Check user data was deleted
        assert_eq!(rest, dbm.load_all_users().keys().cloned().collect());
    }

    #[test]
    fn test_batch_remove_users_cascade() {
        // Test that removing users cascade deleted appointments and trackers
        let mut dbm = DBM::in_memory().unwrap();
        let uuid = generate_uuid();
        let appointment = generate_dummy_appointment(None);
        // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
        let tracker = get_random_tracker(appointment.user_id, ConfirmationStatus::ConfirmedIn(100));

        // Add the user and link an appointment (this is usually done once the appointment)
        // is added after the user creation, but for the test purpose it can be done all at once.
        let info = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(appointment.user_id, &info).unwrap();

        // Appointment only
        assert!(matches!(
            dbm.store_appointment(uuid, &appointment),
            Ok { .. }
        ));

        dbm.batch_remove_users(&[appointment.user_id]);
        assert!(dbm.load_user(appointment.user_id).is_none());
        assert!(dbm.load_appointment(uuid).is_none());

        // Appointment + Tracker
        dbm.store_user(appointment.user_id, &info).unwrap();
        assert!(matches!(
            dbm.store_appointment(uuid, &appointment),
            Ok { .. }
        ));
        assert!(matches!(dbm.store_tracker(uuid, &tracker), Ok { .. }));

        dbm.batch_remove_users(&[appointment.user_id]);
        assert!(dbm.load_user(appointment.user_id).is_none());
        assert!(dbm.load_appointment(uuid).is_none());
        assert!(dbm.load_tracker(uuid).is_none());
    }

    #[test]
    fn test_batch_remove_nonexistent_users() {
        let mut dbm = DBM::in_memory().unwrap();
        let users = (0..10).map(|_| get_random_user_id()).collect::<Vec<_>>();

        // Test it does not fail even if the user does not exist (it will log though)
        dbm.batch_remove_users(&users);
    }

    #[test]
    fn test_get_appointments_trackers_count() {
        let dbm = DBM::in_memory().unwrap();
        let n_users = 100;
        let n_app_per_user = 4;
        let n_trk_per_user = 6;

        for _ in 0..n_users {
            let user_id = get_random_user_id();
            let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
            dbm.store_user(user_id, &user).unwrap();

            // These are un-triggered appointments.
            for _ in 0..n_app_per_user {
                let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
                dbm.store_appointment(uuid, &appointment).unwrap();
            }

            // And these are triggered ones (trackers).
            for _ in 0..n_trk_per_user {
                let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
                dbm.store_appointment(uuid, &appointment).unwrap();
                let tracker = get_random_tracker(user_id, ConfirmationStatus::ConfirmedIn(42));
                dbm.store_tracker(uuid, &tracker).unwrap();
            }
        }

        assert_eq!(dbm.get_appointments_count(), n_users * n_app_per_user);
        assert_eq!(dbm.get_trackers_count(), n_users * n_trk_per_user);
    }

    #[test]
    fn test_store_load_appointment() {
        let dbm = DBM::in_memory().unwrap();

        // In order to add an appointment we need the associated user to be present
        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);

        assert!(matches!(
            dbm.store_appointment(uuid, &appointment),
            Ok { .. }
        ));
        assert_eq!(dbm.load_appointment(uuid).unwrap(), appointment);

        // Appointment info should be updatable but only via the update_appointment method
        assert!(matches!(
            dbm.store_appointment(uuid, &appointment),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn test_store_appointment_missing_user() {
        let dbm = DBM::in_memory().unwrap();

        let uuid = generate_uuid();
        let appointment = generate_dummy_appointment(None);

        assert!(matches!(
            dbm.store_appointment(uuid, &appointment),
            Err(Error::MissingForeignKey)
        ));
        assert!((dbm.load_tracker(uuid).is_none()));
    }

    #[test]
    fn test_load_nonexistent_appointment() {
        let dbm = DBM::in_memory().unwrap();

        let uuid = generate_uuid();
        assert!(dbm.load_appointment(uuid).is_none());
    }

    #[test]
    fn test_appointment_exists() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);

        assert!(!dbm.appointment_exists(uuid));

        dbm.store_user(user_id, &user).unwrap();
        dbm.store_appointment(uuid, &appointment).unwrap();

        assert!(dbm.appointment_exists(uuid));
    }

    #[test]
    fn test_update_appointment() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        assert!(matches!(
            dbm.store_appointment(uuid, &appointment),
            Ok { .. }
        ));

        // Modify the appointment and update it
        let mut modified_appointment = appointment;
        modified_appointment.inner.encrypted_blob.reverse();

        // Not all fields are updatable, create another appointment modifying fields that cannot be
        let mut another_modified_appointment = modified_appointment.clone();
        another_modified_appointment.user_id = get_random_user_id();

        // Check how only the modifiable fields have been updated
        dbm.update_appointment(uuid, &another_modified_appointment)
            .unwrap();
        assert_eq!(dbm.load_appointment(uuid).unwrap(), modified_appointment);
        assert_ne!(
            dbm.load_appointment(uuid).unwrap(),
            another_modified_appointment
        );
    }

    #[test]
    fn test_load_all_appointments() {
        let dbm = DBM::in_memory().unwrap();
        let mut appointments = HashMap::new();

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(
                AVAILABLE_SLOTS + i,
                SUBSCRIPTION_START + i,
                SUBSCRIPTION_EXPIRY + i,
            );
            dbm.store_user(user_id, &user).unwrap();

            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            dbm.store_appointment(uuid, &appointment).unwrap();
            appointments.insert(uuid, appointment);
        }

        assert_eq!(dbm.load_appointments(None), appointments);

        // If an appointment has an associated tracker, it should not be loaded since it is seen
        // as a triggered appointment
        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        dbm.store_appointment(uuid, &appointment).unwrap();

        // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
        let tracker = get_random_tracker(user_id, ConfirmationStatus::InMempoolSince(100));
        dbm.store_tracker(uuid, &tracker).unwrap();

        // We should get all the appointments back except from the triggered one
        assert_eq!(dbm.load_appointments(None), appointments);
    }

    #[test]
    fn test_load_appointments_with_locator() {
        let dbm = DBM::in_memory().unwrap();
        let mut appointments = HashMap::new();
        let dispute_tx = get_random_tx();
        let dispute_txid = dispute_tx.compute_txid();
        let locator = Locator::new(dispute_txid);

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(
                AVAILABLE_SLOTS + i,
                SUBSCRIPTION_START + i,
                SUBSCRIPTION_EXPIRY + i,
            );
            dbm.store_user(user_id, &user).unwrap();

            // Let some appointments belong to a specific dispute tx and some with random ones.
            // We will use the locator for that dispute tx to query these appointments.
            if i % 2 == 0 {
                let (uuid, appointment) =
                    generate_dummy_appointment_with_user(user_id, Some(&dispute_txid));
                dbm.store_appointment(uuid, &appointment).unwrap();
                // Store the appointments made using our dispute tx.
                appointments.insert(uuid, appointment);
            } else {
                let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
                dbm.store_appointment(uuid, &appointment).unwrap();
            }
        }

        // Validate that no other appointments than the ones with our locator are returned.
        assert_eq!(dbm.load_appointments(Some(locator)), appointments);

        // If an appointment has an associated tracker, it should not be loaded since it is seen
        // as a triggered appointment
        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).unwrap();

        // Generate an appointment for our dispute tx, thus it gets the same locator as the ones generated above.
        let (uuid, appointment) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_txid));
        dbm.store_appointment(uuid, &appointment).unwrap();

        // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
        let tracker = get_random_tracker(user_id, ConfirmationStatus::InMempoolSince(100));
        dbm.store_tracker(uuid, &tracker).unwrap();

        // We should get all the appointments matching our locator back except from the triggered one
        assert_eq!(dbm.load_appointments(Some(locator)), appointments);
    }

    #[test]
    fn test_get_appointment_length() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);

        dbm.store_user(user_id, &user).unwrap();
        dbm.store_appointment(uuid, &appointment).unwrap();

        assert_eq!(
            dbm.get_appointment_length(uuid).unwrap(),
            appointment.inner.encrypted_blob.len()
        );
        assert!(dbm.get_appointment_length(generate_uuid()).is_none());
    }

    #[test]
    fn test_get_appointment_user_and_length() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);

        dbm.store_user(user_id, &user).unwrap();
        dbm.store_appointment(uuid, &appointment).unwrap();

        assert_eq!(
            dbm.get_appointment_user_and_length(uuid).unwrap(),
            (user_id, appointment.encrypted_blob().len())
        );
        assert!(dbm
            .get_appointment_user_and_length(generate_uuid())
            .is_none());
    }

    #[test]
    fn test_batch_remove_appointments() {
        let mut dbm = DBM::in_memory().unwrap();

        // Set a limit value for the maximum number of variables in SQLite so we can
        // test splitting big queries into chunks.
        let limit = 10;
        dbm.connection
            .set_limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER, limit);

        let user_id = get_random_user_id();
        let mut user = UserInfo::new(
            AVAILABLE_SLOTS + 123,
            SUBSCRIPTION_START,
            SUBSCRIPTION_EXPIRY,
        );
        dbm.store_user(user_id, &user).unwrap();

        let mut rest = HashSet::new();
        for i in 1..6 {
            let mut to_be_deleted = Vec::new();
            for j in 0..limit * 2 * i {
                let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
                dbm.store_appointment(uuid, &appointment).unwrap();

                if j % 2 == 0 {
                    to_be_deleted.push(uuid);
                } else {
                    rest.insert(uuid);
                }
            }

            // When the appointment are deleted, the user will get back slots based on the deleted data.
            // Here we can just make a number up to make sure it matches.
            user.available_slots = i as u32;
            let updated_users = HashMap::from_iter([(user_id, user)]);

            // Check that the db transaction had i queries on it
            assert_eq!(
                dbm.batch_remove_appointments(&to_be_deleted, &updated_users),
                i as usize
            );
            // Check appointment data was deleted and users properly updated
            assert_eq!(rest, dbm.load_appointments(None).keys().cloned().collect());
            assert_eq!(
                dbm.load_user(user_id).unwrap().available_slots,
                user.available_slots
            );
        }
    }

    #[test]
    fn test_batch_remove_appointments_cascade() {
        let mut dbm = DBM::in_memory().unwrap();
        let uuid = generate_uuid();
        let appointment = generate_dummy_appointment(None);
        // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
        let tracker = get_random_tracker(appointment.user_id, ConfirmationStatus::ConfirmedIn(21));

        let info = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);

        // Add the user b/c of FK restrictions
        dbm.store_user(appointment.user_id, &info).unwrap();

        // Appointment only
        assert!(matches!(
            dbm.store_appointment(uuid, &appointment),
            Ok { .. }
        ));

        dbm.batch_remove_appointments(&[uuid], &HashMap::from_iter([(appointment.user_id, info)]));
        assert!(dbm.load_appointment(uuid).is_none());

        // Appointment + Tracker
        assert!(matches!(
            dbm.store_appointment(uuid, &appointment),
            Ok { .. }
        ));
        assert!(matches!(dbm.store_tracker(uuid, &tracker), Ok { .. }));

        dbm.batch_remove_appointments(&[uuid], &HashMap::from_iter([(appointment.user_id, info)]));
        assert!(dbm.load_appointment(uuid).is_none());
        assert!(dbm.load_tracker(uuid).is_none());
    }

    #[test]
    fn test_batch_remove_nonexistent_appointments() {
        let mut dbm = DBM::in_memory().unwrap();
        let appointments = (0..10).map(|_| generate_uuid()).collect::<Vec<_>>();

        // Test it does not fail even if the user does not exist (it will log though)
        dbm.batch_remove_appointments(&appointments, &HashMap::new());
    }

    #[test]
    fn test_load_uuids() {
        let dbm = DBM::in_memory().unwrap();

        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        let dispute_tx = get_random_tx();
        let dispute_txid = dispute_tx.compute_txid();
        let mut uuids = HashSet::new();

        // Add ten appointments triggered by the same locator.
        for _ in 0..10 {
            let user_id = get_random_user_id();
            dbm.store_user(user_id, &user).unwrap();

            let (uuid, appointment) =
                generate_dummy_appointment_with_user(user_id, Some(&dispute_txid));
            dbm.store_appointment(uuid, &appointment).unwrap();

            uuids.insert(uuid);
        }

        // Add ten more appointments triggered by different locators.
        for _ in 0..10 {
            let user_id = get_random_user_id();
            dbm.store_user(user_id, &user).unwrap();

            let dispute_txid = get_random_tx().compute_txid();
            let (uuid, appointment) =
                generate_dummy_appointment_with_user(user_id, Some(&dispute_txid));
            dbm.store_appointment(uuid, &appointment).unwrap();
        }

        assert_eq!(
            HashSet::from_iter(dbm.load_uuids(Locator::new(dispute_txid))),
            uuids
        );
    }

    #[test]
    fn test_batch_check_locators_exist() {
        let dbm = DBM::in_memory().unwrap();
        // Generate `n_app` appointments which we will store in the DB.
        let n_app = 100;
        let appointments: Vec<_> = (0..n_app)
            .map(|_| generate_dummy_appointment(None))
            .collect();

        // Register all the users beforehand.
        for user_id in appointments.iter().map(|a| a.user_id) {
            let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
            dbm.store_user(user_id, &user).unwrap();
        }

        // Store all the `n_app` appointments.
        for appointment in appointments.iter() {
            dbm.store_appointment(appointment.uuid(), appointment)
                .unwrap();
        }

        // Select `n_app / 5` locators as if they appeared in a new block.
        let known_locators: HashSet<_> = appointments
            .iter()
            .take(n_app / 5)
            .map(|a| a.locator())
            .collect();
        // And extra `n_app / 5` unknown locators.
        let unknown_locators: HashSet<_> = (0..n_app / 5).map(|_| get_random_locator()).collect();
        let all_locators = known_locators
            .iter()
            .chain(unknown_locators.iter())
            .collect();

        assert_eq!(
            HashSet::from_iter(dbm.batch_check_locators_exist(all_locators)),
            known_locators
        );
    }

    #[test]
    fn test_store_load_tracker() {
        let dbm = DBM::in_memory().unwrap();

        // In order to add a tracker we need the associated appointment to be present (which
        // at the same time requires an associated user to be present)
        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        dbm.store_appointment(uuid, &appointment).unwrap();

        // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
        let tracker = get_random_tracker(user_id, ConfirmationStatus::ConfirmedIn(21));
        assert!(matches!(dbm.store_tracker(uuid, &tracker), Ok { .. }));
        assert_eq!(dbm.load_tracker(uuid).unwrap(), tracker);
    }

    #[test]
    fn test_store_duplicate_tracker() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        dbm.store_appointment(uuid, &appointment).unwrap();

        // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
        let tracker = get_random_tracker(user_id, ConfirmationStatus::InMempoolSince(42));
        assert!(matches!(dbm.store_tracker(uuid, &tracker), Ok { .. }));

        // Try to store it again, but it shouldn't go through
        assert!(matches!(
            dbm.store_tracker(uuid, &tracker),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn test_store_tracker_missing_appointment() {
        let dbm = DBM::in_memory().unwrap();

        let uuid = generate_uuid();
        let user_id = get_random_user_id();

        // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
        let tracker = get_random_tracker(user_id, ConfirmationStatus::InMempoolSince(42));

        assert!(matches!(
            dbm.store_tracker(uuid, &tracker),
            Err(Error::MissingForeignKey)
        ));
    }

    #[test]
    fn test_update_tracker_status() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        dbm.store_appointment(uuid, &appointment).unwrap();

        let tracker = get_random_tracker(user_id, ConfirmationStatus::InMempoolSince(42));
        dbm.store_tracker(uuid, &tracker).unwrap();

        // Update the status and check if it's actually updated.
        dbm.update_tracker_status(uuid, &ConfirmationStatus::ConfirmedIn(100))
            .unwrap();
        assert_eq!(
            dbm.load_tracker(uuid).unwrap().status,
            ConfirmationStatus::ConfirmedIn(100)
        );

        // Rejected status doesn't have a persistent DB representation.
        assert!(matches!(
            dbm.update_tracker_status(
                uuid,
                &ConfirmationStatus::Rejected(rpc_errors::RPC_VERIFY_REJECTED)
            ),
            Err(Error::MissingField)
        ));
    }

    #[test]
    fn test_load_nonexistent_tracker() {
        let dbm = DBM::in_memory().unwrap();

        let uuid = generate_uuid();
        assert!(dbm.load_tracker(uuid).is_none());
    }

    #[test]
    fn test_load_all_trackers() {
        let dbm = DBM::in_memory().unwrap();
        let mut trackers = HashMap::new();

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(
                AVAILABLE_SLOTS + i,
                SUBSCRIPTION_START + i,
                SUBSCRIPTION_EXPIRY + i,
            );
            dbm.store_user(user_id, &user).unwrap();

            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            dbm.store_appointment(uuid, &appointment).unwrap();

            // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
            let tracker = get_random_tracker(user_id, ConfirmationStatus::InMempoolSince(42));
            dbm.store_tracker(uuid, &tracker).unwrap();
            trackers.insert(uuid, tracker);
        }

        assert_eq!(dbm.load_trackers(None), trackers);
    }

    #[test]
    fn test_load_trackers_with_locator() {
        let dbm = DBM::in_memory().unwrap();
        let mut trackers = HashMap::new();
        let dispute_tx = get_random_tx();
        let dispute_txid = dispute_tx.compute_txid();
        let locator = Locator::new(dispute_txid);
        let status = ConfirmationStatus::InMempoolSince(42);

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(
                AVAILABLE_SLOTS + i,
                SUBSCRIPTION_START + i,
                SUBSCRIPTION_EXPIRY + i,
            );
            dbm.store_user(user_id, &user).unwrap();
            let tracker = get_random_tracker(user_id, status);

            // Let some trackers belong to our dispute tx and some belong to random ones.
            let (uuid, appointment) = if i % 2 == 0 {
                let (uuid, app) =
                    generate_dummy_appointment_with_user(user_id, Some(&dispute_txid));
                // Store the trackers of appointments made with our dispute tx.
                trackers.insert(uuid, tracker.clone());
                (uuid, app)
            } else {
                generate_dummy_appointment_with_user(user_id, None)
            };
            dbm.store_appointment(uuid, &appointment).unwrap();
            dbm.store_tracker(uuid, &tracker).unwrap();
        }

        assert_eq!(dbm.load_trackers(Some(locator)), trackers);
    }

    #[test]
    fn test_load_trackers_with_confirmation_status_in_mempool() {
        let dbm = DBM::in_memory().unwrap();
        let n_trackers = 100;
        let mut tracker_statuses = HashMap::new();

        // Store a bunch of trackers.
        for i in 0..n_trackers {
            let user_id = get_random_user_id();
            let user = UserInfo::new(
                AVAILABLE_SLOTS + i,
                SUBSCRIPTION_START + i,
                SUBSCRIPTION_EXPIRY + i,
            );
            dbm.store_user(user_id, &user).unwrap();

            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            dbm.store_appointment(uuid, &appointment).unwrap();

            // Some trackers confirmed and some aren't.
            let status = if i % 2 == 0 {
                ConfirmationStatus::InMempoolSince(i)
            } else {
                ConfirmationStatus::ConfirmedIn(i)
            };

            let tracker = get_random_tracker(user_id, status);
            dbm.store_tracker(uuid, &tracker).unwrap();
            tracker_statuses.insert(uuid, status);
        }

        for i in 0..n_trackers + 10 {
            let in_mempool_since_i: HashSet<UUID> = tracker_statuses
                .iter()
                .filter_map(|(&uuid, &status)| {
                    if let ConfirmationStatus::InMempoolSince(x) = status {
                        // If a tracker was in mempool since x, then it's also in mempool since x + 1, x + 2, etc...
                        return (x <= i).then_some(uuid);
                    }
                    None
                })
                .collect();
            assert_eq!(
                HashSet::from_iter(
                    dbm.load_trackers_with_confirmation_status(ConfirmationStatus::InMempoolSince(
                        i
                    ))
                    .unwrap()
                ),
                in_mempool_since_i,
            );
        }
    }

    #[test]
    fn test_load_trackers_with_confirmation_status_confirmed() {
        let dbm = DBM::in_memory().unwrap();
        let n_blocks = 100;
        let n_trackers = 30;
        let mut tracker_statuses = HashMap::new();

        // Loop over a bunch of blocks.
        for i in 0..n_blocks {
            // Store a bunch of trackers in each block.
            for j in 0..n_trackers {
                let user_id = get_random_user_id();
                let user = UserInfo::new(
                    AVAILABLE_SLOTS + i,
                    SUBSCRIPTION_START + i,
                    SUBSCRIPTION_EXPIRY + i,
                );
                dbm.store_user(user_id, &user).unwrap();

                let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
                dbm.store_appointment(uuid, &appointment).unwrap();

                // Some trackers confirmed and some aren't.
                let status = if j % 2 == 0 {
                    ConfirmationStatus::InMempoolSince(i)
                } else {
                    ConfirmationStatus::ConfirmedIn(i)
                };

                let tracker = get_random_tracker(user_id, status);
                dbm.store_tracker(uuid, &tracker).unwrap();
                tracker_statuses.insert(uuid, status);
            }
        }

        for i in 0..n_blocks + 10 {
            let confirmed_in_i: HashSet<UUID> = tracker_statuses
                .iter()
                .filter_map(|(&uuid, &status)| {
                    if let ConfirmationStatus::ConfirmedIn(x) = status {
                        return (x == i).then_some(uuid);
                    }
                    None
                })
                .collect();
            assert_eq!(
                HashSet::from_iter(
                    dbm.load_trackers_with_confirmation_status(ConfirmationStatus::ConfirmedIn(i))
                        .unwrap()
                ),
                confirmed_in_i,
            );
        }
    }

    #[test]
    fn test_load_trackers_with_confirmation_status_bad_status() {
        let dbm = DBM::in_memory().unwrap();

        assert!(matches!(
            dbm.load_trackers_with_confirmation_status(ConfirmationStatus::Rejected(
                rpc_errors::RPC_VERIFY_REJECTED
            )),
            Err(Error::MissingField)
        ));

        assert!(matches!(
            dbm.load_trackers_with_confirmation_status(ConfirmationStatus::IrrevocablyResolved),
            Err(Error::MissingField)
        ));
    }

    #[test]
    fn test_load_penalties_summaries() {
        let dbm = DBM::in_memory().unwrap();
        let n_trackers = 100;
        let mut penalties_summaries = HashMap::new();

        for i in 0..n_trackers {
            let user_id = get_random_user_id();
            let user = UserInfo::new(
                AVAILABLE_SLOTS + i,
                SUBSCRIPTION_START + i,
                SUBSCRIPTION_EXPIRY + i,
            );
            dbm.store_user(user_id, &user).unwrap();

            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            dbm.store_appointment(uuid, &appointment).unwrap();

            let status = if i % 2 == 0 {
                ConfirmationStatus::InMempoolSince(i)
            } else {
                ConfirmationStatus::ConfirmedIn(i)
            };

            let tracker = get_random_tracker(user_id, status);
            dbm.store_tracker(uuid, &tracker).unwrap();

            penalties_summaries.insert(
                uuid,
                PenaltySummary::new(tracker.penalty_tx.compute_txid(), status),
            );
        }

        assert_eq!(dbm.load_penalties_summaries(), penalties_summaries);
    }

    #[test]
    fn test_store_load_last_known_block() {
        let dbm = DBM::in_memory().unwrap();

        let mut block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
        dbm.store_last_known_block(&block_hash).unwrap();
        assert_eq!(dbm.load_last_known_block().unwrap(), block_hash);

        // Update with a new hash to check it can be done
        block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
        dbm.store_last_known_block(&block_hash).unwrap();
        assert_eq!(dbm.load_last_known_block().unwrap(), block_hash);
    }

    #[test]
    fn test_store_load_nonexistent_last_known_block() {
        let dbm = DBM::in_memory().unwrap();

        assert!(dbm.load_last_known_block().is_none());
    }

    #[test]
    fn test_store_load_tower_key() {
        let dbm = DBM::in_memory().unwrap();

        assert!(dbm.load_tower_key().is_none());
        for _ in 0..7 {
            let sk = get_random_keypair().0;
            dbm.store_tower_key(&sk).unwrap();
            assert_eq!(dbm.load_tower_key().unwrap(), sk);
        }
    }
}
