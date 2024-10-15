use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::path::PathBuf;
use std::str::FromStr;

use rusqlite::{params, Connection, Error as SqliteError, ToSql};

use bitcoin::secp256k1::SecretKey;

use teos_common::appointment::{Appointment, Locator};
use teos_common::dbm::{DatabaseConnection, DatabaseManager, Error};
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::{TowerId, UserId};

use crate::{AppointmentStatus, MisbehaviorProof, TowerInfo, TowerStatus, TowerSummary};

const TABLES: [&str; 8] = [
    "CREATE TABLE IF NOT EXISTS towers (
    tower_id INT PRIMARY KEY,
    net_addr TEXT NOT NULL,
    available_slots INT NOT NULL
)",
    "CREATE TABLE IF NOT EXISTS appointments (
    locator INT PRIMARY KEY,
    encrypted_blob BLOB,
    to_self_delay INT
)",
    "CREATE TABLE IF NOT EXISTS pending_appointments (
    locator INT NOT NULL,
    tower_id INT NOT NULL,
    PRIMARY KEY (locator, tower_id),
    FOREIGN KEY(locator)
        REFERENCES appointments(locator)
        ON DELETE CASCADE
    FOREIGN KEY(tower_id)
        REFERENCES towers(tower_id)
        ON DELETE CASCADE
)",
    "CREATE TABLE IF NOT EXISTS invalid_appointments (
    locator INT NOT NULL,
    tower_id INT NOT NULL,
    PRIMARY KEY (locator, tower_id),
    FOREIGN KEY(locator)
        REFERENCES appointments(locator)
        ON DELETE CASCADE
    FOREIGN KEY(tower_id)
        REFERENCES towers(tower_id)
        ON DELETE CASCADE
)",
    "CREATE TABLE IF NOT EXISTS registration_receipts (
    tower_id INT NOT NULL,
    available_slots INT NOT NULL,
    subscription_start INT NOT NULL,
    subscription_expiry INT NOT NULL,
    signature BLOB NOT NULL,
    PRIMARY KEY (tower_id, subscription_expiry),
    FOREIGN KEY(tower_id)
        REFERENCES towers(tower_id)
        ON DELETE CASCADE
)",
    "CREATE TABLE IF NOT EXISTS appointment_receipts (
    locator INT NOT NULL,
    tower_id INT NOT NULL,
    start_block INT NOT NULL,
    user_signature BLOB NOT NULL,
    tower_signature BLOB NOT NULL,
    PRIMARY KEY (locator, tower_id),
    FOREIGN KEY(tower_id)
        REFERENCES towers(tower_id)
        ON DELETE CASCADE
)",
    "CREATE TABLE IF NOT EXISTS misbehaving_proofs (
    tower_id INT PRIMARY KEY,
    locator INT NOT NULL,
    recovered_id INT NOT NULL,
    FOREIGN KEY(locator, tower_id)
        REFERENCES appointment_receipts(locator, tower_id)
        ON DELETE CASCADE
)",
    "CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key INT NOT NULL
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
    pub fn new(db_path: &PathBuf) -> Result<Self, SqliteError> {
        let connection = Connection::open(db_path)?;
        connection.execute("PRAGMA foreign_keys=1;", [])?;
        let mut dbm = Self { connection };
        dbm.create_tables(Vec::from_iter(TABLES))?;

        Ok(dbm)
    }

    /// Stores the client secret key into the database.
    ///
    /// When a new key is generated, old keys are not overwritten but are not retrievable from the API either.
    pub fn store_client_key(&self, sk: &SecretKey) -> Result<(), Error> {
        let query = "INSERT INTO keys (key) VALUES (?)";
        self.store_data(query, params![sk.display_secret().to_string()])
    }

    /// Loads the last known client secret key from the database.
    ///
    /// Loads the key with higher id from the database. Old keys are not overwritten just in case a recovery is needed,
    /// but they are not accessible from the API either.
    pub fn load_client_key(&self) -> Option<SecretKey> {
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

    /// Stores a tower record into the database alongside the corresponding registration receipt.
    ///
    /// This function MUST be guarded against inserting duplicate (tower_id, subscription_expiry) pairs.
    /// This is currently done in WTClient::add_update_tower.
    pub fn store_tower_record(
        &mut self,
        tower_id: TowerId,
        net_addr: &str,
        receipt: &RegistrationReceipt,
    ) -> Result<(), Error> {
        let tx = self.get_mut_connection().transaction().unwrap();
        tx.execute(
            "INSERT INTO towers (tower_id, net_addr, available_slots) 
                VALUES (?1, ?2, ?3) 
                ON CONFLICT (tower_id) DO UPDATE SET net_addr = ?2, available_slots = ?3",
            params![tower_id.to_vec(), net_addr, receipt.available_slots()],
        )
        .map_err(Error::Unknown)?;
        tx.execute(
                "INSERT INTO registration_receipts (tower_id, available_slots, subscription_start, subscription_expiry, signature) 
                    VALUES (?1, ?2, ?3, ?4, ?5)",
                params![tower_id.to_vec(), receipt.available_slots(), receipt.subscription_start(), receipt.subscription_expiry(), receipt.signature()]).map_err( Error::Unknown)?;

        tx.commit().map_err(Error::Unknown)
    }

    /// Loads a tower record from the database.
    ///
    /// Tower records are composed from the tower information and the appointment data. The latter is split in:
    /// accepted appointments (represented by appointment receipts), pending appointments and invalid appointments.
    /// In the case that the tower has misbehaved, then a misbehaving proof is also attached to the record.
    pub fn load_tower_record(&self, tower_id: TowerId) -> Option<TowerInfo> {
        let mut stmt = self
        .connection
        .prepare("SELECT t.net_addr, t.available_slots, r.subscription_start, r.subscription_expiry 
                    FROM towers as t, registration_receipts as r 
                    WHERE t.tower_id = r.tower_id AND t.tower_id = ?1 AND r.subscription_expiry = (SELECT MAX(subscription_expiry) 
                        FROM registration_receipts 
                        WHERE tower_id = ?1)")
        .unwrap();

        let mut tower = stmt
            .query_row([tower_id.to_vec()], |row| {
                let net_addr: String = row.get(0).unwrap();
                let available_slots: u32 = row.get(1).unwrap();
                let subscription_start: u32 = row.get(2).unwrap();
                let subscription_expiry: u32 = row.get(3).unwrap();
                Ok(TowerInfo::new(
                    net_addr,
                    available_slots,
                    subscription_start,
                    subscription_expiry,
                    self.load_appointment_receipts(tower_id),
                    self.load_appointments(tower_id, AppointmentStatus::Pending),
                    self.load_appointments(tower_id, AppointmentStatus::Invalid),
                ))
            })
            .ok()?;

        if let Some(proof) = self.load_misbehaving_proof(tower_id) {
            tower.status = TowerStatus::Misbehaving;
            tower.set_misbehaving_proof(proof);
        } else if !tower.pending_appointments.is_empty() {
            tower.status = TowerStatus::TemporaryUnreachable;
        }

        Some(tower)
    }

    /// Loads the registration receipt(s) for a given tower in the given subscription range.
    /// If no range is given, then loads the latest receipt
    /// Latests is determined by the one with the `subscription_expiry` further into the future.
    pub fn load_registration_receipt(
        &self,
        tower_id: TowerId,
        user_id: UserId,
        subscription_start: Option<u32>,
        subscription_expiry: Option<u32>,
    ) -> Option<Vec<RegistrationReceipt>> {
        let mut query = "SELECT available_slots, subscription_start, subscription_expiry, signature FROM registration_receipts WHERE tower_id = ?1".to_string();

        let tower_id_encoded = tower_id.to_vec();
        let mut params: Vec<&dyn ToSql> = vec![&tower_id_encoded];

        if subscription_expiry.is_none() {
            query.push_str(" AND subscription_expiry = (SELECT MAX(subscription_expiry) FROM registration_receipts WHERE tower_id = ?1)")
        } else {
            query.push_str(" AND subscription_start>=?2 AND subscription_expiry <=?3");
            params.push(&subscription_start);
            params.push(&subscription_expiry)
        }
        let mut stmt = self.connection.prepare(&query).unwrap();

        stmt.query_map(params.as_slice(), |row| {
            let slots: u32 = row.get(0)?;
            let start: u32 = row.get(1)?;
            let expiry: u32 = row.get(2)?;
            let signature: String = row.get(3)?;

            Ok(RegistrationReceipt::with_signature(
                user_id, slots, start, expiry, signature,
            ))
        })
        .unwrap()
        .map(|r| r.ok())
        .collect()
    }

    /// Removes a tower record from the database.
    ///
    /// This triggers a cascade deletion of all related data, such as appointments, appointment receipts, etc. As long as there is a single
    /// reference to them.
    pub fn remove_tower_record(&self, tower_id: TowerId) -> Result<(), Error> {
        let query = "DELETE FROM towers WHERE tower_id=?";
        self.remove_data(query, params![tower_id.to_vec()])
    }

    /// Loads all tower records from the database.
    pub fn load_towers(&self) -> HashMap<TowerId, TowerSummary> {
        let mut towers = HashMap::new();
        let mut stmt = self
            .connection
            .prepare("SELECT tw.tower_id, tw.net_addr, tw.available_slots, rr.subscription_start, rr.subscription_expiry 
                        FROM towers AS tw 
                        JOIN registration_receipts AS rr 
                        JOIN (SELECT tower_id, MAX(subscription_expiry) AS max_se 
                            FROM registration_receipts 
                            GROUP BY tower_id) AS max_rrs ON (tw.tower_id = rr.tower_id) 
                        AND (rr.tower_id = max_rrs.tower_id) 
                        AND (rr.subscription_expiry = max_rrs.max_se)")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let raw_towerid: Vec<u8> = row.get(0).unwrap();
            let tower_id = TowerId::from_slice(&raw_towerid).unwrap();
            let net_addr: String = row.get(1).unwrap();
            let available_slots: u32 = row.get(2).unwrap();
            let start: u32 = row.get(3).unwrap();
            let expiry: u32 = row.get(4).unwrap();

            let mut tower = TowerSummary::with_appointments(
                net_addr,
                available_slots,
                start,
                expiry,
                self.load_appointment_locators(tower_id, AppointmentStatus::Pending),
                self.load_appointment_locators(tower_id, AppointmentStatus::Invalid),
            );

            if self.exists_misbehaving_proof(tower_id) {
                tower.status = TowerStatus::Misbehaving;
            } else if !tower.pending_appointments.is_empty() {
                // TODO: We could set the status to SubscriptionError here if we checked the state of the subscription
                // (using available_slots and expiry). This will be possible once we implement cln rpc queries (which are
                // already viable since cln-plugin = "0.1.1").
                tower.status = TowerStatus::TemporaryUnreachable;
            }

            towers.insert(tower_id, tower);
        }

        towers
    }

    /// Stores an appointments receipt into the database representing an appointment accepted by a given tower.
    pub fn store_appointment_receipt(
        &mut self,
        tower_id: TowerId,
        locator: Locator,
        available_slots: u32,
        receipt: &AppointmentReceipt,
    ) -> Result<(), SqliteError> {
        let tx = self.get_mut_connection().transaction().unwrap();
        tx.execute(
            "INSERT INTO appointment_receipts (locator, tower_id, start_block, user_signature, tower_signature) 
                VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                locator.to_vec(),
                tower_id.to_vec(),
                receipt.start_block(),
                receipt.user_signature(),
                receipt.signature()
            ],
        )?;
        tx.execute(
            "UPDATE towers SET available_slots=?1 WHERE tower_id=?2",
            params![available_slots, tower_id.to_vec()],
        )?;
        tx.commit()
    }

    /// Loads a given appointment receipt of a given tower from the database.
    pub fn load_appointment_receipt(
        &self,
        tower_id: TowerId,
        locator: Locator,
    ) -> Option<AppointmentReceipt> {
        let mut stmt = self
            .connection
            .prepare("SELECT start_block, user_signature, tower_signature FROM appointment_receipts WHERE tower_id = ?1 and locator = ?2")
            .unwrap();

        stmt.query_row(params![tower_id.to_vec(), locator.to_vec()], |row| {
            let start_block = row.get::<_, u32>(0).unwrap();
            let user_sig = row.get::<_, String>(1).unwrap();
            let tower_sig = row.get::<_, String>(2).unwrap();

            Ok(AppointmentReceipt::with_signature(
                user_sig,
                start_block,
                tower_sig,
            ))
        })
        .ok()
    }

    /// Loads the appointment receipts associated to a given tower.
    ///
    /// TODO: Currently this is only loading a summary of the receipt, if we need to really load all the information
    /// for any reason this method may need to be renamed.
    pub fn load_appointment_receipts(&self, tower_id: TowerId) -> HashMap<Locator, String> {
        let mut receipts = HashMap::new();
        let mut stmt = self
            .connection
            .prepare("SELECT locator, tower_signature FROM appointment_receipts WHERE tower_id = ?")
            .unwrap();
        let mut rows = stmt.query([tower_id.to_vec()]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let locator = Locator::from_slice(&row.get::<_, Vec<u8>>(0).unwrap()).unwrap();
            let signature = row.get::<_, String>(1).unwrap();

            receipts.insert(locator, signature);
        }

        receipts
    }

    /// Loads a collection of locators from the database entry associated to a given tower.
    ///
    /// The loaded locators can be loaded either from appointment_receipts, pending_appointments or invalid_appointments
    ///  depending on `status`.
    pub fn load_appointment_locators(
        &self,
        tower_id: TowerId,
        status: AppointmentStatus,
    ) -> HashSet<Locator> {
        let status = match status {
            AppointmentStatus::Accepted => "appointment_receipts",
            AppointmentStatus::Pending => "pending_appointments",
            AppointmentStatus::Invalid => "invalid_appointments",
        };
        let mut appointments = HashSet::new();
        // TODO: Can this be prepared instead of formatted (using ?1 seems to fail)?
        let mut stmt = self
            .connection
            .prepare(&format!("SELECT locator FROM {status} WHERE tower_id = ?"))
            .unwrap();

        let mut rows = stmt.query(params![tower_id.to_vec()]).unwrap();
        while let Ok(Some(inner_row)) = rows.next() {
            appointments
                .insert(Locator::from_slice(&inner_row.get::<_, Vec<u8>>(0).unwrap()).unwrap());
        }

        appointments
    }

    /// Loads an appointment from the database.
    pub fn load_appointment(&self, locator: Locator) -> Option<Appointment> {
        let mut stmt = self
            .connection
            .prepare("SELECT encrypted_blob, to_self_delay FROM appointments WHERE locator = ?")
            .unwrap();

        stmt.query_row(params![locator.to_vec()], |row| {
            let encrypted_blob = row.get::<_, Vec<u8>>(0).unwrap();
            let to_self_delay = row.get::<_, u32>(1).unwrap();

            Ok(Appointment::new(locator, encrypted_blob, to_self_delay))
        })
        .ok()
    }

    /// Stores an appointment into the database.
    ///
    /// Appointments are only stored as a whole when they are pending or invalid.
    /// Accepted appointments are simplified in the form of an appointment receipt.
    fn store_appointment(
        tx: &rusqlite::Transaction,
        appointment: &Appointment,
    ) -> Result<usize, SqliteError> {
        tx.execute(
            "INSERT INTO appointments (locator, encrypted_blob, to_self_delay) VALUES (?1, ?2, ?3)",
            params![
                appointment.locator.to_vec(),
                appointment.encrypted_blob,
                appointment.to_self_delay
            ],
        )
    }

    /// Stores a pending appointment into the database.
    ///
    /// A pending appointment is an appointment that was sent to a tower when it was unreachable.
    /// This data is stored so it can be resent once the tower comes back online.
    /// Internally calls [Self::store_appointment].
    pub fn store_pending_appointment(
        &mut self,
        tower_id: TowerId,
        appointment: &Appointment,
    ) -> Result<(), SqliteError> {
        let tx = self.get_mut_connection().transaction().unwrap();

        // If the appointment already exists (because it was added by another tower as either pending or invalid) we simply
        // ignore the error.
        Self::store_appointment(&tx, appointment).ok();
        tx.execute(
            "INSERT INTO pending_appointments (locator, tower_id) VALUES (?1, ?2)",
            params![appointment.locator.to_vec(), tower_id.to_vec(),],
        )?;

        tx.commit()
    }

    /// Removes a pending appointment from the database.
    ///
    /// If the pending appointment is the only instance of the appointment, the appointment will also be deleted form the appointments table.
    pub fn delete_pending_appointment(
        &mut self,
        tower_id: TowerId,
        locator: Locator,
    ) -> Result<(), SqliteError> {
        // We will delete data from pending_appointments or from appointments depending on whether the later has a single reference
        // to it or not. If that's the case, deleting the entry from appointments will trigger a cascade deletion of the entry in pending.
        // If there are other references, this will be deleted when removing the last one.
        let count = {
            let mut stmt = self
                .connection
                .prepare("SELECT COUNT(*) FROM pending_appointments WHERE locator=?")
                .unwrap();
            let pending = stmt
                .query_row(params![locator.to_vec()], |row| row.get::<_, u32>(0))
                .unwrap();

            let mut stmt = self
                .connection
                .prepare("SELECT COUNT(*) FROM invalid_appointments WHERE locator=?")
                .unwrap();
            let invalid = stmt
                .query_row(params![locator.to_vec()], |row| row.get::<_, u32>(0))
                .unwrap_or(0);

            pending + invalid
        };

        let tx = self.get_mut_connection().transaction().unwrap();
        if count == 1 {
            tx.execute(
                "DELETE FROM appointments WHERE locator=?",
                params![locator.to_vec()],
            )?;
        } else {
            tx.execute(
                "DELETE FROM pending_appointments WHERE locator=?1 AND tower_id=?2",
                params![locator.to_vec(), tower_id.to_vec()],
            )?;
        };
        tx.commit()
    }

    /// Stores an invalid appointment into the database.
    ///
    /// An invalid appointment is an appointment that was rejected by the tower.
    /// Storing this data may allow us to see what was the issue and send the data later on.
    /// Internally calls [Self::store_appointment].
    pub fn store_invalid_appointment(
        &mut self,
        tower_id: TowerId,
        appointment: &Appointment,
    ) -> Result<(), SqliteError> {
        let tx = self.get_mut_connection().transaction().unwrap();

        // If the appointment already exists (because it was added by another tower as either pending or invalid) we simply
        // ignore the error.
        Self::store_appointment(&tx, appointment).ok();
        tx.execute(
            "INSERT INTO invalid_appointments (locator, tower_id) VALUES (?1, ?2)",
            params![appointment.locator.to_vec(), tower_id.to_vec(),],
        )?;

        tx.commit()
    }

    /// Loads non finalized appointments from the database for a given tower based on a status flag.
    ///
    /// This is meant to be used only for pending and invalid appointments, if the method is called for
    /// accepted appointment, an empty collection will be returned.
    pub fn load_appointments(
        &self,
        tower_id: TowerId,
        status: AppointmentStatus,
    ) -> Vec<Appointment> {
        let table = match status {
            AppointmentStatus::Accepted => return Vec::new(),
            AppointmentStatus::Pending => "pending_appointments",
            AppointmentStatus::Invalid => "invalid_appointments",
        };

        let mut appointments = Vec::new();
        let mut stmt = self
            .connection
            .prepare(&format!("SELECT a.locator, a.encrypted_blob, a.to_self_delay FROM appointments as a, {table} as t WHERE a.locator = t.locator AND t.tower_id = ?"))
            .unwrap();
        let mut rows = stmt.query([tower_id.to_vec()]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let locator = Locator::from_slice(&row.get::<_, Vec<u8>>(0).unwrap()).unwrap();
            let encrypted_blob = row.get::<_, Vec<u8>>(1).unwrap();
            let to_self_delay = row.get::<_, u32>(2).unwrap();

            appointments.push(Appointment::new(locator, encrypted_blob, to_self_delay));
        }

        appointments
    }

    /// Stores a misbehaving proof into the database.
    ///
    /// A misbehaving proof is proof that the tower has signed an appointment using a key different
    /// than the one advertised to the user when they registered.
    pub fn store_misbehaving_proof(
        &mut self,
        tower_id: TowerId,
        proof: &MisbehaviorProof,
    ) -> Result<(), SqliteError> {
        let tx = self.get_mut_connection().transaction().unwrap();
        tx.execute(
            "INSERT INTO appointment_receipts (tower_id, locator, start_block, user_signature, tower_signature) 
                VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                tower_id.to_vec(),
                proof.locator.to_vec(),
                proof.appointment_receipt.start_block(),
                proof.appointment_receipt.user_signature(),
                proof.appointment_receipt.signature()
            ],
        )?;
        tx.execute(
            "INSERT INTO misbehaving_proofs (tower_id, locator, recovered_id) VALUES (?1, ?2, ?3)",
            params![
                tower_id.to_vec(),
                proof.locator.to_vec(),
                proof.recovered_id.to_vec()
            ],
        )?;

        tx.commit()
    }

    /// Loads the misbehaving proof for a given tower from the database (if found).
    fn load_misbehaving_proof(&self, tower_id: TowerId) -> Option<MisbehaviorProof> {
        let mut misbehaving_stmt = self
            .connection
            .prepare("SELECT locator, recovered_id FROM misbehaving_proofs WHERE tower_id = ?")
            .unwrap();

        misbehaving_stmt
            .query_row([tower_id.to_vec()], |row| {
                let locator = Locator::from_slice(&row.get::<_, Vec<u8>>(0).unwrap()).unwrap();
                let recovered_id = TowerId::from_slice(&row.get::<_, Vec<u8>>(1).unwrap()).unwrap();
                Ok((locator, recovered_id))
            })
            .map(|(locator, recovered_id)| {
                let mut receipt_stmt = self
                    .connection
                    .prepare(
                        "SELECT start_block, user_signature, tower_signature 
                        FROM appointment_receipts 
                        WHERE locator = ?1 AND tower_id = ?2",
                    )
                    .unwrap();
                let receipt = receipt_stmt
                    .query_row([locator.to_vec(), tower_id.to_vec()], |row| {
                        let start_block = row.get::<_, u32>(0).unwrap();
                        let user_signature = row.get::<_, String>(1).unwrap();
                        let tower_signature = row.get::<_, String>(2).unwrap();
                        Ok(AppointmentReceipt::with_signature(
                            user_signature,
                            start_block,
                            tower_signature,
                        ))
                    })
                    .unwrap();
                MisbehaviorProof::new(locator, receipt, recovered_id)
            })
            .ok()
    }

    /// Checks whether a misbehaving proof exists for a given tower.
    fn exists_misbehaving_proof(&self, tower_id: TowerId) -> bool {
        let mut misbehaving_stmt = self
            .connection
            .prepare("SELECT tower_id FROM misbehaving_proofs WHERE tower_id = ?")
            .unwrap();
        misbehaving_stmt.exists([tower_id.to_vec()]).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use teos_common::cryptography::get_random_keypair;
    use teos_common::test_utils::{
        generate_random_appointment, get_random_registration_receipt, get_random_user_id,
        get_registration_receipt_from_previous,
    };

    impl DBM {
        pub(crate) fn in_memory() -> Result<Self, SqliteError> {
            let connection = Connection::open_in_memory()?;
            connection.execute("PRAGMA foreign_keys=1;", [])?;
            let mut dbm = Self { connection };
            dbm.create_tables(Vec::from_iter(TABLES))?;

            Ok(dbm)
        }

        pub(crate) fn appointment_exists(&self, locator: Locator) -> bool {
            let mut stmt = self
                .connection
                .prepare("SELECT * FROM appointments WHERE locator=? ")
                .unwrap();
            stmt.exists(params![locator.to_vec()]).unwrap()
        }

        pub(crate) fn appointment_receipt_exists(
            &self,
            locator: Locator,
            tower_id: TowerId,
        ) -> bool {
            let mut stmt = self
                .connection
                .prepare("SELECT * FROM appointment_receipts WHERE locator=?1 AND tower_id=?2 ")
                .unwrap();
            stmt.exists(params![locator.to_vec(), tower_id.to_vec()])
                .unwrap()
        }
    }

    #[test]
    fn test_create_tables() {
        let connection = Connection::open_in_memory().unwrap();
        let mut dbm = DBM { connection };
        dbm.create_tables(Vec::from_iter(TABLES)).unwrap();
    }

    #[test]
    fn test_store_load_tower_record() {
        let mut dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let tower_info = TowerInfo::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
            HashMap::new(),
            Vec::new(),
            Vec::new(),
        );

        // Check the loaded data matches the in memory data
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();
        assert_eq!(dbm.load_tower_record(tower_id).unwrap(), tower_info);
    }

    #[test]
    fn test_load_registration_receipt() {
        let mut dbm = DBM::in_memory().unwrap();

        // Registration receipts are stored alongside tower records when the register command is called
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";
        let receipt = get_random_registration_receipt();
        let subscription_start = Some(receipt.subscription_start());
        let subscription_expiry = Some(receipt.subscription_expiry());

        // Check the receipt was stored
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();
        assert_eq!(
            dbm.load_registration_receipt(
                tower_id,
                receipt.user_id(),
                subscription_start,
                subscription_expiry
            )
            .unwrap()[0],
            receipt
        );

        // Add another receipt for the same tower with a higher expiry and check that output gives vector of both receipts
        let middle_receipt = get_registration_receipt_from_previous(&receipt);
        let latest_receipt = get_registration_receipt_from_previous(&middle_receipt);

        let latest_subscription_expiry = Some(latest_receipt.subscription_expiry());

        dbm.store_tower_record(tower_id, net_addr, &latest_receipt)
            .unwrap();
        assert_eq!(
            dbm.load_registration_receipt(
                tower_id,
                latest_receipt.user_id(),
                subscription_start,
                latest_subscription_expiry
            )
            .unwrap(),
            vec![receipt, latest_receipt.clone()]
        );

        // Add a final one with a lower expiry and check if the lastest receipt is loaded when boundry
        // params are not passed
        dbm.store_tower_record(tower_id, net_addr, &middle_receipt)
            .unwrap();
        assert_eq!(
            dbm.load_registration_receipt(tower_id, latest_receipt.user_id(), None, None)
                .unwrap()[0],
            latest_receipt
        );
    }

    #[test]
    fn test_load_same_registration_receipt() {
        let mut dbm = DBM::in_memory().unwrap();

        // Registration receipts are stored alongside tower records when the register command is called
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";
        let receipt = get_random_registration_receipt();
        let subscription_start = Some(receipt.subscription_start());
        let subscription_expiry = Some(receipt.subscription_expiry());

        // Store it once
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();
        assert_eq!(
            dbm.load_registration_receipt(
                tower_id,
                receipt.user_id(),
                subscription_start,
                subscription_expiry
            )
            .unwrap()[0],
            receipt
        );

        // Store the same again, this should fail due to UNIQUE PK constrains.
        // Notice store_tower_record is guarded against this by WTClient::add_update_tower though.
        assert!(matches!(
            dbm.store_tower_record(tower_id, net_addr, &receipt),
            Err { .. }
        ));
    }

    #[test]
    fn test_load_nonexistent_tower_record() {
        let dbm = DBM::in_memory().unwrap();

        // If the tower does not exists, `load_tower` will fail.
        let tower_id = get_random_user_id();
        assert!(dbm.load_tower_record(tower_id).is_none());
    }

    #[test]
    fn test_store_load_towers() {
        let mut dbm = DBM::in_memory().unwrap();
        let mut towers = HashMap::new();

        // In order to add a tower record we need to associated registration receipt.
        for _ in 0..10 {
            let tower_id = get_random_user_id();
            let net_addr = "talaia.watch";
            let mut receipt = get_random_registration_receipt();
            dbm.store_tower_record(tower_id, net_addr, &receipt)
                .unwrap();

            // Add not only one registration receipt to test if the tower retrieves the one with furthest expiry date.
            for _ in 0..10 {
                receipt = get_registration_receipt_from_previous(&receipt);
                dbm.store_tower_record(tower_id, net_addr, &receipt)
                    .unwrap();
            }

            towers.insert(
                tower_id,
                TowerSummary::new(
                    net_addr.to_owned(),
                    receipt.available_slots(),
                    receipt.subscription_start(),
                    receipt.subscription_expiry(),
                ),
            );
        }

        assert_eq!(dbm.load_towers(), towers);
    }

    #[test]
    fn test_load_towers_empty() {
        // If there are no towers in the database, `load_towers` should return an empty map.
        let dbm = DBM::in_memory().unwrap();
        assert_eq!(dbm.load_towers(), HashMap::new());
    }

    #[test]
    fn test_remove_tower_record() {
        let mut dbm = DBM::in_memory().unwrap();

        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";
        let receipt = get_random_registration_receipt();
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        assert!(matches!(dbm.remove_tower_record(tower_id), Ok(())));
    }

    #[test]
    fn test_remove_tower_record_inexistent() {
        let dbm = DBM::in_memory().unwrap();

        assert!(matches!(
            dbm.remove_tower_record(get_random_user_id()),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn test_store_load_appointment_receipts() {
        let mut dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let mut tower_summary = TowerSummary::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        // Add some appointment receipts and check they match
        let mut receipts = HashMap::new();
        for _ in 0..5 {
            let appointment = generate_random_appointment(None);
            let user_signature = "user_signature";
            let appointment_receipt = AppointmentReceipt::with_signature(
                user_signature.to_owned(),
                42,
                "tower_signature".to_owned(),
            );

            tower_summary.available_slots -= 1;

            dbm.store_appointment_receipt(
                tower_id,
                appointment.locator,
                tower_summary.available_slots,
                &appointment_receipt,
            )
            .unwrap();
            receipts.insert(
                appointment.locator,
                appointment_receipt.signature().unwrap(),
            );
        }

        assert_eq!(dbm.load_appointment_receipts(tower_id), receipts);
    }

    #[test]
    fn test_load_appointment_receipt() {
        let mut dbm = DBM::in_memory().unwrap();
        let tower_id = get_random_user_id();
        let appointment = generate_random_appointment(None);

        // If there is no appointment receipt for the given (locator, tower_id) pair, Error::NotFound is returned
        // Try first with both being unknown
        assert!(dbm
            .load_appointment_receipt(tower_id, appointment.locator)
            .is_none());

        // Add the tower but not the appointment and try again
        let net_addr = "talaia.watch";
        let receipt = get_random_registration_receipt();
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        assert!(dbm
            .load_appointment_receipt(tower_id, appointment.locator)
            .is_none());

        // Add both
        let tower_summary = TowerSummary::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );
        let appointment_receipt = AppointmentReceipt::with_signature(
            "user_signature".to_owned(),
            42,
            "tower_signature".to_owned(),
        );
        dbm.store_appointment_receipt(
            tower_id,
            appointment.locator,
            tower_summary.available_slots,
            &appointment_receipt,
        )
        .unwrap();

        assert_eq!(
            dbm.load_appointment_receipt(tower_id, appointment.locator)
                .unwrap(),
            appointment_receipt
        );
    }

    #[test]
    fn test_load_appointment_locators() {
        // `load_appointment_locators` is used to load locators from either `appointment_receipts`, `pending_appointments` or `invalid_appointments`
        let mut dbm = DBM::in_memory().unwrap();

        // We first need to add a tower record to the database so we can add some associated data.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let tower_summary = TowerSummary::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        // Create all types of appointments and store them in the db.
        let user_signature = "user_signature";
        let mut receipts = HashSet::new();
        let mut pending_appointments = HashSet::new();
        let mut invalid_appointments = HashSet::new();
        for _ in 0..5 {
            let appointment = generate_random_appointment(None);
            let appointment_receipt = AppointmentReceipt::with_signature(
                user_signature.to_owned(),
                42,
                "tower_signature".to_owned(),
            );
            let pending_appointment = generate_random_appointment(None);
            let invalid_appointment = generate_random_appointment(None);

            dbm.store_appointment_receipt(
                tower_id,
                appointment.locator,
                tower_summary.available_slots,
                &appointment_receipt,
            )
            .unwrap();
            dbm.store_pending_appointment(tower_id, &pending_appointment)
                .unwrap();
            dbm.store_invalid_appointment(tower_id, &invalid_appointment)
                .unwrap();

            receipts.insert(appointment.locator);
            pending_appointments.insert(pending_appointment.locator);
            invalid_appointments.insert(invalid_appointment.locator);
        }

        // Pull data from the db and check it matches the expected data
        assert_eq!(
            dbm.load_appointment_locators(tower_id, AppointmentStatus::Accepted),
            receipts
        );
        assert_eq!(
            dbm.load_appointment_locators(tower_id, AppointmentStatus::Pending),
            pending_appointments
        );
        assert_eq!(
            dbm.load_appointment_locators(tower_id, AppointmentStatus::Invalid),
            invalid_appointments
        );
    }

    #[test]
    fn test_store_load_appointment() {
        let mut dbm = DBM::in_memory().unwrap();

        let appointment = generate_random_appointment(None);
        let tx = dbm.get_mut_connection().transaction().unwrap();
        DBM::store_appointment(&tx, &appointment).unwrap();
        tx.commit().unwrap();

        let loaded_appointment = dbm.load_appointment(appointment.locator);
        assert_eq!(appointment, loaded_appointment.unwrap());
    }

    #[test]
    fn test_store_load_appointment_inexistent() {
        let dbm = DBM::in_memory().unwrap();

        let locator = generate_random_appointment(None).locator;
        let loaded_appointment = dbm.load_appointment(locator);
        assert!(loaded_appointment.is_none());
    }

    #[test]
    fn test_store_pending_appointment() {
        let mut dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let mut tower_summary = TowerSummary::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        )
        .with_status(TowerStatus::TemporaryUnreachable);
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        // Add some pending appointments and check they match
        for _ in 0..5 {
            let appointment = generate_random_appointment(None);

            tower_summary
                .pending_appointments
                .insert(appointment.locator);

            dbm.store_pending_appointment(tower_id, &appointment)
                .unwrap();
            assert_eq!(
                TowerSummary::from(dbm.load_tower_record(tower_id).unwrap()),
                tower_summary
            );
        }
    }

    #[test]
    fn test_store_pending_appointment_twice() {
        let mut dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id_1 = get_random_user_id();
        let tower_id_2 = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        dbm.store_tower_record(tower_id_1, net_addr, &receipt)
            .unwrap();
        dbm.store_tower_record(tower_id_2, net_addr, &receipt)
            .unwrap();

        // If the same appointment is stored twice (by different towers) it should go through
        // Since the appointment data will be stored only once and this will create two references
        let appointment = generate_random_appointment(None);
        dbm.store_pending_appointment(tower_id_1, &appointment)
            .unwrap();
        dbm.store_pending_appointment(tower_id_2, &appointment)
            .unwrap();

        // If this is called twice with for the same tower it will fail, since two identical references
        // can not exist. This is intended behavior and should not happen
        assert!(dbm
            .store_pending_appointment(tower_id_2, &appointment)
            .is_err());
    }

    #[test]
    fn test_delete_pending_appointment() {
        let mut dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        // Add a single one, remove it later
        let appointment = generate_random_appointment(None);
        dbm.store_pending_appointment(tower_id, &appointment)
            .unwrap();
        assert!(dbm
            .delete_pending_appointment(tower_id, appointment.locator)
            .is_ok());

        // The appointment should be completely gone
        assert!(!dbm
            .load_appointment_locators(tower_id, AppointmentStatus::Pending)
            .contains(&appointment.locator));
        assert!(!dbm.appointment_exists(appointment.locator));

        // Try again with more than one reference
        let another_tower_id = get_random_user_id();
        dbm.store_tower_record(another_tower_id, net_addr, &receipt)
            .unwrap();

        // Add two
        dbm.store_pending_appointment(tower_id, &appointment)
            .unwrap();
        dbm.store_pending_appointment(another_tower_id, &appointment)
            .unwrap();
        // Delete one
        assert!(dbm
            .delete_pending_appointment(tower_id, appointment.locator)
            .is_ok());
        // Check
        assert!(!dbm
            .load_appointment_locators(tower_id, AppointmentStatus::Pending)
            .contains(&appointment.locator));
        assert!(dbm
            .load_appointment_locators(another_tower_id, AppointmentStatus::Pending)
            .contains(&appointment.locator));
        assert!(dbm.appointment_exists(appointment.locator));

        // Add an invalid reference and check again
        dbm.store_invalid_appointment(tower_id, &appointment)
            .unwrap();
        assert!(dbm
            .delete_pending_appointment(another_tower_id, appointment.locator)
            .is_ok());
        assert!(!dbm
            .load_appointment_locators(another_tower_id, AppointmentStatus::Pending)
            .contains(&appointment.locator));
        assert!(dbm
            .load_appointment_locators(tower_id, AppointmentStatus::Invalid)
            .contains(&appointment.locator));
        assert!(dbm.appointment_exists(appointment.locator));
    }

    #[test]
    fn test_store_invalid_appointment() {
        let mut dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let mut tower_summary = TowerSummary::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        // Add some invalid appointments and check they match
        for _ in 0..5 {
            let appointment = generate_random_appointment(None);

            tower_summary
                .invalid_appointments
                .insert(appointment.locator);

            dbm.store_invalid_appointment(tower_id, &appointment)
                .unwrap();
            assert_eq!(
                TowerSummary::from(dbm.load_tower_record(tower_id).unwrap()),
                tower_summary
            );
        }
    }

    #[test]
    fn test_store_invalid_appointment_twice() {
        let mut dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id_1 = get_random_user_id();
        let tower_id_2 = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        dbm.store_tower_record(tower_id_1, net_addr, &receipt)
            .unwrap();
        dbm.store_tower_record(tower_id_2, net_addr, &receipt)
            .unwrap();

        // Same as with pending appointments. Two references from different towers is allowed
        let appointment = generate_random_appointment(None);
        dbm.store_invalid_appointment(tower_id_1, &appointment)
            .unwrap();
        dbm.store_invalid_appointment(tower_id_2, &appointment)
            .unwrap();

        // Two references from the same tower is not.
        assert!(dbm
            .store_invalid_appointment(tower_id_2, &appointment)
            .is_err());
    }

    #[test]
    fn test_store_load_misbehaving_proof() {
        let mut dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let tower_summary = TowerSummary::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();
        assert_eq!(
            TowerSummary::from(dbm.load_tower_record(tower_id).unwrap()),
            tower_summary
        );

        // Store a misbehaving proof and load it back
        let appointment = generate_random_appointment(None);
        let appointment_receipt = AppointmentReceipt::with_signature(
            "user_signature".to_owned(),
            42,
            "tower_signature".to_owned(),
        );

        let proof = MisbehaviorProof::new(
            appointment.locator,
            appointment_receipt,
            get_random_user_id(),
        );

        dbm.store_misbehaving_proof(tower_id, &proof).unwrap();
        assert_eq!(dbm.load_misbehaving_proof(tower_id).unwrap(), proof);
    }

    #[test]
    fn test_store_load_non_existing_misbehaving_proof() {
        let dbm = DBM::in_memory().unwrap();
        assert!(dbm.load_misbehaving_proof(get_random_user_id()).is_none());
    }

    #[test]
    fn test_store_exists_misbehaving_proof() {
        let mut dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let tower_summary = TowerSummary::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();
        assert_eq!(
            TowerSummary::from(dbm.load_tower_record(tower_id).unwrap()),
            tower_summary
        );

        // // Store a misbehaving proof check
        let appointment = generate_random_appointment(None);
        let appointment_receipt = AppointmentReceipt::with_signature(
            "user_signature".to_owned(),
            42,
            "tower_signature".to_owned(),
        );

        let proof = MisbehaviorProof::new(
            appointment.locator,
            appointment_receipt,
            get_random_user_id(),
        );

        dbm.store_misbehaving_proof(tower_id, &proof).unwrap();
        assert!(dbm.exists_misbehaving_proof(tower_id));
    }

    #[test]
    fn test_exists_misbehaving_proof_false() {
        let dbm = DBM::in_memory().unwrap();
        assert!(!dbm.exists_misbehaving_proof(get_random_user_id()));
    }

    #[test]
    fn test_store_load_client_key() {
        let dbm = DBM::in_memory().unwrap();

        assert!(dbm.load_client_key().is_none());
        for _ in 0..7 {
            let sk = get_random_keypair().0;
            dbm.store_client_key(&sk).unwrap();
            assert_eq!(dbm.load_client_key().unwrap(), sk);
        }
    }
}
