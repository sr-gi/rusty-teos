use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{error::TryRecvError, UnboundedReceiver};

use backoff::future::retry_notify;
use backoff::{Error, ExponentialBackoff};

use teos_common::appointment::Locator;
use teos_common::cryptography;
use teos_common::errors;
use teos_common::UserId as TowerId;

use crate::net::http::{self, AddAppointmentError};
use crate::wt_client::{RevocationData, WTClient};
use crate::{MisbehaviorProof, TowerStatus};

const POLLING_TIME: u64 = 1;

#[derive(Eq, PartialEq, Debug)]
enum RetryError {
    // bool marks whether the Subscription error is permanent or not
    Subscription(String, bool),
    Unreachable,
    Misbehaving(MisbehaviorProof),
    Abandoned,
}

impl Display for RetryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RetryError::Subscription(r, _) => write!(f, "{r}"),
            RetryError::Unreachable => write!(f, "Tower cannot be reached"),
            RetryError::Misbehaving(_) => write!(f, "Tower misbehaved"),
            RetryError::Abandoned => write!(f, "Tower was abandoned. Skipping retry"),
        }
    }
}

impl RetryError {
    fn is_permanent(&self) -> bool {
        matches!(
            self,
            RetryError::Subscription(_, true) | RetryError::Misbehaving(_) | RetryError::Abandoned
        )
    }
}

pub struct RetryManager {
    wt_client: Arc<Mutex<WTClient>>,
    unreachable_towers: UnboundedReceiver<(TowerId, RevocationData)>,
    max_elapsed_time_secs: u16,
    auto_retry_delay: u32,
    max_interval_time_secs: u16,
    retriers: HashMap<TowerId, Arc<Retrier>>,
}

impl RetryManager {
    pub fn new(
        wt_client: Arc<Mutex<WTClient>>,
        unreachable_towers: UnboundedReceiver<(TowerId, RevocationData)>,
        max_elapsed_time_secs: u16,
        auto_retry_delay: u32,
        max_interval_time_secs: u16,
    ) -> Self {
        RetryManager {
            wt_client,
            unreachable_towers,
            max_elapsed_time_secs,
            auto_retry_delay,
            max_interval_time_secs,
            retriers: HashMap::new(),
        }
    }

    /// Starts the retry manager's main logic loop.
    /// This method will keep running until the `unreachable_towers` sender disconnects.
    ///
    /// It will receive a `(tower_id, revocation_data)` pair and try to send all the appointments contained
    /// in `revocation_data` (identified by `locator`) to the tower with `tower_id`. This is done by spawning
    /// a tokio thread for each `tower_id` that tries to send all the pending appointments.
    ///
    /// The content of [RevocationData] will depend on who called `unreachable_towers.send`:
    ///     - If it was called by `on_commitment_revocation`, the data will be fresh and contain a single locator
    ///     - If it was called by the [WTClient] constructor, or by manually retrying, then the data will the stale
    ///       and contain a `HashSet<locator>` with, potentially, many locators.
    pub async fn manage_retry(&mut self) {
        log::info!("Starting retry manager");

        loop {
            match self.unreachable_towers.try_recv() {
                Ok((tower_id, data)) => {
                    // Not start a retry if the tower is flagged to be abandoned
                    if !self
                        .wt_client
                        .lock()
                        .unwrap()
                        .towers
                        .contains_key(&tower_id)
                    {
                        log::info!("Skipping retrying abandoned tower {tower_id}");
                    } else if let Some(retrier) = self.retriers.get(&tower_id) {
                        if retrier.is_idle() {
                            if !data.is_none() {
                                log::error!("Data was send to an idle retrier. This should have never happened. Please report! ({data:?})");
                                continue;
                            }
                            log::info!(
                                "Manually finished idling. Flagging {} for retry",
                                retrier.tower_id
                            );
                            // While a retrier is idle data is not kept in memory.
                            // Load the pending appointments from the DB and feed them to the retrier
                            retrier.set_status(RetrierStatus::Stopped);
                            retrier.pending_appointments.lock().unwrap().extend(
                                self.wt_client
                                    .lock()
                                    .unwrap()
                                    .dbm
                                    .load_appointment_locators(
                                        retrier.tower_id,
                                        crate::AppointmentStatus::Pending,
                                    ),
                            );
                        } else {
                            self.add_pending_appointments(tower_id, data.into());
                        }
                    } else {
                        self.add_pending_appointments(tower_id, data.into());
                    }
                }
                Err(TryRecvError::Empty) => {
                    // Keep only running retriers and retriers ready to be started/re-started.
                    // This will remove failed ones and ones finished successfully and have no pending appointments.
                    //
                    // Note that a failed retrier could have received some new appointments to retry. In this case, we don't try to send
                    // them because we know that that tower is unreachable. We most likely received these new appointments while the tower
                    // was still flagged as temporarily unreachable when cleaning up after giving up retrying.
                    self.retriers.retain(|_, retrier| {
                        retrier.remove_if_failed();
                        retrier.should_start() || retrier.is_running() || retrier.is_idle()
                    });
                    // Start all the ready retriers.
                    for retrier in self.retriers.values() {
                        if retrier.should_start() {
                            self.start_retrying(retrier.clone());
                        // Effectively this is the same as `if retrier.is_idle` plus returning for how long is true.
                        } else if let Some(t) = retrier.get_elapsed_time() {
                            if t > self.auto_retry_delay as u64 {
                                log::info!(
                                    "Finished idling. Flagging {} for retry",
                                    retrier.tower_id
                                );
                                // While a retrier is idle data is not kept in memory.
                                // Load the pending appointments from the DB and feed them to the retrier
                                retrier.set_status(RetrierStatus::Stopped);
                                retrier.pending_appointments.lock().unwrap().extend(
                                    self.wt_client
                                        .lock()
                                        .unwrap()
                                        .dbm
                                        .load_appointment_locators(
                                            retrier.tower_id,
                                            crate::AppointmentStatus::Pending,
                                        ),
                                );
                            }
                        }
                    }
                    // Sleep to not waste a lot of CPU cycles.
                    tokio::time::sleep(Duration::from_secs(POLLING_TIME)).await;
                }
                Err(TryRecvError::Disconnected) => break,
            }
        }
    }

    /// Adds an appointment to pending for a given tower.
    ///
    /// If the tower is not currently being retried, a new entry for it is created, otherwise, the data is appended to the existing entry.
    fn add_pending_appointments(&mut self, tower_id: TowerId, locators: HashSet<Locator>) {
        if let std::collections::hash_map::Entry::Vacant(e) = self.retriers.entry(tower_id) {
            log::debug!("Creating a new entry for tower {tower_id}");
            e.insert(Arc::new(Retrier::new(
                self.wt_client.clone(),
                tower_id,
                locators,
            )));
        } else {
            let mut pending_appointments = self
                .retriers
                .get(&tower_id)
                .unwrap()
                .pending_appointments
                .lock()
                .unwrap();
            for locator in locators {
                log::debug!("Adding pending appointment {locator} to existing tower {tower_id}",);
                pending_appointments.insert(locator);
            }
        }
    }

    fn start_retrying(&self, retrier: Arc<Retrier>) {
        log::info!("Retrying tower {}", retrier.tower_id);
        retrier.start(self.max_elapsed_time_secs, self.max_interval_time_secs);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RetrierStatus {
    /// Retrier is stopped. This could happen if the retrier was never started or it started and
    /// finished successfully. If a retrier is stopped and has some pending appointments, it should be
    /// started/re-started, otherwise, it can be deleted safely.
    Stopped,
    /// Retrier is currently retrying the tower. If the retrier receives new appointments, it will
    /// **try** to send them along (but it might not send them).
    ///
    /// If a retrier status is `Running`, then its associated tower is either temporary unreachable or subscription error.
    Running,
    /// Retrier failed retrying the tower. Should not be re-started.
    ///
    /// If a retrier status is `Failed`, then its associated tower is neither reachable nor temporary unreachable.
    Failed,
    /// Retrier is currently idle waiting for a signal to start working again. An Idle retrier can be forced to start
    /// working again by the user by manually calling `retrytower`.
    ///
    /// If a retrier status is `Idle`, then its associated tower is unreachable.
    Idle(Instant),
}

impl RetrierStatus {
    /// Check whether the status is [Running](RetrierStatus::Stopped).
    pub fn is_stopped(&self) -> bool {
        *self == RetrierStatus::Stopped
    }

    /// Check whether the status is [Running](RetrierStatus::Running).
    pub fn is_running(&self) -> bool {
        *self == RetrierStatus::Running
    }

    /// Check whether the status is [Idle](RetrierStatus::Idle).
    pub fn is_idle(&self) -> bool {
        matches!(self, RetrierStatus::Idle { .. })
    }

    /// Check whether the status is [Failed](RetrierStatus::Failed).
    pub fn failed(&self) -> bool {
        *self == RetrierStatus::Failed
    }

    /// Gets the elapsed time of an [Idle](RetrierStatus::Idle) status, [None] otherwise.
    pub fn get_elapsed_time(&self) -> Option<u64> {
        if let RetrierStatus::Idle(x) = *self {
            Some(x.elapsed().as_secs())
        } else {
            None
        }
    }
}

pub struct Retrier {
    wt_client: Arc<Mutex<WTClient>>,
    tower_id: TowerId,
    pending_appointments: Mutex<HashSet<Locator>>,
    status: Mutex<RetrierStatus>,
}

impl Retrier {
    pub fn new(
        wt_client: Arc<Mutex<WTClient>>,
        tower_id: TowerId,
        locators: HashSet<Locator>,
    ) -> Self {
        Self {
            wt_client,
            tower_id,
            pending_appointments: Mutex::new(locators),
            status: Mutex::new(RetrierStatus::Stopped),
        }
    }

    fn has_pending_appointments(&self) -> bool {
        !self.pending_appointments.lock().unwrap().is_empty()
    }

    fn set_status(&self, status: RetrierStatus) {
        *self.status.lock().unwrap() = status.clone();

        // Add or remove retriers from WTClient based on the RetrierStatus
        if self.is_running() || self.is_idle() {
            log::debug!("Adding {} to active retriers", self.tower_id);
            self.wt_client
                .lock()
                .unwrap()
                .retriers
                .insert(self.tower_id, status);
        } else if self.is_stopped() {
            // We are not removing failed retriers here to prevent a manual retry until the retrier is removed from
            // the manager
            log::debug!("Removing retrier {} from active retriers", self.tower_id);
            self.wt_client
                .lock()
                .unwrap()
                .retriers
                .remove(&self.tower_id);
        }
    }

    /// Maps [RetrierStatus::is_stopped]
    pub fn is_stopped(&self) -> bool {
        self.status.lock().unwrap().is_stopped()
    }

    /// Maps [RetrierStatus::is_running]
    pub fn is_running(&self) -> bool {
        self.status.lock().unwrap().is_running()
    }

    /// Maps [RetrierStatus::is_idle]
    pub fn is_idle(&self) -> bool {
        self.status.lock().unwrap().is_idle()
    }

    /// Maps [RetrierStatus::failed]
    pub fn failed(&self) -> bool {
        self.status.lock().unwrap().failed()
    }

    /// Maps [RetrierStatus::get_elapsed_time]
    pub fn get_elapsed_time(&self) -> Option<u64> {
        self.status.lock().unwrap().get_elapsed_time()
    }

    pub fn should_start(&self) -> bool {
        // A retrier can be started/re-started if it is stopped (i.e. not running and not failed)
        // and has some pending appointments.
        self.is_stopped() && self.has_pending_appointments()
    }

    pub fn start(self: Arc<Self>, max_elapsed_time_secs: u16, max_interval_time_secs: u16) {
        // We shouldn't be retrying failed and running retriers.
        debug_assert_eq!(*self.status.lock().unwrap(), RetrierStatus::Stopped);

        // When manually retrying the tower may be in either SubscriptionError or Unreachable state.
        // Flag this as TemporaryUnreachable only if there is no SubscriptionError.
        // Rationale: if there is a subscription error that needs to be handled first, otherwise we'll
        //            waste a retry cycle with a request that will always fail.
        {
            let mut state = self.wt_client.lock().unwrap();
            if !state
                .get_tower_status(&self.tower_id)
                .unwrap()
                .is_subscription_error()
            {
                state.set_tower_status(self.tower_id, TowerStatus::TemporaryUnreachable);
            }
        }
        self.set_status(RetrierStatus::Running);

        tokio::spawn(async move {
            let r = retry_notify(
                ExponentialBackoff {
                    max_elapsed_time: Some(Duration::from_secs(max_elapsed_time_secs as u64)),
                    max_interval: Duration::from_secs(max_interval_time_secs as u64),
                    ..ExponentialBackoff::default()
                },
                || async { self.run().await },
                |err, _| {
                    log::warn!("Retry error happened with {}. {err}", self.tower_id);
                },
            )
            .await;

            match r {
                Ok(_) => {
                    log::info!("Retry strategy succeeded for {}", self.tower_id);
                    // Set the tower status now so new appointment doesn't go to the retry manager.
                    self.wt_client
                        .lock()
                        .unwrap()
                        .set_tower_status(self.tower_id, TowerStatus::Reachable);
                    // Retrier succeeded and can be re-used by re-starting it.
                    self.set_status(RetrierStatus::Stopped);
                }
                Err(e) => {
                    // Notice we'll end up here after a permanent error. That is, either after finishing the backoff strategy
                    // unsuccessfully or by manually raising such an error (like when facing a tower misbehavior).
                    log::warn!("Retry strategy gave up for {}. {e}", self.tower_id);
                    if e.is_permanent() {
                        self.set_status(RetrierStatus::Failed);
                    }

                    match e {
                        RetryError::Subscription(_, true) => {
                            log::info!("Setting {} status as subscription error", self.tower_id);
                            self.wt_client
                                .lock()
                                .unwrap()
                                .set_tower_status(self.tower_id, TowerStatus::SubscriptionError)
                        }
                        RetryError::Misbehaving(p) => {
                            log::warn!("Cannot recover known tower_id from the appointment receipt. Flagging tower as misbehaving");
                            self.wt_client
                                .lock()
                                .unwrap()
                                .flag_misbehaving_tower(self.tower_id, p);
                        }
                        RetryError::Abandoned => {
                            log::info!("Skipping retrying abandoned tower {}", self.tower_id)
                        }
                        // This covers `RetryError::Unreachable` and `RetryError::Subscription(_, false)`
                        _ => {
                            log::debug!("Starting to idle");
                            self.set_status(RetrierStatus::Idle(Instant::now()));
                            // Clear all pending appointments so they do not waste any memory while idling
                            self.pending_appointments.lock().unwrap().clear();
                            self.wt_client
                                .lock()
                                .unwrap()
                                .set_tower_status(self.tower_id, TowerStatus::Unreachable);
                        }
                    }
                }
            }
        });
    }

    async fn run(&self) -> Result<(), Error<RetryError>> {
        // Create a new scope so we can get all the data only locking the WTClient once.
        let (tower_id, status, net_addr, user_id, user_sk, proxy) = {
            let wt_client = self.wt_client.lock().unwrap();
            if !wt_client.towers.contains_key(&self.tower_id) {
                return Err(Error::permanent(RetryError::Abandoned));
            }

            let tower = wt_client.towers.get(&self.tower_id).unwrap();
            (
                self.tower_id,
                tower.status,
                tower.net_addr.clone(),
                wt_client.user_id,
                wt_client.user_sk,
                wt_client.proxy.clone(),
            )
        };

        // If the tower state is subscription_error we need to re-register first. If we cannot, then the retry is aborted.
        if status.is_subscription_error() {
            let receipt = http::register(tower_id, user_id, &net_addr, &proxy)
                .await
                .map_err(|e| {
                    log::debug!("Cannot renew registration with tower. Error: {e:?}");
                    Error::transient(RetryError::Subscription(
                        "Cannot renew registration with tower".to_owned(),
                        false,
                    ))
                })?;
            if !receipt.verify(&tower_id) {
                return Err(Error::permanent(RetryError::Subscription("Registration receipt contains bad signature. Are you using the right tower_id?".to_owned(), true)));
            }
            self.wt_client
                .lock()
                .unwrap()
                .add_update_tower(tower_id, net_addr.net_addr(), &receipt)
                .map_err(|e| {
                    let reason = if e.is_expiry() {
                        "Registration receipt contains a subscription expiry that is not higher than the one we are currently registered for"
                    } else {
                        "Registration receipt does not contain more slots than the ones we are currently registered for"
                    };
                    Error::permanent(RetryError::Subscription(reason.to_owned(), true))
                })?;
        }

        while self.has_pending_appointments() {
            let locators = self.pending_appointments.lock().unwrap().clone();
            for locator in locators.into_iter() {
                let appointment = self
                    .wt_client
                    .lock()
                    .unwrap()
                    .dbm
                    .load_appointment(locator)
                    .unwrap();

                match http::add_appointment(
                    tower_id,
                    &net_addr,
                    &proxy,
                    &appointment,
                    &cryptography::sign(&appointment.to_vec(), &user_sk).unwrap(),
                )
                .await
                {
                    Ok((slots, receipt)) => {
                        self.pending_appointments.lock().unwrap().remove(&locator);
                        let mut wt_client = self.wt_client.lock().unwrap();
                        wt_client.add_appointment_receipt(
                            tower_id,
                            appointment.locator,
                            slots,
                            &receipt,
                        );
                        wt_client.remove_pending_appointment(tower_id, appointment.locator);
                        log::debug!("Response verified and data stored in the database");
                    }
                    Err(e) => {
                        match e {
                            AddAppointmentError::RequestError(e) => {
                                if e.is_connection() {
                                    log::warn!(
                                        "{tower_id} cannot be reached. Tower will be retried later"
                                    );
                                    return Err(Error::transient(RetryError::Unreachable));
                                }
                            }
                            AddAppointmentError::ApiError(e) => match e.error_code {
                                errors::INVALID_SIGNATURE_OR_SUBSCRIPTION_ERROR => {
                                    log::warn!("There is a subscription issue with {tower_id}");
                                    self.wt_client
                                        .lock()
                                        .unwrap()
                                        .set_tower_status(tower_id, TowerStatus::SubscriptionError);
                                    return Err(Error::transient(RetryError::Subscription(
                                        "Subscription error".to_owned(),
                                        false,
                                    )));
                                }
                                _ => {
                                    log::warn!(
                                        "{tower_id} rejected the appointment. Error: {}, error_code: {}",
                                        e.error,
                                        e.error_code
                                    );
                                    // We need to move the appointment from pending to invalid
                                    // Add it first to invalid and remove it from pending later so a cascade delete is not triggered
                                    self.pending_appointments.lock().unwrap().remove(&locator);
                                    let mut wt_client = self.wt_client.lock().unwrap();
                                    wt_client.add_invalid_appointment(tower_id, &appointment);
                                    wt_client
                                        .remove_pending_appointment(tower_id, appointment.locator);
                                }
                            },
                            AddAppointmentError::SignatureError(proof) => {
                                return Err(Error::permanent(RetryError::Misbehaving(proof)));
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Removed our retrier identifier from the WTClient if the retrier has failed
    pub fn remove_if_failed(&self) {
        if self.failed() {
            log::debug!(
                "Removing failed retrier {} from active retriers",
                self.tower_id
            );
            self.wt_client
                .lock()
                .unwrap()
                .retriers
                .remove(&self.tower_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;
    use tempdir::TempDir;
    use tokio::sync::mpsc::unbounded_channel;

    use teos_common::errors;
    use teos_common::net::http::Endpoint;
    use teos_common::protos::AddAppointmentRequest;
    use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
    use teos_common::test_utils::{
        generate_random_appointment, get_random_registration_receipt, get_random_user_id,
        get_registration_receipt_from_previous,
    };

    use crate::net::http::ApiError;
    use crate::test_utils::get_dummy_add_appointment_response;

    const LONG_AUTO_RETRY_DELAY: u32 = 60;
    const SHORT_AUTO_RETRY_DELAY: u32 = 3;
    const API_DELAY: f64 = 0.5;
    const HALF_API_DELAY: f64 = API_DELAY / 2.0;
    const MAX_ELAPSED_TIME: u16 = 2;
    const MAX_INTERVAL_TIME: u16 = 1;
    const MAX_RUN_TIME: f64 = 0.2;

    macro_rules! wait_until {
        () => {};
        ($cond:expr $(,)?) => {
            loop {
                if $cond {
                    break;
                }
                tokio::time::sleep(Duration::from_secs_f64(0.1)).await;
            }
        };
    }

    impl Retrier {
        fn empty(wt_client: Arc<Mutex<WTClient>>, tower_id: TowerId) -> Self {
            Self {
                wt_client,
                tower_id,
                pending_appointments: Mutex::new(HashSet::new()),
                status: Mutex::new(RetrierStatus::Stopped),
            }
        }
    }

    #[tokio::test]
    async fn test_manage_retry_reachable() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), tx.clone()).await,
        ));

        let mut server = mockito::Server::new_async().await;

        // Add a tower with pending appointments
        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, &server.url(), &receipt)
            .unwrap();

        // Add appointment to pending
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Prepare the mock response
        let mut add_appointment_receipt = AppointmentReceipt::new(
            cryptography::sign(&appointment.to_vec(), &wt_client.lock().unwrap().user_sk).unwrap(),
            42,
        );
        add_appointment_receipt.sign(&tower_sk);
        let add_appointment_response =
            get_dummy_add_appointment_response(appointment.locator, &add_appointment_receipt);

        let api_mock = server
            .mock("POST", Endpoint::AddAppointment.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |_| {
                std::thread::sleep(Duration::from_secs_f64(API_DELAY));
                json!(add_appointment_response).to_string().into()
            })
            .create_async()
            .await;

        // Start the task and send the tower to the channel for retry
        tx.send((tower_id, RevocationData::Fresh(appointment.locator)))
            .unwrap();

        let wt_client_clone = wt_client.clone();
        let task = tokio::spawn(async move {
            RetryManager::new(
                wt_client_clone,
                rx,
                MAX_ELAPSED_TIME,
                LONG_AUTO_RETRY_DELAY,
                MAX_INTERVAL_TIME,
            )
            .manage_retry()
            .await
        });

        // Wait for a fraction of the API delay and check how the tower status changed
        tokio::time::sleep(Duration::from_secs_f64(HALF_API_DELAY)).await;
        assert!(wt_client
            .lock()
            .unwrap()
            .get_retrier_status(&tower_id)
            .unwrap()
            .is_running());

        wait_until!(wt_client
            .lock()
            .unwrap()
            .get_retrier_status(&tower_id)
            .is_none());

        {
            let state = wt_client.lock().unwrap();
            assert!(state.get_tower_status(&tower_id).unwrap().is_reachable());
            assert!(!state
                .towers
                .get(&tower_id)
                .unwrap()
                .pending_appointments
                .contains(&appointment.locator));
        }
        api_mock.assert_async().await;

        task.abort();
    }

    #[tokio::test]
    async fn test_manage_retry_unreachable() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), tx.clone()).await,
        ));

        // Add a tower with pending appointments
        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, "http://unreachable.tower", &receipt)
            .unwrap();

        // Add appointment to pending
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Start the task and send the tower to the channel for retry
        tx.send((tower_id, RevocationData::Fresh(appointment.locator)))
            .unwrap();

        let wt_client_clone = wt_client.clone();
        let task = tokio::spawn(async move {
            RetryManager::new(
                wt_client_clone,
                rx,
                MAX_ELAPSED_TIME,
                SHORT_AUTO_RETRY_DELAY,
                MAX_INTERVAL_TIME,
            )
            .manage_retry()
            .await
        });

        // Wait for one retry round and check to tower status
        tokio::time::sleep(Duration::from_secs_f64(MAX_RUN_TIME)).await;
        assert!(wt_client
            .lock()
            .unwrap()
            .get_tower_status(&tower_id)
            .unwrap()
            .is_temporary_unreachable());
        assert!(wt_client
            .lock()
            .unwrap()
            .get_retrier_status(&tower_id)
            .unwrap()
            .is_running());

        // Wait until the task gives up and check again (this gives up due to accumulation of transient errors, so the retriers will be idle).
        wait_until!(wt_client
            .lock()
            .unwrap()
            .get_retrier_status(&tower_id)
            .unwrap()
            .is_idle());

        assert!(wt_client
            .lock()
            .unwrap()
            .get_tower_status(&tower_id)
            .unwrap()
            .is_unreachable());

        // Add a proper server and check that the auto-retry works
        // Prepare the mock response
        let mut server = mockito::Server::new_async().await;
        let mut add_appointment_receipt = AppointmentReceipt::new(
            cryptography::sign(&appointment.to_vec(), &wt_client.lock().unwrap().user_sk).unwrap(),
            42,
        );
        add_appointment_receipt.sign(&tower_sk);
        let add_appointment_response =
            get_dummy_add_appointment_response(appointment.locator, &add_appointment_receipt);
        let api_mock = server
            .mock("POST", Endpoint::AddAppointment.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(add_appointment_response).to_string())
            .create_async()
            .await;

        // Update the tower details
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(
                tower_id,
                &server.url(),
                &get_registration_receipt_from_previous(&receipt),
            )
            .unwrap();

        // Wait and check. We wait twice the short retry delay because it can be the case that the first auto retry
        // is performed while we are patching the mock.
        tokio::time::sleep(Duration::from_secs((SHORT_AUTO_RETRY_DELAY * 2) as u64)).await;
        assert_eq!(
            wt_client
                .lock()
                .unwrap()
                .get_tower_status(&tower_id)
                .unwrap(),
            TowerStatus::Reachable
        );
        assert!(!wt_client
            .lock()
            .unwrap()
            .towers
            .get(&tower_id)
            .unwrap()
            .pending_appointments
            .contains(&appointment.locator));
        assert!(!wt_client.lock().unwrap().retriers.contains_key(&tower_id));
        api_mock.assert_async().await;

        task.abort();
    }

    #[tokio::test]
    async fn test_manage_retry_rejected() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), tx.clone()).await,
        ));
        let mut server = mockito::Server::new_async().await;

        // Add a tower with pending appointments
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, &server.url(), &receipt)
            .unwrap();

        // Add appointment to pending
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Prepare the mock response
        let api_mock = server
            .mock("POST", Endpoint::AddAppointment.path().as_str())
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body_from_request(|_| {
                std::thread::sleep(Duration::from_secs_f64(API_DELAY));
                json!(ApiError {
                    error: "error_msg".to_owned(),
                    error_code: 1,
                })
                .to_string()
                .into()
            })
            .create_async()
            .await;

        // Start the task and send the tower to the channel for retry
        tx.send((tower_id, RevocationData::Fresh(appointment.locator)))
            .unwrap();

        let wt_client_clone = wt_client.clone();
        let task = tokio::spawn(async move {
            RetryManager::new(
                wt_client_clone,
                rx,
                MAX_ELAPSED_TIME,
                LONG_AUTO_RETRY_DELAY,
                MAX_INTERVAL_TIME,
            )
            .manage_retry()
            .await
        });

        // Wait for a fraction of the API delay and check how the tower status changed
        tokio::time::sleep(Duration::from_secs_f64(HALF_API_DELAY)).await;
        assert!(wt_client
            .lock()
            .unwrap()
            .get_retrier_status(&tower_id)
            .unwrap()
            .is_running());

        // Wait for the remaining time and re-check
        wait_until!(wt_client
            .lock()
            .unwrap()
            .get_retrier_status(&tower_id)
            .is_none());

        assert!(wt_client
            .lock()
            .unwrap()
            .get_tower_status(&tower_id)
            .unwrap()
            .is_reachable());
        assert!(!wt_client
            .lock()
            .unwrap()
            .towers
            .get(&tower_id)
            .unwrap()
            .pending_appointments
            .contains(&appointment.locator));
        assert!(wt_client
            .lock()
            .unwrap()
            .towers
            .get(&tower_id)
            .unwrap()
            .invalid_appointments
            .contains(&appointment.locator));
        api_mock.assert_async().await;

        task.abort();
    }

    #[tokio::test]
    async fn test_manage_retry_misbehaving() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), tx.clone()).await,
        ));
        let mut server = mockito::Server::new_async().await;

        // Add a tower with pending appointments
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, &server.url(), &receipt)
            .unwrap();

        // Add appointment to pending
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Prepare the mock response
        let mut add_appointment_receipt = AppointmentReceipt::new(
            cryptography::sign(&appointment.to_vec(), &wt_client.lock().unwrap().user_sk).unwrap(),
            42,
        );
        // Sign with a random key so it counts as misbehaving
        add_appointment_receipt.sign(&cryptography::get_random_keypair().0);
        let add_appointment_response =
            get_dummy_add_appointment_response(appointment.locator, &add_appointment_receipt);
        let api_mock = server
            .mock("POST", Endpoint::AddAppointment.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |_| {
                std::thread::sleep(Duration::from_secs_f64(API_DELAY));
                json!(add_appointment_response).to_string().into()
            })
            .create_async()
            .await;

        // Start the task and send the tower to the channel for retry
        tx.send((tower_id, RevocationData::Fresh(appointment.locator)))
            .unwrap();

        let wt_client_clone = wt_client.clone();
        let task = tokio::spawn(async move {
            RetryManager::new(
                wt_client_clone,
                rx,
                MAX_ELAPSED_TIME,
                LONG_AUTO_RETRY_DELAY,
                MAX_INTERVAL_TIME,
            )
            .manage_retry()
            .await
        });

        // Wait for a fraction of the API delay and check how the tower status changed
        tokio::time::sleep(Duration::from_secs_f64(HALF_API_DELAY)).await;
        assert!(wt_client
            .lock()
            .unwrap()
            .get_retrier_status(&tower_id)
            .unwrap()
            .is_running());

        // Wait until the tower is no longer being retried.
        wait_until!(wt_client
            .lock()
            .unwrap()
            .get_retrier_status(&tower_id)
            .is_none());

        // The tower should have a misbehaving status.
        assert!(wt_client
            .lock()
            .unwrap()
            .get_tower_status(&tower_id)
            .unwrap()
            .is_misbehaving());
        api_mock.assert_async().await;

        task.abort();
    }

    #[tokio::test]
    async fn test_manage_retry_abandoned() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), tx.clone()).await,
        ));
        let server = mockito::Server::new_async().await;

        // Add a tower with pending appointments
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, &server.url(), &receipt)
            .unwrap();

        // Remove the tower (to simulate it has been abandoned)
        wt_client.lock().unwrap().remove_tower(tower_id).unwrap();

        // Start the task and send the tower to the channel for retry
        tx.send((tower_id, RevocationData::None)).unwrap();

        let wt_client_clone = wt_client.clone();
        let task = tokio::spawn(async move {
            RetryManager::new(
                wt_client_clone,
                rx,
                MAX_ELAPSED_TIME,
                LONG_AUTO_RETRY_DELAY,
                MAX_INTERVAL_TIME,
            )
            .manage_retry()
            .await
        });
        assert!(!wt_client.lock().unwrap().towers.contains_key(&tower_id));

        task.abort();
    }

    #[tokio::test]
    async fn test_manage_retry_subscription_error() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), tx.clone()).await,
        ));
        let mut server = mockito::Server::new_async().await;

        // Add a tower with pending appointments
        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let mut registration_receipt =
            RegistrationReceipt::new(wt_client.lock().unwrap().user_id, 21, 42, 420);
        registration_receipt.sign(&tower_sk);
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, &server.url(), &registration_receipt)
            .unwrap();

        // Add appointment to pending
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Mock the registration and add_appointment response (this is right, so after the re-registration the appointments are accepted)
        let mut re_registration_receipt =
            get_registration_receipt_from_previous(&registration_receipt);
        re_registration_receipt.sign(&tower_sk);

        let mut add_appointment_receipt = AppointmentReceipt::new(
            cryptography::sign(&appointment.to_vec(), &wt_client.lock().unwrap().user_sk).unwrap(),
            42,
        );
        add_appointment_receipt.sign(&tower_sk);
        let add_appointment_response =
            get_dummy_add_appointment_response(appointment.locator, &add_appointment_receipt);

        let api_mock = server
            .mock("POST", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |request| {
                let response = if request.path() == Endpoint::Register.path().as_str() {
                    std::thread::sleep(Duration::from_secs_f64(API_DELAY));
                    json!(re_registration_receipt).to_string()
                } else if request.path() == Endpoint::AddAppointment.path().as_str() {
                    json!(add_appointment_response).to_string()
                } else {
                    panic!("Wrong endpoint hit")
                };
                response.into()
            })
            .create_async()
            .await
            .expect(2);

        // Set the status as SubscriptionError so we simulate the retrier faced this in a previous round
        wt_client
            .lock()
            .unwrap()
            .set_tower_status(tower_id, TowerStatus::SubscriptionError);

        // Start the task and send the tower to the channel for retry
        tx.send((tower_id, RevocationData::Fresh(appointment.locator)))
            .unwrap();

        let wt_client_clone = wt_client.clone();
        let task = tokio::spawn(async move {
            RetryManager::new(
                wt_client_clone,
                rx,
                MAX_ELAPSED_TIME,
                LONG_AUTO_RETRY_DELAY,
                MAX_INTERVAL_TIME,
            )
            .manage_retry()
            .await
        });

        // Wait for a fraction of the API delay and check how the tower status changed
        tokio::time::sleep(Duration::from_secs_f64(HALF_API_DELAY)).await;
        assert!(wt_client
            .lock()
            .unwrap()
            .get_retrier_status(&tower_id)
            .unwrap()
            .is_running());

        // Wait for the remaining time and re-check
        wait_until!(wt_client
            .lock()
            .unwrap()
            .get_retrier_status(&tower_id)
            .is_none());

        {
            let state = wt_client.lock().unwrap();
            let tower = state.towers.get(&tower_id).unwrap();
            assert!(tower.status.is_reachable());
            assert!(tower.pending_appointments.is_empty());
        }
        api_mock.assert_async().await;

        task.abort();
    }

    #[tokio::test]
    async fn test_manage_retry_while_idle() {
        use crate::dbm::DBM;
        // Let's try adding a tower, setting it to idle and send revocation data in all its forms
        // This replicates the three types of data the retrier can receive:
        // - Initialization (from db) with stale data
        // - Regular (fresh) data from `on_commitment_revocation`
        // - A wake up call with no data

        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let (tx, rx) = unbounded_channel();

        // Stale data is sent on WTClient initialization if found in the database. We'll force that to happen by populating the DB before initializing the WTClient
        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);

        let mut dbm = DBM::new(&tmp_path.path().to_path_buf().join("watchtowers_db.sql3")).unwrap();
        let receipt = get_random_registration_receipt();
        dbm.store_tower_record(tower_id, "http://unreachable.tower", &receipt)
            .unwrap();

        let appointment = generate_random_appointment(None);
        dbm.store_pending_appointment(tower_id, &appointment)
            .unwrap();

        // Now we can create the WTClient and check that the data is pending
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), tx.clone()).await,
        ));

        // Also create the retrier thread so retries can be managed
        let wt_client_clone = wt_client.clone();
        let task = tokio::spawn(async move {
            RetryManager::new(
                wt_client_clone,
                rx,
                MAX_ELAPSED_TIME,
                LONG_AUTO_RETRY_DELAY,
                MAX_INTERVAL_TIME,
            )
            .manage_retry()
            .await
        });

        {
            // After the retriers gives up, it should go idling and flag the tower as unreachable
            tokio::time::sleep(Duration::from_secs_f64(
                MAX_ELAPSED_TIME as f64 + MAX_RUN_TIME,
            ))
            .await;

            wait_until!(wt_client
                .lock()
                .unwrap()
                .get_retrier_status(&tower_id)
                .unwrap()
                .is_idle());

            let state = wt_client.lock().unwrap();
            let tower = state.towers.get(&tower_id).unwrap();
            assert!(tower.pending_appointments.contains(&appointment.locator));
            assert_eq!(tower.status, TowerStatus::Unreachable);
        }

        // With the retrier idling all fresh data sent to it will be stored but it won't trigger a retry.
        // (we can check the data was stored later on)
        let appointment2 = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment2);
        tx.send((tower_id, RevocationData::Fresh(appointment2.locator)))
            .unwrap();

        {
            tokio::time::sleep(Duration::from_secs_f64(POLLING_TIME as f64 + MAX_RUN_TIME)).await;
            let state = wt_client.lock().unwrap();
            assert!(state.get_retrier_status(&tower_id).unwrap().is_idle());
            let tower = state.towers.get(&tower_id).unwrap();
            assert_eq!(tower.status, TowerStatus::Unreachable);
        }

        // Create the receipts, the responses and set the mocks
        let mut appointment_receipt = AppointmentReceipt::new(
            cryptography::sign(&appointment.to_vec(), &wt_client.lock().unwrap().user_sk).unwrap(),
            42,
        );
        let mut appointment2_receipt = AppointmentReceipt::new(
            cryptography::sign(&appointment2.to_vec(), &wt_client.lock().unwrap().user_sk).unwrap(),
            42,
        );
        appointment_receipt.sign(&tower_sk);
        appointment2_receipt.sign(&tower_sk);

        // Mock a proper response
        let mut server = mockito::Server::new_async().await;

        let api_mock = server
            .mock("POST", Endpoint::AddAppointment.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |request| {
                let body = serde_json::from_slice::<AddAppointmentRequest>(request.body().unwrap())
                    .unwrap();

                let response = if body.appointment.unwrap().locator == appointment.locator.to_vec()
                {
                    get_dummy_add_appointment_response(appointment.locator, &appointment_receipt)
                } else {
                    get_dummy_add_appointment_response(appointment2.locator, &appointment2_receipt)
                };
                json!(response).to_string().into()
            })
            .expect(2)
            .create_async()
            .await;

        // Patch the tower address
        wt_client
            .lock()
            .unwrap()
            .towers
            .get_mut(&tower_id)
            .unwrap()
            .set_net_addr(server.url());

        // Check pending data is still there now, and is it not once the retrier succeeds
        assert_eq!(
            wt_client
                .lock()
                .unwrap()
                .towers
                .get(&tower_id)
                .unwrap()
                .pending_appointments
                .len(),
            2,
        );

        // Send a retry flag to the retrier to force a retry.
        tx.send((tower_id, RevocationData::None)).unwrap();

        // After retrying the pending pool has been emptied, meaning that both appointments went trough
        tokio::time::sleep(Duration::from_secs_f64(POLLING_TIME as f64 + MAX_RUN_TIME)).await;
        assert!(!wt_client.lock().unwrap().retriers.contains_key(&tower_id));
        assert!(wt_client
            .lock()
            .unwrap()
            .towers
            .get(&tower_id)
            .unwrap()
            .pending_appointments
            .is_empty());
        api_mock.assert_async().await;

        task.abort();
    }

    #[tokio::test]
    async fn test_retry_tower() {
        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await,
        ));
        let mut server = mockito::Server::new_async().await;

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, &server.url(), &receipt)
            .unwrap();

        // Add appointment to pending
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Prepare the mock response
        let mut add_appointment_receipt = AppointmentReceipt::new(
            cryptography::sign(&appointment.to_vec(), &wt_client.lock().unwrap().user_sk).unwrap(),
            42,
        );
        add_appointment_receipt.sign(&tower_sk);
        let add_appointment_response =
            get_dummy_add_appointment_response(appointment.locator, &add_appointment_receipt);
        let api_mock = server
            .mock("POST", Endpoint::AddAppointment.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(add_appointment_response).to_string())
            .create_async()
            .await;

        // Since we are retrying manually, we need to add the data to pending appointments manually too
        let retrier = Retrier::new(wt_client, tower_id, HashSet::from([appointment.locator]));
        let r = retrier.run().await;
        assert_eq!(r, Ok(()));
        api_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_retry_tower_no_pending() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await,
        ));
        let server = mockito::Server::new_async().await;

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, &server.url(), &receipt)
            .unwrap();

        // If there are no pending appointments the method will simply return
        let r = Retrier::empty(wt_client, tower_id).run().await;
        assert_eq!(r, Ok(()));
    }

    #[tokio::test]
    async fn test_retry_tower_misbehaving() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await,
        ));
        let mut server = mockito::Server::new_async().await;

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, &server.url(), &receipt)
            .unwrap();

        // Add appointment to pending
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Prepare the mock response
        let mut add_appointment_receipt = AppointmentReceipt::new(
            cryptography::sign(&appointment.to_vec(), &wt_client.lock().unwrap().user_sk).unwrap(),
            42,
        );
        add_appointment_receipt.sign(&cryptography::get_random_keypair().0);
        let add_appointment_response =
            get_dummy_add_appointment_response(appointment.locator, &add_appointment_receipt);
        let api_mock = server
            .mock("POST", Endpoint::AddAppointment.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(add_appointment_response).to_string())
            .create_async()
            .await;

        // Since we are retrying manually, we need to add the data to pending appointments manually too
        let retrier = Retrier::new(wt_client, tower_id, HashSet::from([appointment.locator]));
        let r = retrier.run().await;
        assert!(matches!(
            r,
            Err(Error::Permanent(RetryError::Misbehaving { .. },))
        ));
        api_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_retry_tower_unreachable() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await,
        ));

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, "http://unreachable.tower", &receipt)
            .unwrap();

        // Add some pending appointments and try again (with an unreachable tower).
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Since we are retrying manually, we need to add the data to pending appointments manually too
        let retrier = Retrier::new(wt_client, tower_id, HashSet::from([appointment.locator]));
        let r = retrier.run().await;

        assert_eq!(r, Err(Error::transient(RetryError::Unreachable)));
    }

    #[tokio::test]
    async fn test_retry_tower_subscription_error() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await,
        ));
        let mut server = mockito::Server::new_async().await;

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, &server.url(), &receipt)
            .unwrap();

        let api_mock = server
            .mock("POST", Endpoint::AddAppointment.path().as_str())
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(
                json!(ApiError {
                    error: "error_msg".to_owned(),
                    error_code: errors::INVALID_SIGNATURE_OR_SUBSCRIPTION_ERROR,
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Add some pending appointments and try again (with an unreachable tower).
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Since we are retrying manually, we need to add the data to pending appointments manually too
        let retrier = Retrier::new(wt_client, tower_id, HashSet::from([appointment.locator]));
        let r = retrier.run().await;

        assert!(matches!(
            r,
            Err(Error::Transient {
                err: RetryError::Subscription { .. },
                ..
            })
        ));
        api_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_retry_tower_rejected() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await,
        ));
        let mut server = mockito::Server::new_async().await;

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, &server.url(), &receipt)
            .unwrap();

        let api_mock = server
            .mock("POST", Endpoint::AddAppointment.path().as_str())
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(
                json!(ApiError {
                    error: "error_msg".to_owned(),
                    error_code: 1,
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Add some pending appointments and try again (with an unreachable tower).
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Since we are retrying manually, we need to add the data to pending appointments manually too
        let retrier = Retrier::new(
            wt_client.clone(),
            tower_id,
            HashSet::from([appointment.locator]),
        );
        let r = retrier.run().await;

        assert!(wt_client
            .lock()
            .unwrap()
            .towers
            .get(&tower_id)
            .unwrap()
            .invalid_appointments
            .contains(&appointment.locator));
        assert!(r.is_ok());
        api_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_retry_tower_abandoned() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await,
        ));

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, "http://tower.adrress", &receipt)
            .unwrap();

        // Remove the tower (to simulate it has been abandoned)
        wt_client.lock().unwrap().remove_tower(tower_id).unwrap();

        // If there are no pending appointments the method will simply return
        let r = Retrier::empty(wt_client, tower_id).run().await;

        assert_eq!(r, Err(Error::permanent(RetryError::Abandoned)));
    }
}
