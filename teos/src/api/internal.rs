use std::sync::{Arc, Condvar, Mutex};
use tonic::{Code, Request, Response, Status};
use triggered::Trigger;

use crate::extended_appointment::UUID;
use crate::protos as msgs;
use crate::protos::private_tower_services_server::PrivateTowerServices;
use crate::protos::public_tower_services_server::PublicTowerServices;
use crate::watcher::{
    AddAppointmentFailure, AppointmentInfo, GetAppointmentFailure, GetSubscriptionInfoFailure,
    Watcher,
};

use teos_common::appointment::{Appointment, AppointmentStatus, Locator};
use teos_common::protos as common_msgs;
use teos_common::UserId;

/// Internal API of the tower.
/// Holds the [Watcher] (which is the single entry point of the tower's core) and offers interfaces
/// to all available methods. The [InternalAPI] has two interfaces, a public one, reachable from the [API]
/// and a private one, only accessible from the [RPCServer].
pub struct InternalAPI {
    /// A [Watcher] instance.
    watcher: Arc<Watcher>,
    /// A list of public API endpoints.
    addresses: Vec<msgs::NetworkAddress>,
    /// A flag that indicates wether bitcoind is reachable or not.
    bitcoind_reachable: Arc<(Mutex<bool>, Condvar)>,
    /// A signal indicating the tower is shuting down.
    shutdown_trigger: Trigger,
}

impl InternalAPI {
    /// Creates a new [InternalAPI] instance.
    pub fn new(
        watcher: Arc<Watcher>,
        addresses: Vec<msgs::NetworkAddress>,
        bitcoind_reachable: Arc<(Mutex<bool>, Condvar)>,
        shutdown_trigger: Trigger,
    ) -> Self {
        Self {
            watcher,
            addresses,
            bitcoind_reachable,
            shutdown_trigger,
        }
    }

    pub fn get_addresses(&self) -> &Vec<msgs::NetworkAddress> {
        &self.addresses
    }

    /// Checks whether bitcoind is reachable.
    fn check_service_unavailable(&self) -> Result<(), Status> {
        if *self.bitcoind_reachable.0.lock().unwrap() {
            Ok(())
        } else {
            log::error!("Bitcoind not reachable");
            Err(Status::new(
                Code::Unavailable,
                "Service currently unavailable",
            ))
        }
    }
}

/// Public tower API. Accessible by users.
#[tonic::async_trait]
impl PublicTowerServices for Arc<InternalAPI> {
    /// Register endpoint. Part of the public API. Internally calls [Watcher::register].
    async fn register(
        &self,
        request: Request<common_msgs::RegisterRequest>,
    ) -> Result<Response<common_msgs::RegisterResponse>, Status> {
        self.check_service_unavailable()?;
        let req_data = request.into_inner();

        let user_id = UserId::from_slice(&req_data.user_id).map_err(|_| {
            Status::new(
                Code::InvalidArgument,
                "Provided public key does not match expected format (33-byte compressed key)",
            )
        })?;

        match self.watcher.register(user_id) {
            Ok(receipt) => Ok(Response::new(common_msgs::RegisterResponse {
                user_id: req_data.user_id,
                available_slots: receipt.available_slots(),
                subscription_start: receipt.subscription_start(),
                subscription_expiry: receipt.subscription_expiry(),
                subscription_signature: receipt.signature().unwrap(),
            })),
            Err(_) => Err(Status::new(
                Code::ResourceExhausted,
                "Subscription maximum slots count reached",
            )),
        }
    }

    /// Add appointment endpoint. Part of the public API. Internally calls [Watcher::add_appointment].
    async fn add_appointment(
        &self,
        request: Request<common_msgs::AddAppointmentRequest>,
    ) -> Result<Response<common_msgs::AddAppointmentResponse>, Status> {
        self.check_service_unavailable()?;
        let req_data = request.into_inner();
        let app_data = req_data.appointment.unwrap();

        let appointment = Appointment::new(
            Locator::from_slice(&app_data.locator).unwrap(),
            app_data.encrypted_blob,
            app_data.to_self_delay,
        );
        let locator = appointment.locator;

        match self
            .watcher
            .add_appointment(appointment, req_data.signature)
        {
            Ok((receipt, available_slots, subscription_expiry)) => {
                Ok(Response::new(common_msgs::AddAppointmentResponse {
                    locator: locator.to_vec(),
                    start_block: receipt.start_block(),
                    signature: receipt.signature().unwrap(),
                    available_slots,
                    subscription_expiry,
                }))
            }
            Err(e) => match e {
                AddAppointmentFailure::AuthenticationFailure
                | AddAppointmentFailure::NotEnoughSlots => Err(Status::new(
                    Code::Unauthenticated,
                    "Invalid signature or user does not have enough slots available",
                )),
                AddAppointmentFailure::SubscriptionExpired(x) => Err(Status::new(
                    Code::Unauthenticated,
                    format!("Your subscription expired at {x}"),
                )),
                AddAppointmentFailure::AlreadyTriggered => Err(Status::new(
                    Code::AlreadyExists,
                    "The provided appointment has already been triggered",
                )),
            },
        }
    }

    /// Get appointment endpoint. Part of the public API. Internally calls [Watcher::get_appointment].
    async fn get_appointment(
        &self,
        request: Request<common_msgs::GetAppointmentRequest>,
    ) -> Result<Response<common_msgs::GetAppointmentResponse>, Status> {
        self.check_service_unavailable()?;
        let req_data = request.into_inner();
        let locator = Locator::from_slice(&req_data.locator).unwrap();

        match self.watcher.get_appointment(locator, &req_data.signature) {
            Ok(info) => {
                let (appointment_data, status) = match info {
                    AppointmentInfo::Appointment(appointment) => (
                        common_msgs::AppointmentData {
                            appointment_data: Some(
                                common_msgs::appointment_data::AppointmentData::Appointment(
                                    appointment.into(),
                                ),
                            ),
                        },
                        AppointmentStatus::BeingWatched,
                    ),
                    AppointmentInfo::Tracker(tracker) => (
                        common_msgs::AppointmentData {
                            appointment_data: Some(
                                common_msgs::appointment_data::AppointmentData::Tracker(
                                    tracker.into(),
                                ),
                            ),
                        },
                        AppointmentStatus::DisputeResponded,
                    ),
                };
                Ok(Response::new(common_msgs::GetAppointmentResponse {
                    appointment_data: Some(appointment_data),
                    status: status as i32,
                }))
            }
            Err(e) => match e {
                GetAppointmentFailure::NotFound => {
                    Err(Status::new(Code::NotFound, "Appointment not found"))
                }
                GetAppointmentFailure::AuthenticationFailure => Err(Status::new(
                    Code::Unauthenticated,
                    "User cannot be authenticated",
                )),
                GetAppointmentFailure::SubscriptionExpired(x) => Err(Status::new(
                    Code::Unauthenticated,
                    format!("Your subscription expired at {x}"),
                )),
            },
        }
    }

    /// Get subscription info endpoint. Part of the public API. Internally calls [Watcher::get_subscription_info].
    async fn get_subscription_info(
        &self,
        request: Request<common_msgs::GetSubscriptionInfoRequest>,
    ) -> Result<Response<common_msgs::GetSubscriptionInfoResponse>, Status> {
        self.check_service_unavailable()?;
        let (subscription_info, locators) = self
            .watcher
            .get_subscription_info(&request.into_inner().signature)
            .map_err(|e| match e {
                GetSubscriptionInfoFailure::AuthenticationFailure => Status::new(
                    Code::Unauthenticated,
                    "User not found. Have you registered?",
                ),
                GetSubscriptionInfoFailure::SubscriptionExpired(x) => Status::new(
                    Code::Unauthenticated,
                    format!("Your subscription expired at {x}"),
                ),
            })?;

        Ok(Response::new(common_msgs::GetSubscriptionInfoResponse {
            available_slots: subscription_info.available_slots,
            subscription_expiry: subscription_info.subscription_expiry,
            locators: locators.iter().map(|x| x.to_vec()).collect(),
        }))
    }
}

/// Private tower API. Only accessible by the tower admin via RPC.
#[tonic::async_trait]
impl PrivateTowerServices for Arc<InternalAPI> {
    /// Get all appointments endpoint. Gets all appointments in the tower. Part of the private API.
    /// Internally calls [Watcher::get_all_watcher_appointments] and [Watcher::get_all_responder_trackers].
    async fn get_all_appointments(
        &self,
        request: Request<()>,
    ) -> Result<Response<msgs::GetAllAppointmentsResponse>, Status> {
        log::debug!(
            "Received a get_all_appointments request from {}",
            request
                .remote_addr()
                .map_or("an unknown address".to_owned(), |a| a.to_string())
        );

        let mut all_appointments = Vec::new();

        for (_, appointment) in self.watcher.get_all_watcher_appointments().into_iter() {
            all_appointments.push(common_msgs::AppointmentData {
                appointment_data: Some(
                    common_msgs::appointment_data::AppointmentData::Appointment(
                        appointment.inner.into(),
                    ),
                ),
            })
        }

        for (_, tracker) in self.watcher.get_all_responder_trackers().into_iter() {
            all_appointments.push(common_msgs::AppointmentData {
                appointment_data: Some(common_msgs::appointment_data::AppointmentData::Tracker(
                    tracker.into(),
                )),
            })
        }

        Ok(Response::new(msgs::GetAllAppointmentsResponse {
            appointments: all_appointments,
        }))
    }

    /// Get appointments endpoint. Gets the appointments with a specific locator. Part of the private API.
    /// Internally calls [Watcher::get_watcher_appointments_using_locator] and [Watcher::get_responder_trackers_using_locator].
    async fn get_appointments(
        &self,
        request: tonic::Request<msgs::GetAppointmentsRequest>,
    ) -> Result<tonic::Response<msgs::GetAppointmentsResponse>, Status> {
        log::debug!(
            "Received a get_appointments requests from {}",
            request
                .remote_addr()
                .map_or("an unknown address".to_owned(), |a| a.to_string())
        );

        let mut matching_appointments = vec![];
        let locator = Locator::from_slice(&request.into_inner().locator).map_err(|_| {
            Status::new(
                Code::InvalidArgument,
                "The provided locator does not match the expected format (16-byte hexadecimal string)",
            )
        })?;

        for (_, appointment) in self
            .watcher
            .get_watcher_appointments_with_locator(locator)
            .into_iter()
        {
            matching_appointments.push(common_msgs::AppointmentData {
                appointment_data: Some(
                    common_msgs::appointment_data::AppointmentData::Appointment(
                        appointment.inner.into(),
                    ),
                ),
            })
        }

        for (_, tracker) in self
            .watcher
            .get_responder_trackers_with_locator(locator)
            .into_iter()
        {
            matching_appointments.push(common_msgs::AppointmentData {
                appointment_data: Some(common_msgs::appointment_data::AppointmentData::Tracker(
                    tracker.into(),
                )),
            })
        }

        Ok(Response::new(msgs::GetAppointmentsResponse {
            appointments: matching_appointments,
        }))
    }

    /// Get tower info endpoint. Gets information about the tower state. Part of the private API.
    /// Internally calls [Watcher::get_registered_users_count], [Watcher::get_appointments_count]
    /// and [Watcher::get_trackers_count].
    async fn get_tower_info(
        &self,
        request: Request<()>,
    ) -> Result<Response<msgs::GetTowerInfoResponse>, Status> {
        log::debug!(
            "Received a get_tower_info request from {}",
            request
                .remote_addr()
                .map_or("an unknown address".to_owned(), |a| a.to_string())
        );

        Ok(Response::new(msgs::GetTowerInfoResponse {
            tower_id: self.watcher.tower_id.to_vec(),
            addresses: self.get_addresses().clone(),
            n_registered_users: self.watcher.get_registered_users_count() as u32,
            n_watcher_appointments: self.watcher.get_appointments_count() as u32,
            n_responder_trackers: self.watcher.get_trackers_count() as u32,
            bitcoind_reachable: self.check_service_unavailable().is_ok(),
        }))
    }

    /// Get user endpoint. Gets all users in the tower. Part of the private API.
    /// Internally calls [Watcher::get_user_ids].
    async fn get_users(
        &self,
        request: Request<()>,
    ) -> Result<Response<msgs::GetUsersResponse>, Status> {
        log::debug!(
            "Received a get_users requests from {}",
            request
                .remote_addr()
                .map_or("an unknown address".to_owned(), |a| a.to_string())
        );

        let user_ids = self
            .watcher
            .get_user_ids()
            .iter()
            .map(|x| x.to_vec())
            .collect();

        Ok(Response::new(msgs::GetUsersResponse { user_ids }))
    }

    /// Get user endpoint. Gets information about a given user. Part of the private API.
    /// Internally calls [Watcher::get_user].
    async fn get_user(
        &self,
        request: Request<msgs::GetUserRequest>,
    ) -> Result<Response<msgs::GetUserResponse>, Status> {
        log::debug!(
            "Received a get_user request from {}",
            request
                .remote_addr()
                .map_or("an unknown address".to_owned(), |a| a.to_string())
        );

        let user_id = UserId::from_slice(&request.into_inner().user_id).map_err(|_| {
            Status::new(
                Code::InvalidArgument,
                "Provided public key does not match expected format (33-byte compressed key)",
            )
        })?;

        match self.watcher.get_user_info(user_id) {
            Some((info, locators)) => Ok(Response::new(msgs::GetUserResponse {
                available_slots: info.available_slots,
                subscription_expiry: info.subscription_expiry,
                // TODO: Should make it return locators and make `get_appointments` queryable using the (user_id, locator) pair for consistency.
                appointments: locators
                    .into_iter()
                    .map(|locator| UUID::new(locator, user_id).to_vec())
                    .collect(),
            })),
            None => Err(Status::new(Code::NotFound, "User not found")),
        }
    }

    /// Stop endpoint. Stops the tower daemon. Part of the private API.
    async fn stop(&self, request: Request<()>) -> Result<Response<()>, Status> {
        self.shutdown_trigger.trigger();

        log::debug!(
            "Received a shutting down request from {}, notifying components",
            request
                .remote_addr()
                .map_or("an unknown address".to_owned(), |a| a.to_string())
        );
        Ok(Response::new(()))
    }
}

#[cfg(test)]
mod tests_private_helpers {
    use super::*;

    impl InternalAPI {
        pub(crate) fn get_watcher(&self) -> &Watcher {
            &self.watcher
        }
    }
}

#[cfg(test)]
mod tests_private_api {
    use super::*;
    use std::collections::HashSet;
    use std::iter::FromIterator;

    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    use crate::responder::{ConfirmationStatus, TransactionTracker};
    use crate::test_utils::{
        create_api, generate_dummy_appointment, generate_dummy_appointment_with_user,
        get_random_tx, DURATION, SLOTS, START_HEIGHT,
    };
    use crate::watcher::Breach;

    use teos_common::cryptography::{self, get_random_keypair};
    use teos_common::test_utils::get_random_user_id;

    #[tokio::test]
    async fn test_get_all_appointments() {
        let (internal_api, _s) = create_api().await;

        let response = internal_api
            .get_all_appointments(Request::new(()))
            .await
            .unwrap()
            .into_inner();

        assert!(matches!(response, msgs::GetAllAppointmentsResponse { .. }));
    }

    #[tokio::test]
    async fn test_get_all_appointments_watcher() {
        let (internal_api, _s) = create_api().await;

        // Add data to the Watcher so we can retrieve it later on
        let (user_sk, user_pk) = get_random_keypair();
        internal_api.watcher.register(UserId(user_pk)).unwrap();

        let appointment = generate_dummy_appointment(None).inner;
        let user_signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();
        internal_api
            .watcher
            .add_appointment(appointment.clone(), user_signature)
            .unwrap();

        let response = internal_api
            .get_all_appointments(Request::new(()))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.appointments.len(), 1);
        assert!(matches!(
            response.appointments[0].appointment_data,
            Some(common_msgs::appointment_data::AppointmentData::Appointment { .. })
        ));
    }

    #[tokio::test]
    async fn test_get_all_appointments_responder() {
        let (internal_api, _s) = create_api().await;

        // Add data to the Responser so we can retrieve it later on
        internal_api.watcher.add_random_tracker_to_responder();

        let response = internal_api
            .get_all_appointments(Request::new(()))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.appointments.len(), 1);
        assert!(matches!(
            response.appointments[0].appointment_data,
            Some(common_msgs::appointment_data::AppointmentData::Tracker { .. })
        ));
    }

    #[tokio::test]
    async fn test_get_appointments() {
        let (internal_api, _s) = create_api().await;

        let locator = Locator::new(get_random_tx().compute_txid()).to_vec();
        let response = internal_api
            .get_appointments(Request::new(msgs::GetAppointmentsRequest { locator }))
            .await
            .unwrap()
            .into_inner();

        assert!(matches!(response, msgs::GetAppointmentsResponse { .. }));
    }

    #[tokio::test]
    async fn test_get_appointments_watcher() {
        let (internal_api, _s) = create_api().await;

        for i in 0..3 {
            // Create a dispute tx to be used for creating different dummy appointments with the same locator.
            let dispute_txid = get_random_tx().compute_txid();

            // The number of different appointments to create for this dispute tx.
            let appointments_to_create = 4 * i + 7;

            // Add that many appointments to the watcher.
            for _ in 0..appointments_to_create {
                let (user_sk, user_pk) = get_random_keypair();
                internal_api.watcher.register(UserId(user_pk)).unwrap();
                let appointment = generate_dummy_appointment(Some(&dispute_txid)).inner;
                let signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();
                internal_api
                    .watcher
                    .add_appointment(appointment, signature)
                    .unwrap();
            }

            let locator = Locator::new(dispute_txid);

            // Query for the current locator and assert it retrieves correct appointments.
            let response = internal_api
                .get_appointments(Request::new(msgs::GetAppointmentsRequest {
                    locator: locator.to_vec(),
                }))
                .await
                .unwrap()
                .into_inner();

            // The response should contain `appointments_to_create` appointments, all having the locator of the current iteration.
            assert_eq!(response.appointments.len(), appointments_to_create);
            for app_data in response.appointments {
                assert!(matches!(
                    app_data.appointment_data,
                    Some(common_msgs::appointment_data::AppointmentData::Appointment(
                        common_msgs::Appointment {
                            locator: ref app_loc,
                            ..
                        }
                    )) if Locator::from_slice(app_loc).unwrap() == locator
                ));
            }
        }
    }

    #[tokio::test]
    async fn test_get_appointments_responder() {
        let (internal_api, _s) = create_api().await;

        for i in 0..3 {
            // Create a dispute tx to be used for creating different trackers.
            let dispute_tx = get_random_tx();
            let breach = Breach::new(dispute_tx.clone(), get_random_tx());

            // The number of different trackers to create for this dispute tx.
            let trackers_to_create = 4 * i + 7;

            // Add that many trackers to the responder.
            for _ in 0..trackers_to_create {
                let tracker = TransactionTracker::new(
                    breach.clone(),
                    get_random_user_id(),
                    ConfirmationStatus::ConfirmedIn(100),
                );
                internal_api
                    .watcher
                    .add_dummy_tracker_to_responder(&tracker);
            }

            let locator = Locator::new(dispute_tx.compute_txid());

            // Query for the current locator and assert it retrieves correct trackers.
            let response = internal_api
                .get_appointments(Request::new(msgs::GetAppointmentsRequest {
                    locator: locator.to_vec(),
                }))
                .await
                .unwrap()
                .into_inner();

            // The response should contain `trackers_to_create` trackers, all with dispute txid that matches with the locator of the current iteration.
            assert_eq!(response.appointments.len(), trackers_to_create);
            for app_data in response.appointments {
                assert!(matches!(
                    app_data.appointment_data,
                    Some(common_msgs::appointment_data::AppointmentData::Tracker(
                        common_msgs::Tracker {
                            ref dispute_txid,
                            ..
                        }
                    )) if Locator::new(Txid::from_slice(dispute_txid).unwrap()) == locator
                ));
            }
        }
    }

    #[tokio::test]
    async fn test_get_tower_info_empty() {
        let (internal_api, _s) = create_api().await;

        let response = internal_api
            .get_tower_info(Request::new(()))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.tower_id, internal_api.watcher.tower_id.to_vec());
        assert_eq!(response.n_registered_users, 0);
        assert_eq!(response.n_watcher_appointments, 0);
        assert_eq!(response.n_responder_trackers, 0);
    }

    #[tokio::test]
    async fn test_get_tower_info() {
        let (internal_api, _s) = create_api().await;

        // Register a user
        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        internal_api.watcher.register(user_id).unwrap();

        // Add data to the Watcher
        for _ in 0..2 {
            let appointment = generate_dummy_appointment(None).inner;
            let user_signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();
            internal_api
                .watcher
                .add_appointment(appointment.clone(), user_signature)
                .unwrap();
        }

        // And the Responder
        for _ in 0..3 {
            internal_api.watcher.add_random_tracker_to_responder();
        }

        let response = internal_api
            .get_tower_info(Request::new(()))
            .await
            .unwrap()
            .into_inner();

        // Given get_tower_info checks data in memory, the data added to the Responder in the test won't be added to the Watcher too.
        assert_eq!(response.tower_id, internal_api.watcher.tower_id.to_vec());
        assert_eq!(response.n_registered_users, 1);
        assert_eq!(response.n_watcher_appointments, 2);
        assert_eq!(response.n_responder_trackers, 3);
    }

    #[tokio::test]
    async fn test_get_users() {
        let (internal_api, _s) = create_api().await;
        let mut users = HashSet::new();

        // Add a couple of users
        for _ in 0..2 {
            let (_, user_pk) = get_random_keypair();
            let user_id = UserId(user_pk);
            internal_api.watcher.register(user_id).unwrap();
            users.insert(user_id.to_vec());
        }

        let response = internal_api
            .get_users(Request::new(()))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(HashSet::from_iter(response.user_ids), users);
    }

    #[tokio::test]
    async fn test_get_users_empty() {
        let (internal_api, _s) = create_api().await;

        let response = internal_api
            .get_users(Request::new(()))
            .await
            .unwrap()
            .into_inner();

        assert!(response.user_ids.is_empty());
    }

    #[tokio::test]
    async fn test_get_user() {
        let (internal_api, _s) = create_api().await;

        // Register a user and get it back
        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        internal_api.watcher.register(user_id).unwrap();

        let response = internal_api
            .get_user(Request::new(msgs::GetUserRequest {
                user_id: user_id.to_vec(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.available_slots, SLOTS);
        assert_eq!(response.subscription_expiry, START_HEIGHT as u32 + DURATION);
        assert!(response.appointments.is_empty());

        // Add an appointment and check back
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        let user_signature = cryptography::sign(&appointment.inner.to_vec(), &user_sk).unwrap();
        internal_api
            .watcher
            .add_appointment(appointment.inner, user_signature)
            .unwrap();

        let response = internal_api
            .get_user(Request::new(msgs::GetUserRequest {
                user_id: user_id.to_vec(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.available_slots, SLOTS - 1);
        assert_eq!(response.subscription_expiry, START_HEIGHT as u32 + DURATION);
        assert_eq!(response.appointments, Vec::from([uuid.to_vec()]));
    }

    #[tokio::test]
    async fn test_get_user_not_found() {
        let (internal_api, _s) = create_api().await;

        // Non-registered user
        let (_, user_pk) = get_random_keypair();

        match internal_api
            .get_user(Request::new(msgs::GetUserRequest {
                user_id: UserId(user_pk).to_vec(),
            }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::NotFound);
                assert_eq!(status.message(), "User not found")
            }
            _ => panic!("Test should have returned Err"),
        }
    }

    #[tokio::test]
    async fn test_stop() {
        let (internal_api, _s) = create_api().await;

        assert!(!internal_api.shutdown_trigger.is_triggered());
        internal_api.stop(Request::new(())).await.unwrap();
        assert!(internal_api.shutdown_trigger.is_triggered());
    }
}

#[cfg(test)]
mod tests_public_api {
    use super::*;

    use crate::responder::{ConfirmationStatus, TransactionTracker};
    use crate::test_utils::{
        create_api, create_api_with_config, generate_dummy_appointment, get_random_tx, ApiConfig,
        DURATION, SLOTS,
    };
    use crate::watcher::Breach;
    use teos_common::cryptography::{self, get_random_keypair};

    #[tokio::test]
    async fn test_register() {
        let (internal_api, _s) = create_api().await;

        let (_, user_pk) = get_random_keypair();

        // Registering (even multiple times) should work
        for _ in 0..2 {
            let response = internal_api
                .register(Request::new(common_msgs::RegisterRequest {
                    user_id: UserId(user_pk).to_vec(),
                }))
                .await
                .unwrap()
                .into_inner();

            assert!(matches!(response, common_msgs::RegisterResponse { .. }))
        }
    }

    #[tokio::test]
    async fn test_register_wrong_user_id() {
        let (internal_api, _s) = create_api().await;

        let mut user_ids = Vec::new();

        // Wrong user id size
        let (_, user_pk) = get_random_keypair();
        let mut user_id_vec = UserId(user_pk).to_vec();
        user_id_vec.pop();
        user_ids.push(user_id_vec);

        // Wrong format (does not start with 2 nor 3)
        user_id_vec = UserId(user_pk).to_vec();
        user_id_vec[0] = 1;
        user_ids.push(user_id_vec);

        for user_id in user_ids {
            match internal_api
                .register(Request::new(common_msgs::RegisterRequest { user_id }))
                .await
            {
                Err(status) => {
                    assert_eq!(status.code(), Code::InvalidArgument);
                    assert_eq!(status.message(), "Provided public key does not match expected format (33-byte compressed key)")
                }
                _ => panic!("Test should have returned Err"),
            }
        }
    }

    #[tokio::test]
    async fn test_register_max_slots() {
        let (internal_api, _s) = create_api_with_config(ApiConfig::new(u32::MAX, DURATION)).await;

        let (_, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk).to_vec();

        // First registration should go trough
        internal_api
            .register(Request::new(common_msgs::RegisterRequest {
                user_id: user_id.clone(),
            }))
            .await
            .unwrap();

        // Trying to add more slots (re-register) must fail
        match internal_api
            .register(Request::new(common_msgs::RegisterRequest { user_id }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::ResourceExhausted);
                assert_eq!(status.message(), "Subscription maximum slots count reached")
            }
            _ => panic!("Test should have returned Err"),
        }
    }

    #[tokio::test]
    async fn test_register_service_unavailable() {
        let (internal_api, _s) =
            create_api_with_config(ApiConfig::new(u32::MAX, DURATION).bitcoind_unreachable()).await;

        let (_, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk).to_vec();

        match internal_api
            .register(Request::new(common_msgs::RegisterRequest { user_id }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::Unavailable);
                assert_eq!(status.message(), "Service currently unavailable")
            }
            _ => panic!("Test should have returned Err"),
        }
    }

    #[tokio::test]
    async fn test_add_appointment() {
        let (internal_api, _s) = create_api().await;

        // User must be registered
        let (user_sk, user_pk) = get_random_keypair();
        internal_api.watcher.register(UserId(user_pk)).unwrap();

        let appointment = generate_dummy_appointment(None).inner;
        let signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();

        let response = internal_api
            .add_appointment(Request::new(common_msgs::AddAppointmentRequest {
                appointment: Some(appointment.clone().into()),
                signature,
            }))
            .await
            .unwrap()
            .into_inner();

        assert!(matches!(
            response,
            common_msgs::AddAppointmentResponse { .. }
        ));
    }

    #[tokio::test]
    async fn test_add_appointment_non_registered() {
        let (internal_api, _s) = create_api().await;

        // User is not registered this time
        let (user_sk, _) = get_random_keypair();

        let appointment = generate_dummy_appointment(None).inner;
        let signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();

        match internal_api
            .add_appointment(Request::new(common_msgs::AddAppointmentRequest {
                appointment: Some(appointment.clone().into()),
                signature,
            }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::Unauthenticated);
                assert_eq!(
                    status.message(),
                    "Invalid signature or user does not have enough slots available"
                )
            }
            _ => panic!("Test should have returned Err"),
        }
    }

    #[tokio::test]
    async fn test_add_appointment_not_enough_slots() {
        let (internal_api, _s) = create_api_with_config(ApiConfig::new(0, DURATION)).await;

        // User is registered but has no slots
        let (user_sk, user_pk) = get_random_keypair();
        internal_api.watcher.register(UserId(user_pk)).unwrap();

        let appointment = generate_dummy_appointment(None).inner;
        let signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();

        match internal_api
            .add_appointment(Request::new(common_msgs::AddAppointmentRequest {
                appointment: Some(appointment.clone().into()),
                signature,
            }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::Unauthenticated);
                assert_eq!(
                    status.message(),
                    "Invalid signature or user does not have enough slots available"
                )
            }
            _ => panic!("Test should have returned Err"),
        }
    }

    #[tokio::test]
    async fn test_add_appointment_subscription_expired() {
        let (internal_api, _s) = create_api_with_config(ApiConfig::new(SLOTS, 0)).await;

        // User is registered but subscription is expired
        let (user_sk, user_pk) = get_random_keypair();
        internal_api.watcher.register(UserId(user_pk)).unwrap();

        let appointment = generate_dummy_appointment(None).inner;
        let signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();

        match internal_api
            .add_appointment(Request::new(common_msgs::AddAppointmentRequest {
                appointment: Some(appointment.clone().into()),
                signature,
            }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::Unauthenticated);
                assert!(status.message().starts_with("Your subscription expired at"),)
            }
            _ => panic!("Test should have returned Err"),
        }
    }

    #[tokio::test]
    async fn test_add_appointment_already_triggered() {
        let (internal_api, _s) = create_api().await;

        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        internal_api.watcher.register(user_id).unwrap();

        // Add a tracker to the responder to simulate it being triggered.
        let dispute_tx = get_random_tx();
        let tracker = TransactionTracker::new(
            Breach::new(dispute_tx.clone(), get_random_tx()),
            user_id,
            ConfirmationStatus::ConfirmedIn(100),
        );
        internal_api
            .get_watcher()
            .add_dummy_tracker_to_responder(&tracker);

        // Try to add it again using the API.
        let appointment = generate_dummy_appointment(Some(&dispute_tx.compute_txid())).inner;
        let signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();
        match internal_api
            .add_appointment(Request::new(common_msgs::AddAppointmentRequest {
                appointment: Some(appointment.into()),
                signature,
            }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::AlreadyExists);
                assert!(status
                    .message()
                    .starts_with("The provided appointment has already been triggered"),)
            }
            _ => panic!("Test should have returned Err"),
        }
    }

    #[tokio::test]
    async fn test_add_appointment_service_unavailable() {
        let (internal_api, _s) =
            create_api_with_config(ApiConfig::new(u32::MAX, DURATION).bitcoind_unreachable()).await;

        let (user_sk, _) = get_random_keypair();
        let appointment = generate_dummy_appointment(None).inner;
        let signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();

        match internal_api
            .add_appointment(Request::new(common_msgs::AddAppointmentRequest {
                appointment: Some(appointment.clone().into()),
                signature,
            }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::Unavailable);
                assert_eq!(status.message(), "Service currently unavailable")
            }
            _ => panic!("Test should have returned Err"),
        }
    }

    #[tokio::test]
    async fn test_get_appointment() {
        let (internal_api, _s) = create_api().await;

        // The user must be registered
        let (user_sk, user_pk) = get_random_keypair();
        internal_api.watcher.register(UserId(user_pk)).unwrap();

        // Add the appointment
        let appointment = generate_dummy_appointment(None).inner;
        let user_signature = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();
        internal_api
            .watcher
            .add_appointment(appointment.clone(), user_signature)
            .unwrap();

        // Get the appointment through the API
        let message = format!("get appointment {}", appointment.locator);
        let response = internal_api
            .get_appointment(Request::new(common_msgs::GetAppointmentRequest {
                locator: appointment.locator.to_vec(),
                signature: cryptography::sign(message.as_bytes(), &user_sk).unwrap(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert!(matches!(
            response,
            common_msgs::GetAppointmentResponse { .. }
        ));
    }

    #[tokio::test]
    async fn test_get_appointment_non_registered() {
        let (internal_api, _s) = create_api().await;

        // Add a first user to link the appointment to him
        let (user_sk, user_pk) = get_random_keypair();
        internal_api.watcher.register(UserId(user_pk)).unwrap();

        // There's no need to add the appointment given the subscription status is checked first
        let appointment = generate_dummy_appointment(None).inner;

        // Try to get the appointment through the API
        let message = format!("get appointment {}", appointment.locator);
        match internal_api
            .get_appointment(Request::new(common_msgs::GetAppointmentRequest {
                locator: appointment.locator.to_vec(),
                signature: cryptography::sign(message.as_bytes(), &user_sk).unwrap(),
            }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::NotFound);
                assert_eq!(status.message(), "Appointment not found");
            }
            _ => panic!("Test should have returned Err"),
        }
    }

    #[tokio::test]
    async fn test_get_appointment_non_existent() {
        let (internal_api, _s) = create_api().await;

        // The user is registered but the appointment does not exist
        let (user_sk, user_pk) = get_random_keypair();
        internal_api.watcher.register(UserId(user_pk)).unwrap();

        // Try to get the appointment through the API
        let appointment = generate_dummy_appointment(None).inner;
        let message = format!("get appointment {}", appointment.locator);

        match internal_api
            .get_appointment(Request::new(common_msgs::GetAppointmentRequest {
                locator: appointment.locator.to_vec(),
                signature: cryptography::sign(message.as_bytes(), &user_sk).unwrap(),
            }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::NotFound);
                assert_eq!(status.message(), "Appointment not found");
            }
            _ => panic!("Test should have returned Err"),
        }
    }

    #[tokio::test]
    async fn test_get_appointment_subscription_expired() {
        let (internal_api, _s) = create_api_with_config(ApiConfig::new(SLOTS, 0)).await;

        // Register the user
        let (user_sk, user_pk) = get_random_keypair();
        internal_api.watcher.register(UserId(user_pk)).unwrap();

        // There s no need to add the appointment given the subscription status is checked first.
        let appointment = generate_dummy_appointment(None).inner;

        // Try to get the appointment through the API
        let message = format!("get appointment {}", appointment.locator);
        match internal_api
            .get_appointment(Request::new(common_msgs::GetAppointmentRequest {
                locator: appointment.locator.to_vec(),
                signature: cryptography::sign(message.as_bytes(), &user_sk).unwrap(),
            }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::Unauthenticated);
                assert!(status.message().starts_with("Your subscription expired at"));
            }
            _ => panic!("Test should have returned Err"),
        }
    }

    #[tokio::test]
    async fn test_get_appointment_service_unavailable() {
        let (internal_api, _s) =
            create_api_with_config(ApiConfig::new(SLOTS, DURATION).bitcoind_unreachable()).await;

        let (user_sk, _) = get_random_keypair();
        let appointment = generate_dummy_appointment(None).inner;
        let message = format!("get appointment {}", appointment.locator);
        match internal_api
            .get_appointment(Request::new(common_msgs::GetAppointmentRequest {
                locator: appointment.locator.to_vec(),
                signature: cryptography::sign(message.as_bytes(), &user_sk).unwrap(),
            }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::Unavailable);
                assert_eq!(status.message(), "Service currently unavailable");
            }
            _ => panic!("Test should have returned Err"),
        }
    }

    #[tokio::test]
    async fn test_get_subscription_info() {
        let (internal_api, _s) = create_api().await;

        // The user must be registered
        let (user_sk, user_pk) = get_random_keypair();
        internal_api.watcher.register(UserId(user_pk)).unwrap();

        // Get the subscription info though the API
        let message = "get subscription info".to_string();
        let response = internal_api
            .get_subscription_info(Request::new(common_msgs::GetSubscriptionInfoRequest {
                signature: cryptography::sign(message.as_bytes(), &user_sk).unwrap(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert!(matches!(
            response,
            common_msgs::GetSubscriptionInfoResponse { .. }
        ));
    }

    #[tokio::test]
    async fn test_get_subscription_info_non_registered() {
        let (internal_api, _s) = create_api_with_config(ApiConfig::new(SLOTS, 0)).await;

        // The user is not registered
        let (user_sk, _) = get_random_keypair();

        // Try to get the subscription info though the API
        let message = "get subscription info".to_string();
        match internal_api
            .get_subscription_info(Request::new(common_msgs::GetSubscriptionInfoRequest {
                signature: cryptography::sign(message.as_bytes(), &user_sk).unwrap(),
            }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::Unauthenticated);
                assert_eq!(status.message(), "User not found. Have you registered?");
            }
            _ => panic!("Test should have returned Err"),
        }
    }

    #[tokio::test]
    async fn test_get_subscription_info_expired() {
        let (internal_api, _s) = create_api_with_config(ApiConfig::new(SLOTS, 0)).await;

        // The user is registered but the subscription has expired
        let (user_sk, user_pk) = get_random_keypair();
        internal_api.watcher.register(UserId(user_pk)).unwrap();

        // Try to get the subscription info though the API
        let message = "get subscription info".to_string();
        match internal_api
            .get_subscription_info(Request::new(common_msgs::GetSubscriptionInfoRequest {
                signature: cryptography::sign(message.as_bytes(), &user_sk).unwrap(),
            }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::Unauthenticated);
                assert!(status.message().starts_with("Your subscription expired at"));
            }
            _ => panic!("Test should have returned Err"),
        }
    }

    #[tokio::test]
    async fn test_get_subscription_info_service_unavailable() {
        let (internal_api, _s) =
            create_api_with_config(ApiConfig::new(SLOTS, DURATION).bitcoind_unreachable()).await;

        let (user_sk, _) = get_random_keypair();
        let message = "get subscription info".to_string();
        match internal_api
            .get_subscription_info(Request::new(common_msgs::GetSubscriptionInfoRequest {
                signature: cryptography::sign(message.as_bytes(), &user_sk).unwrap(),
            }))
            .await
        {
            Err(status) => {
                assert_eq!(status.code(), Code::Unavailable);
                assert_eq!(status.message(), "Service currently unavailable");
            }
            _ => panic!("Test should have returned Err"),
        }
    }
}
