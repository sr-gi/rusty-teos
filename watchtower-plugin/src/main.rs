use std::convert::TryFrom;
use std::env;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use home::home_dir;
use serde_json::json;
use tokio::io::{stdin, stdout};
use tokio::sync::mpsc::unbounded_channel;

use cln_plugin::options::config_type::DefaultInteger;
use cln_plugin::options::ConfigOption;
use cln_plugin::{anyhow, Builder, Error, Plugin};

use teos_common::appointment::{Appointment, Locator};
use teos_common::net::http::Endpoint;
use teos_common::net::NetAddr;
use teos_common::protos as common_msgs;
use teos_common::TowerId;
use teos_common::{cryptography, errors};

use watchtower_plugin::convert::{CommitmentRevocation, GetAppointmentParams, RegisterParams};
use watchtower_plugin::net::http::{
    self, get_request, post_request, process_post_response, AddAppointmentError, ApiResponse,
    RequestError,
};
use watchtower_plugin::net::ProxyInfo;
use watchtower_plugin::retrier::RetryManager;
use watchtower_plugin::wt_client::{RevocationData, WTClient};
use watchtower_plugin::{constants, TowerStatus};

const DEV_WT_MAX_RETRY_INTERVAL_CONFIG: ConfigOption<DefaultInteger> =
    ConfigOption::new_i64_with_default(
        constants::DEV_WT_MAX_RETRY_INTERVAL,
        constants::DEFAULT_DEV_WT_MAX_RETRY_INTERVAL,
        constants::DEV_WT_MAX_RETRY_INTERVAL_DESC,
    );

const WT_AUTO_RETRY_DELAY_CONFIG: ConfigOption<DefaultInteger> = ConfigOption::new_i64_with_default(
    constants::WT_AUTO_RETRY_DELAY,
    constants::DEFAULT_WT_AUTO_RETRY_DELAY,
    constants::WT_AUTO_RETRY_DELAY_DESC,
);

const WT_MAX_RETRY_TIME_CONFIG: ConfigOption<DefaultInteger> = ConfigOption::new_i64_with_default(
    constants::WT_MAX_RETRY_TIME,
    constants::DEFAULT_WT_MAX_RETRY_TIME,
    constants::WT_MAX_RETRY_TIME_DESC,
);

const WT_PORT_CONFG: ConfigOption<DefaultInteger> = ConfigOption::new_i64_with_default(
    constants::WT_PORT,
    constants::DEFAULT_WT_PORT,
    constants::WT_PORT_DESC,
);

fn to_cln_error(e: RequestError) -> Error {
    let e = match e {
        RequestError::ConnectionError(e) => anyhow!(e),
        RequestError::DeserializeError(e) => anyhow!(e),
        RequestError::Unexpected(e) => anyhow!(e),
    };
    log::info!("{e}");
    e
}

/// Sends fresh data to a retrier as long as is does not exist, or it does and its running.
fn send_to_retrier(state: &MutexGuard<WTClient>, tower_id: TowerId, locator: Locator) {
    if if let Some(status) = state.get_retrier_status(&tower_id) {
        // A retrier in the retriers map can only be running or idle
        status.is_running()
    } else {
        true
    } {
        state
            .unreachable_towers
            .send((tower_id, RevocationData::Fresh(locator)))
            .unwrap();
    } else {
        log::debug!("Not sending data to idle retrier ({tower_id}, {locator})")
    }
}

/// Registers the client to a given tower.
///
/// Accepted tower_id formats:
///     - tower_id@host:port
///     - tower_id host port
///     - tower_id@host (will default port to DEFAULT_PORT)
///     - tower_id host (will default port to DEFAULT_PORT)
async fn register(
    plugin: Plugin<Arc<Mutex<WTClient>>>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let params = RegisterParams::try_from(v).map_err(|x| anyhow!(x))?;
    let mut host = params.host.unwrap_or_else(|| "localhost".to_owned());
    let tower_id = params.tower_id;
    let user_id = plugin.state().lock().unwrap().user_id;

    // TODO: The user should pick the start_time or, at least, check the returned start time against it's known block height.
    // Otherwise the tower could just generate a subscription starting far in the future. For this we need to access lightning RPC
    // which is not available in the current version of `cln-plugin` (but already on master). Add it for the next release.

    let port = params.port.unwrap_or(
        u16::try_from(plugin.option(&WT_PORT_CONFG).unwrap())
            .map_err(|_| anyhow!("{} out of range", constants::WT_PORT))?,
    );

    let tower_net_addr = {
        if !host.starts_with("http://") {
            host = format!("http://{host}")
        }
        NetAddr::new(format!("{host}:{port}"))
    };

    let proxy = plugin.state().lock().unwrap().proxy.clone();

    let receipt = http::register(tower_id, user_id, &tower_net_addr, &proxy)
        .await
        .map_err(|e| {
            let mut state = plugin.state().lock().unwrap();
            if e.is_connection() && state.towers.contains_key(&tower_id) {
                state.set_tower_status(tower_id, TowerStatus::TemporaryUnreachable);
            }
            to_cln_error(e)
        })?;

    if !receipt.verify(&tower_id) {
        return Err(anyhow!(
            "Registration receipt contains bad signature. Are you using the right tower_id?"
        ));
    }

    plugin
        .state()
        .lock()
        .unwrap()
        .add_update_tower(tower_id, tower_net_addr.net_addr(), &receipt).map_err(|e| {
            if e.is_expiry() {
                anyhow!("Registration receipt contains a subscription expiry that is not higher than the one we are currently registered for")
            } else {
                anyhow!("Registration receipt does not contain more slots than the ones we are currently registered for")
            }
        })?;

    log::info!(
        "Registration succeeded. Available slots: {}. Subscription period (block height range): ({}-{})",
        receipt.available_slots(),
        receipt.subscription_start(),
        receipt.subscription_expiry()
    );

    Ok(json!(receipt))
}

/// Gets the latest registration receipt from the client to a given tower (if it exists).
///
/// This is pulled from the database
async fn get_registration_receipt(
    plugin: Plugin<Arc<Mutex<WTClient>>>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let tower_id = TowerId::try_from(v).map_err(|x| anyhow!(x))?;
    let state = plugin.state().lock().unwrap();

    if let Some(response) = state.get_registration_receipt(tower_id) {
        Ok(json!(response))
    } else {
        Err(anyhow!(
            "Cannot find {tower_id} within the known towers. Have you registered?"
        ))
    }
}

/// Gets the subscription information directly form the tower.
async fn get_subscription_info(
    plugin: Plugin<Arc<Mutex<WTClient>>>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let tower_id = TowerId::try_from(v).map_err(|x| anyhow!(x))?;

    let (user_sk, tower_net_addr, proxy) = {
        let state = plugin.state().lock().unwrap();
        if let Some(info) = state.towers.get(&tower_id) {
            Ok((state.user_sk, info.net_addr.clone(), state.proxy.clone()))
        } else {
            Err(anyhow!("Unknown tower id: {tower_id}"))
        }
    }?;

    let signature = cryptography::sign("get subscription info".as_bytes(), &user_sk).unwrap();

    let response: common_msgs::GetSubscriptionInfoResponse = process_post_response(
        post_request(
            &tower_net_addr,
            Endpoint::GetSubscriptionInfo,
            &common_msgs::GetSubscriptionInfoRequest { signature },
            &proxy,
        )
        .await,
    )
    .await
    .map_err(|e| {
        if e.is_connection() {
            plugin
                .state()
                .lock()
                .unwrap()
                .set_tower_status(tower_id, TowerStatus::TemporaryUnreachable);
        }
        to_cln_error(e)
    })?;

    Ok(json!(response))
}

/// Gets information about an appointment from the tower.
async fn get_appointment(
    plugin: Plugin<Arc<Mutex<WTClient>>>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let params = GetAppointmentParams::try_from(v).map_err(|x| anyhow!(x))?;

    let (user_sk, tower_net_addr, proxy) = {
        let state = plugin.state().lock().unwrap();
        if let Some(info) = state.towers.get(&params.tower_id) {
            Ok((state.user_sk, info.net_addr.clone(), state.proxy.clone()))
        } else {
            Err(anyhow!("Unknown tower id: {}", params.tower_id))
        }
    }?;

    let signature = cryptography::sign(
        format!("get appointment {}", params.locator).as_bytes(),
        &user_sk,
    )
    .unwrap();

    let response: ApiResponse<common_msgs::GetAppointmentResponse> = process_post_response(
        post_request(
            &tower_net_addr,
            Endpoint::GetAppointment,
            &common_msgs::GetAppointmentRequest {
                locator: params.locator.to_vec(),
                signature,
            },
            &proxy,
        )
        .await,
    )
    .await
    .map_err(|e| {
        if e.is_connection() {
            plugin
                .state()
                .lock()
                .unwrap()
                .set_tower_status(params.tower_id, TowerStatus::TemporaryUnreachable);
        }
        to_cln_error(e)
    })?;

    Ok(json!(response))
}

/// Gets an appointment receipt from the client given a tower_id and a locator (if it exists).
///
/// This is pulled from the database
async fn get_appointment_receipt(
    plugin: Plugin<Arc<Mutex<WTClient>>>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let params = GetAppointmentParams::try_from(v).map_err(|x| anyhow!(x))?;
    let state = plugin.state().lock().unwrap();

    if let Some(r) = state.get_appointment_receipt(params.tower_id, params.locator) {
        Ok(json!(r))
    } else if state.towers.contains_key(&params.tower_id) {
        Err(anyhow!(
            "Cannot find {} within {}. Did you send that appointment?",
            params.locator,
            params.tower_id
        ))
    } else {
        Err(anyhow!(
            "Cannot find {} within the known towers. Have you registered?",
            params.tower_id
        ))
    }
}

/// Lists all the registered towers.
///
/// The given information comes from memory, so it is summarized.
async fn list_towers(
    plugin: Plugin<Arc<Mutex<WTClient>>>,
    _: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    Ok(json!(plugin.state().lock().unwrap().towers))
}

/// Gets information about a given tower.
///
/// Data comes from disk (DB), so all stored data is provided.
async fn get_tower_info(
    plugin: Plugin<Arc<Mutex<WTClient>>>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let state = plugin.state().lock().unwrap();
    let tower_id = TowerId::try_from(v).map_err(|e| anyhow!(e))?;

    if let Some(tower_info) = state.load_tower_info(tower_id) {
        // Notice we need to check the status in memory since we cannot distinguish between unreachable and temporary unreachable
        // by just checking the data in the database.
        Ok(json!(
            tower_info.with_status(state.get_tower_status(&tower_id).unwrap())
        ))
    } else {
        Err(anyhow!(
            "Cannot find {tower_id} within the known towers. Have you registered?",
        ))
    }
}

async fn ping(
    plugin: Plugin<Arc<Mutex<WTClient>>>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let (tower_net_addr, proxy) = {
        // Check if the tower_id is known to the plugin
        let tower_id = TowerId::try_from(v).map_err(|e| anyhow!(e))?;
        let state = plugin.state().lock().unwrap();
        (
            state
                .towers
                .get(&tower_id)
                .ok_or(anyhow!("Unknown tower_id"))?
                .net_addr
                .clone(),
            state.proxy.clone(),
        )
    };
    let response = get_request(&tower_net_addr, Endpoint::Ping, &proxy)
        .await
        .map_err(to_cln_error)?;

    if response.status().is_success() {
        Ok(json!("Tower is reachable"))
    } else {
        Err(anyhow!(format!(
            "Tower cannot be reached (Error: {})",
            response.status()
        )))
    }
}

/// Triggers a manual retry of a tower, tries to send all pending appointments to it.
///
/// Only works if the tower is unreachable or there's been a subscription error (and the tower is not already being retried).
async fn retry_tower(
    plugin: Plugin<Arc<Mutex<WTClient>>>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let tower_id = TowerId::try_from(v).map_err(|e| anyhow!(e))?;
    let state = plugin.state().lock().unwrap();
    if let Some(tower_status) = state.get_tower_status(&tower_id) {
        if let Some(retrier_status) = state.retriers.get(&tower_id) {
            if retrier_status.is_idle() {
                // We don't send any associated data in this case given the idle retrier already has it all.
                state
                    .unreachable_towers
                    .send((tower_id, RevocationData::None))
                    .map_err(|e| anyhow!(e))?;
            } else {
                // Status can only be running or idle for data in the retriers map.
                return Err(anyhow!("{tower_id} is already being retried"));
            }
        } else if tower_status.is_retryable() {
            // We do send associated data here given there is no retrier associated to this tower.
            state
                .unreachable_towers
                .send((
                    tower_id,
                    RevocationData::Stale(
                        state
                            .towers
                            .get(&tower_id)
                            .unwrap()
                            .pending_appointments
                            .iter()
                            .cloned()
                            .collect(),
                    ),
                ))
                .map_err(|e| anyhow!(e))?;
        } else {
            return Err(anyhow!(
                "Tower status must be unreachable or have a subscription issue to manually retry",
            ));
        }
    } else {
        return Err(anyhow!("Unknown tower {tower_id}"));
    }
    Ok(json!(format!("Retrying {tower_id}")))
}

/// Forgets about a tower wiping out all local data associated to it.
async fn abandon_tower(
    plugin: Plugin<Arc<Mutex<WTClient>>>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let tower_id = TowerId::try_from(v).map_err(|e| anyhow!(e))?;
    let mut state = plugin.state().lock().unwrap();
    if state.towers.contains_key(&tower_id) {
        state.remove_tower(tower_id).unwrap();
        Ok(json!(format!("{tower_id} successfully abandoned")))
    } else {
        Err(anyhow!("Unknown tower {tower_id}"))
    }
}

/// Sends an appointment to all registered towers for every new commitment transaction.
///
/// The appointment is built using the data provided by the backend (dispute txid and penalty transaction).
async fn on_commitment_revocation(
    plugin: Plugin<Arc<Mutex<WTClient>>>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let commitment_revocation = serde_json::from_value::<CommitmentRevocation>(v)
        .map_err(|e| anyhow!("Cannot decode commitment_revocation data. Error: {e}"))?;
    log::debug!(
        "New commitment revocation received for channel {}. Commit number {}",
        commitment_revocation.channel_id,
        commitment_revocation.commit_num
    );

    // TODO: For now, to_self_delay is hardcoded to 42. Revisit and define it better / remove it when / if needed
    let locator = Locator::new(commitment_revocation.commitment_txid);
    let appointment = Appointment::new(
        locator,
        cryptography::encrypt(
            &commitment_revocation.penalty_tx,
            &commitment_revocation.commitment_txid,
        )
        .unwrap(),
        42,
    );
    let signature = cryptography::sign(
        &appointment.to_vec(),
        &plugin.state().lock().unwrap().user_sk,
    )
    .unwrap();

    // Looks like we cannot iterate through towers given a locked state is not Send (due to the async call),
    // so we need to clone the bare minimum.
    let towers = plugin
        .state()
        .lock()
        .unwrap()
        .towers
        .iter()
        .map(|(id, info)| (*id, info.net_addr.clone(), info.status))
        .collect::<Vec<_>>();

    let proxy = plugin.state().lock().unwrap().proxy.clone();

    for (tower_id, net_addr, status) in towers {
        if status.is_reachable() {
            match http::add_appointment(tower_id, &net_addr, &proxy, &appointment, &signature).await
            {
                Ok((slots, receipt)) => {
                    plugin
                        .state()
                        .lock()
                        .unwrap()
                        .add_appointment_receipt(tower_id, locator, slots, &receipt);
                    log::debug!("Response verified and data stored in the database");
                }
                Err(e) => match e {
                    AddAppointmentError::RequestError(e) => {
                        if e.is_connection() {
                            log::warn!(
                                "{tower_id} cannot be reached. Adding {} to pending appointments",
                                appointment.locator
                            );
                            let mut state = plugin.state().lock().unwrap();
                            state.set_tower_status(tower_id, TowerStatus::TemporaryUnreachable);
                            state.add_pending_appointment(tower_id, &appointment);
                            send_to_retrier(&state, tower_id, appointment.locator);
                        }
                    }
                    AddAppointmentError::ApiError(e) => match e.error_code {
                        errors::INVALID_SIGNATURE_OR_SUBSCRIPTION_ERROR => {
                            log::warn!(
                                "There is a subscription issue with {tower_id}. Adding {} to pending",
                                appointment.locator
                            );
                            let mut state = plugin.state().lock().unwrap();
                            state.set_tower_status(tower_id, TowerStatus::SubscriptionError);
                            state.add_pending_appointment(tower_id, &appointment);
                            send_to_retrier(&state, tower_id, appointment.locator);
                        }

                        _ => {
                            log::warn!(
                                "{tower_id} rejected the appointment. Error: {}, error_code: {}",
                                e.error,
                                e.error_code
                            );
                            plugin
                                .state()
                                .lock()
                                .unwrap()
                                .add_invalid_appointment(tower_id, &appointment);
                        }
                    },
                    AddAppointmentError::SignatureError(proof) => {
                        log::warn!("Cannot recover known tower_id from the appointment receipt. Flagging tower as misbehaving");
                        plugin
                            .state()
                            .lock()
                            .unwrap()
                            .flag_misbehaving_tower(tower_id, proof)
                    }
                },
            };
        } else if status.is_misbehaving() {
            log::warn!("{tower_id} is misbehaving. Not sending any further appointments",);
        } else {
            if status.is_subscription_error() {
                log::warn!(
                    "There is a subscription issue with {tower_id}. Adding {} to pending",
                    appointment.locator
                );
            } else {
                log::warn!(
                    "{tower_id} is {status}. Adding {} to pending",
                    appointment.locator,
                );
            }

            let mut state = plugin.state().lock().unwrap();
            state.add_pending_appointment(tower_id, &appointment);

            if !status.is_unreachable() {
                send_to_retrier(&state, tower_id, appointment.locator);
            }
        }
    }

    // FIXME: Ask cdecker: Do hooks need to return something?
    Ok(json!(r#" {"result": continue}"#))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let data_dir = match env::var(constants::TOWERS_DATA_DIR) {
        Ok(v) => PathBuf::from(v),
        Err(_) => home_dir().unwrap().join(constants::DEFAULT_TOWERS_DATA_DIR),
    };

    let builder = Builder::new(stdin(), stdout())
        .option(WT_PORT_CONFG)
        .option(WT_MAX_RETRY_TIME_CONFIG)
        .option(WT_AUTO_RETRY_DELAY_CONFIG)
        .option(DEV_WT_MAX_RETRY_INTERVAL_CONFIG)
        .rpcmethod(
            constants::RPC_REGISTER_TOWER,
            constants::RPC_REGISTER_TOWER_DESC,
            register,
        )
        .rpcmethod(
            constants::RPC_GET_REGISTRATION_RECEIPT,
            constants::RPC_GET_REGISTRATION_RECEIPT_DESC,
            get_registration_receipt,
        )
        .rpcmethod(
            constants::RPC_GET_APPOINTMENT,
            constants::RPC_GET_APPOINTMENT_DESC,
            get_appointment,
        )
        .rpcmethod(
            constants::RPC_GET_APPOINTMENT_RECEIPT,
            constants::RPC_GET_APPOINTMENT_RECEIPT_DESC,
            get_appointment_receipt,
        )
        .rpcmethod(
            constants::RPC_GET_SUBSCRIPTION_INFO,
            constants::RPC_GET_SUBSCRIPTION_INFO_DESC,
            get_subscription_info,
        )
        .rpcmethod(
            constants::RPC_LIST_TOWERS,
            constants::RPC_LIST_TOWERS_DESC,
            list_towers,
        )
        .rpcmethod(
            constants::RPC_GET_TOWER_INFO,
            constants::RPC_GET_TOWER_INFO_DESC,
            get_tower_info,
        )
        .rpcmethod(constants::RPC_PING, constants::RPC_PING_DESC, ping)
        .rpcmethod(
            constants::RPC_RETRY_TOWER,
            constants::RPC_RETRY_TOWER_DESC,
            retry_tower,
        )
        .rpcmethod(
            constants::RPC_ABANDON_TOWER,
            constants::RPC_ABANDON_TOWER_DESC,
            abandon_tower,
        )
        .hook(
            constants::HOOK_COMMITMENT_REVOCATION,
            on_commitment_revocation,
        );

    // We're unwrapping here given it does not seem we actually have anything to check at the moment.
    // Change this so the plugin can be disabled soon if this happens not to be the case.
    let midstate = if let Some(midstate) = builder.configure().await? {
        midstate
    } else {
        return Ok(());
    };

    let (tx, rx) = unbounded_channel();
    let wt_client = Arc::new(Mutex::new(
        WTClient::with_proxy(
            data_dir,
            tx,
            midstate.configuration().proxy.map(|proxy| {
                // We don't need to inform `always-use-proxy` needing `proxy` to work. This is done by CLN already when needed.
                ProxyInfo::new(
                    proxy,
                    midstate.configuration().always_use_proxy.unwrap_or(false),
                )
            }),
        )
        .await,
    ));

    let max_elapsed_time = u16::try_from(midstate.option(&WT_MAX_RETRY_TIME_CONFIG).unwrap())
        .inspect_err(|_| {
            log::error!("{} out of range", constants::WT_MAX_RETRY_TIME);
        })?;

    let auto_retry_delay = u32::try_from(midstate.option(&WT_AUTO_RETRY_DELAY_CONFIG).unwrap())
        .inspect_err(|_| {
            log::error!("{} out of range", constants::WT_AUTO_RETRY_DELAY);
        })?;

    let max_interval_time = u16::try_from(
        midstate.option(&DEV_WT_MAX_RETRY_INTERVAL_CONFIG).unwrap(),
    )
    .inspect_err(|_| {
        log::error!("{} out of range", constants::DEV_WT_MAX_RETRY_INTERVAL);
    })?;

    let plugin = midstate.start(wt_client.clone()).await?;
    tokio::spawn(async move {
        RetryManager::new(
            wt_client,
            rx,
            max_elapsed_time,
            auto_retry_delay,
            max_interval_time,
        )
        .manage_retry()
        .await
    });
    plugin.join().await
}
