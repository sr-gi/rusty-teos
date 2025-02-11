use log::LevelFilter;
use simple_logger::SimpleLogger;
use std::fs;
use std::io::ErrorKind;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Condvar, Mutex};
use structopt::StructOpt;
use tokio::task;
use tonic::transport::{Certificate, Server, ServerTlsConfig};

use bitcoin::network::Network;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use lightning_block_sync::init::validate_best_block_header;
use lightning_block_sync::poll::{
    ChainPoller, Poll, Validate, ValidatedBlock, ValidatedBlockHeader,
};
use lightning_block_sync::{BlockSource, BlockSourceError, SpvClient, UnboundedCache};

use teos::api::internal::InternalAPI;
use teos::api::{http, tor::TorAPI};
use teos::bitcoin_cli::BitcoindClient;
use teos::carrier::Carrier;
use teos::chain_monitor::ChainMonitor;
use teos::config::{self, AuthMethod, Config, Opt};
use teos::dbm::DBM;
use teos::gatekeeper::Gatekeeper;
use teos::protos as msgs;
use teos::protos::private_tower_services_server::PrivateTowerServicesServer;
use teos::protos::public_tower_services_server::PublicTowerServicesServer;
use teos::responder::Responder;
use teos::tls::tls_init;
use teos::watcher::Watcher;

use teos_common::constants::IRREVOCABLY_RESOLVED;
use teos_common::cryptography::get_random_keypair;
use teos_common::TowerId;

async fn get_last_n_blocks<B, T>(
    poller: &mut ChainPoller<B, T>,
    mut last_known_block: ValidatedBlockHeader,
    n: usize,
) -> Result<Vec<ValidatedBlock>, BlockSourceError>
where
    B: DerefMut<Target = T> + Sized + Send + Sync,
    T: BlockSource,
{
    let mut last_n_blocks = Vec::with_capacity(n);
    for _ in 0..n {
        log::debug!("Fetching block #{}", last_known_block.height);
        let block = poller.fetch_block(&last_known_block).await?;
        last_known_block = poller.look_up_previous_header(&last_known_block).await?;
        last_n_blocks.push(block);
    }

    Ok(last_n_blocks)
}

fn create_new_tower_keypair(db: &DBM) -> (SecretKey, PublicKey) {
    let (sk, pk) = get_random_keypair();
    db.store_tower_key(&sk).unwrap();
    (sk, pk)
}

#[tokio::main]
async fn main() {
    let opt = Opt::from_args();
    let path = config::data_dir_absolute_path(opt.data_dir.clone());
    let conf_file_path = path.join("teos.toml");
    // Create data dir if it does not exist
    fs::create_dir_all(&path).unwrap_or_else(|e| {
        eprintln!("Cannot create data dir: {e:?}");
        std::process::exit(1);
    });

    // Load conf (from file or defaults) and patch it with the command line parameters received (if any)
    let mut conf = config::from_file::<Config>(&conf_file_path);
    let is_default = conf.is_default();
    conf.patch_with_options(opt);
    conf.verify().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });

    // Set log level
    SimpleLogger::new()
        .with_level(if conf.deps_debug {
            LevelFilter::Debug
        } else {
            LevelFilter::Warn
        })
        .with_module_level(
            "teos",
            if conf.debug {
                LevelFilter::Debug
            } else {
                LevelFilter::Info
            },
        )
        .init()
        .unwrap();

    // Create network dir
    let path_network = path.join(conf.btc_network.clone());
    fs::create_dir_all(&path_network).unwrap_or_else(|e| {
        eprintln!("Cannot create network dir: {e:?}");
        std::process::exit(1);
    });

    // Log default data dir
    log::info!("Default data directory: {:?}", &path);

    // Log datadir path
    log::info!("Using data directory: {:?}", &path_network);

    // Log config file path based on whether the config file is found or not
    if is_default {
        log::info!("Config file: {:?} (not found, skipping)", &conf_file_path);
    } else {
        log::info!("Config file: {:?}", &conf_file_path);
        conf.log_non_default_options();
    }

    let dbm = Arc::new(Mutex::new(
        DBM::new(path_network.join("teos_db.sql3")).unwrap(),
    ));

    // Load tower secret key or create a fresh one if none is found. If overwrite key is set, create a new
    // key straightaway
    let (tower_sk, tower_pk) = {
        let locked_db = dbm.lock().unwrap();
        if conf.overwrite_key {
            log::info!("Overwriting tower keys");
            create_new_tower_keypair(&locked_db)
        } else if let Some(sk) = locked_db.load_tower_key() {
            (sk, PublicKey::from_secret_key(&Secp256k1::new(), &sk))
        } else {
            log::info!("Tower keys not found. Creating a fresh set");
            create_new_tower_keypair(&locked_db)
        }
    };
    log::info!("tower_id: {tower_pk}");

    let btc_rpc_auth = match conf.get_auth_method() {
        AuthMethod::CookieFile => {
            Auth::CookieFile(config::data_dir_absolute_path(conf.btc_rpc_cookie))
        }
        AuthMethod::UserPass => Auth::UserPass(conf.btc_rpc_user, conf.btc_rpc_password),
        // Notice an invalid conf would have failed on `Config::verify()`
        _ => unreachable!("A verified conf will only have one of these two auth methods"),
    };

    // Initialize our bitcoind client
    let (bitcoin_cli, bitcoind_reachable) = match BitcoindClient::new(
        &conf.btc_rpc_connect,
        conf.btc_rpc_port,
        btc_rpc_auth.clone(),
        &conf.btc_network,
    )
    .await
    {
        Ok(client) => (
            Arc::new(client),
            Arc::new((Mutex::new(true), Condvar::new())),
        ),
        Err(e) => {
            let e_msg = match e.kind() {
                ErrorKind::InvalidData => "invalid btcrpcuser or btcrpcpassword".into(),
                _ => e.to_string(),
            };
            log::error!("Failed to connect to bitcoind. Error: {e_msg}");
            std::process::exit(1);
        }
    };

    // FIXME: Temporary. We're using bitcoin_core_rpc and rust-lightning's rpc until they both get merged
    // https://github.com/rust-bitcoin/rust-bitcoincore-rpc/issues/166
    let schema = if !conf.btc_rpc_connect.starts_with("http") {
        "http://"
    } else {
        ""
    };
    let rpc = Arc::new(
        Client::new(
            &format!("{schema}{}:{}", conf.btc_rpc_connect, conf.btc_rpc_port),
            btc_rpc_auth,
        )
        .unwrap(),
    );
    let mut derefed = bitcoin_cli.deref();
    // Load last known block from DB if found. Poll it from Bitcoind otherwise.
    let last_known_block = dbm.lock().unwrap().load_last_known_block();
    let tip = if let Some(block_hash) = last_known_block {
        let mut last_known_header = derefed
            .get_header(&block_hash, None)
            .await
            .unwrap()
            .validate(block_hash)
            .unwrap();

        log::info!(
            "Last known block: {} (height: {})",
            last_known_header.header.block_hash(),
            last_known_header.height
        );

        // If we are running in pruned mode some data may be missing (if we happen to have been offline for a while)
        if let Some(prune_height) = rpc.get_blockchain_info().unwrap().prune_height {
            if last_known_header.height - IRREVOCABLY_RESOLVED + 1 < prune_height as u32 {
                log::warn!(
                    "Cannot load blocks in the range {}-{}. Chain has gone too far out of sync",
                    last_known_header.height - IRREVOCABLY_RESOLVED + 1,
                    last_known_header.height
                );
                if conf.force_update {
                    log::info!("Forcing a backend update");
                    // We want to grab the first IRREVOCABLY_RESOLVED we know about for the initial cache
                    // So we can perform transitions from there onwards.
                    let target_height = prune_height + IRREVOCABLY_RESOLVED as u64;
                    let target_hash = rpc.get_block_hash(target_height).unwrap();
                    last_known_header = derefed
                        .get_header(
                            &rpc.get_block_hash(target_height).unwrap(),
                            Some(target_height as u32),
                        )
                        .await
                        .unwrap()
                        .validate(target_hash)
                        .unwrap();
                } else {
                    log::error!(
                        "The underlying chain has gone too far out of sync. The tower block cache cannot be initialized. Run with --forceupdate to force update. THIS WILL, POTENTIALLY, MAKE THE TOWER MISS SOME OF ITS APPOINTMENTS"
                    );
                    std::process::exit(1);
                }
            }
        }
        last_known_header
    } else {
        validate_best_block_header(&derefed).await.unwrap()
    };

    // DISCUSS: This is not really required (and only triggered in regtest). This is only in place so the caches can be
    // populated with enough blocks mainly because the size of the cache is based on the amount of blocks passed when initializing.
    // However, we could add an additional parameter to specify the size of the cache, and initialize with however may blocks we
    // could pull from the backend. Adding this functionality just for regtest seemed unnecessary though, hence the check.
    if tip.height < IRREVOCABLY_RESOLVED {
        log::error!(
            "Not enough blocks to start teosd (required: {IRREVOCABLY_RESOLVED}). Mine at least {} more",
            IRREVOCABLY_RESOLVED - tip.height
        );
        std::process::exit(1);
    }

    log::info!(
        "Current chain tip: {} (height: {})",
        tip.header.block_hash(),
        tip.height
    );

    // This is how chain poller names bitcoin networks.
    let btc_network = match conf.btc_network.as_str() {
        "main" => "bitcoin",
        "test" => "testnet",
        any => any,
    };

    // Build components
    let gatekeeper = Arc::new(Gatekeeper::new(
        tip.height,
        conf.subscription_slots,
        conf.subscription_duration,
        conf.expiry_delta,
        dbm.clone(),
    ));

    let mut poller = ChainPoller::new(&mut derefed, Network::from_core_arg(btc_network).unwrap());
    let (responder, watcher) = {
        let last_n_blocks = get_last_n_blocks(&mut poller, tip, IRREVOCABLY_RESOLVED as usize)
            .await.unwrap_or_else(|e| {
                // I'm pretty sure this can only happen if we are pulling blocks from the target to the prune height, and by the time we get to
                // the end at least one has been pruned.
                log::error!("Couldn't load the latest {IRREVOCABLY_RESOLVED} blocks. Please try again (Error: {})", e.into_inner());
                std::process::exit(1);
            }
        );

        let responder = Arc::new(Responder::new(
            &last_n_blocks,
            tip.height,
            Carrier::new(rpc, bitcoind_reachable.clone(), tip.height),
            gatekeeper.clone(),
            dbm.clone(),
        ));
        let watcher = Arc::new(Watcher::new(
            gatekeeper.clone(),
            responder.clone(),
            &last_n_blocks[0..6],
            tip.height,
            tower_sk,
            TowerId(tower_pk),
            dbm.clone(),
        ));
        (responder, watcher)
    };

    if watcher.is_fresh() & responder.is_fresh() & gatekeeper.is_fresh() {
        log::info!("Fresh bootstrap");
    } else {
        log::info!("Bootstrapping from backed up data");
    }

    let (shutdown_trigger, shutdown_signal_rpc_api) = triggered::trigger();
    let shutdown_signal_internal_api = shutdown_signal_rpc_api.clone();
    let shutdown_signal_http = shutdown_signal_rpc_api.clone();
    let shutdown_signal_cm = shutdown_signal_rpc_api.clone();
    let shutdown_signal_tor = shutdown_signal_rpc_api.clone();

    // The ordering here actually matters. Listeners are called by order, and we want the gatekeeper to be called
    // first so it updates the users' states and both the Watcher and the Responder operate only on registered users.
    let listener = &(gatekeeper, &(watcher.clone(), responder));
    let cache = &mut UnboundedCache::new();
    let spv_client = SpvClient::new(tip, poller, cache, listener);
    let mut chain_monitor = ChainMonitor::new(
        spv_client,
        tip,
        dbm,
        conf.polling_delta,
        shutdown_signal_cm,
        bitcoind_reachable.clone(),
    )
    .await;

    // Get all the components up to date if there's a backlog of blocks
    chain_monitor.poll_best_tip().await;
    log::info!("Bootstrap completed. Turning on interfaces");

    // Build interfaces
    let http_api_addr = format!("{}:{}", conf.api_bind, conf.api_port)
        .parse()
        .unwrap();
    let mut addresses = vec![msgs::NetworkAddress::from_ipv4(
        conf.api_bind.clone(),
        conf.api_port,
    )];

    // Create Tor endpoint if required
    let tor_api = if conf.tor_support {
        let tor_api = TorAPI::new(
            http_api_addr,
            conf.onion_hidden_service_port,
            conf.tor_control_port,
            path_network,
        )
        .await;
        addresses.push(msgs::NetworkAddress::from_torv3(
            tor_api.get_onion_address(),
            conf.onion_hidden_service_port,
        ));

        Some(tor_api)
    } else {
        None
    };

    let internal_api = Arc::new(InternalAPI::new(
        watcher,
        addresses,
        bitcoind_reachable.clone(),
        shutdown_trigger,
    ));
    let internal_api_cloned = internal_api.clone();

    let rpc_api_addr = format!("{}:{}", conf.rpc_bind, conf.rpc_port)
        .parse()
        .unwrap();
    let internal_api_addr = format!("{}:{}", conf.internal_api_bind, conf.internal_api_port)
        .parse()
        .unwrap();

    // Generate mtls certificates to data directory so the admin can securely connect
    // to the server to perform administrative tasks.
    let (identity, ca_cert) = tls_init(&path).unwrap_or_else(|e| {
        eprintln!("Couldn't generate tls certificates: {e:?}");
        std::process::exit(1);
    });

    let tls = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(Certificate::from_pem(ca_cert));

    // Start tasks
    let private_api_task = task::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .expect("couldn't configure tls")
            .add_service(PrivateTowerServicesServer::new(internal_api))
            .serve_with_shutdown(rpc_api_addr, shutdown_signal_rpc_api)
            .await
            .unwrap();
    });

    let public_api_task = task::spawn(async move {
        Server::builder()
            .add_service(PublicTowerServicesServer::new(internal_api_cloned))
            .serve_with_shutdown(internal_api_addr, shutdown_signal_internal_api)
            .await
            .unwrap();
    });

    let (http_service_ready, ready_signal_http) = triggered::trigger();
    let http_api_task = task::spawn(http::serve(
        http_api_addr,
        internal_api_addr,
        http_service_ready,
        shutdown_signal_http,
    ));
    ready_signal_http.await;

    // Add Tor Onion Service for public API
    let mut tor_task = Option::None;
    let (tor_service_ready, ready_signal_tor) = triggered::trigger();
    if let Some(tor_api) = tor_api {
        log::info!("Starting up Tor hidden service");

        tor_task = Some(task::spawn(async move {
            if let Err(e) = tor_api
                .expose_onion_service(tor_service_ready, shutdown_signal_tor)
                .await
            {
                eprintln!("Cannot connect to the Tor backend: {e}");
                std::process::exit(1);
            }
        }));

        ready_signal_tor.await
    }

    log::info!("Tower ready");
    chain_monitor.monitor_chain().await;

    // Wait until shutdown
    http_api_task.await.unwrap();
    private_api_task.await.unwrap();
    public_api_task.await.unwrap();
    if let Some(tor_task) = tor_task {
        tor_task.await.unwrap();
    }

    log::info!("Shutting down tower");
}
