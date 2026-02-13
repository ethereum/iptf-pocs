// Test environment harness for scaffolding the full intmax2 service stack.
// Migration SQL files sourced from intmax2 dev branch: 983157b7a973d5e5b8c875434cedee05cf0c39e4

use std::sync::Arc;

use actix_cors::Cors;
use actix_web::{
    App,
    HttpServer,
    dev::ServerHandle,
    web::Data,
};
use alloy::{
    node_bindings::{
        Anvil,
        AnvilInstance,
    },
    primitives::{
        Address,
        B256,
        U256,
    },
};
use anyhow::{
    Context,
    Result,
};
use intmax2_client_sdk::{
    client::{
        client::Client as Intmax2Client,
        config::ClientConfig,
    },
    external_api::{
        balance_prover::BalanceProverClient,
        block_builder::BlockBuilderClient,
        contract::{
            block_builder_registry::BlockBuilderRegistryContract,
            erc20_contract::ERC20Contract,
            liquidity_contract::LiquidityContract,
            rollup_contract::RollupContract,
            utils::{
                get_provider_with_fallback,
                get_provider_with_signer,
            },
            withdrawal_contract::WithdrawalContract,
        },
        store_vault_server::StoreVaultServerClient,
        validity_prover::ValidityProverClient,
        withdrawal_server::WithdrawalServerClient,
    },
};
use intmax2_interfaces::utils::network::Network;
use intmax2_zkp::circuits::validity::transition::processor::ValidityTransitionProcessor;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::config::PoseidonGoldilocksConfig,
};
use server_common::health_check::health_check;
use sqlx::{
    PgPool,
    migrate::Migrator,
};
use testcontainers::{
    ContainerAsync,
    GenericImage,
    ImageExt,
    core::{
        ContainerPort,
        WaitFor,
    },
    runners::AsyncRunner,
};
use tokio::task::JoinHandle;

static STORE_VAULT_MIGRATOR: Migrator = sqlx::migrate!("migrations/store_vault");
static VALIDITY_PROVER_MIGRATOR: Migrator = sqlx::migrate!("migrations/validity_prover");
static WITHDRAWAL_MIGRATOR: Migrator = sqlx::migrate!("migrations/withdrawal");

// Test scroll messenger contract for relaying deposits to the rollup.
// Source: intmax2-contract/contracts/test/rollup/L2ScrollMessengerTestForRollup.sol
alloy::sol! {
    #[sol(rpc, bytecode = "0x6080604052348015600e575f5ffd5b506102648061001c5f395ff3fe608060405234801561000f575f5ffd5b506004361061004a575f3560e01c8063653721471461004e5780636e296e451461007c578063c50bf6be1461008c578063f1094e99146100bd575b5f5ffd5b5f54610060906001600160a01b031681565b6040516001600160a01b03909116815260200160405180910390f35b5f546001600160a01b0316610060565b6100bb61009a366004610149565b5f80546001600160a01b0319166001600160a01b0392909216919091179055565b005b6100bb6100cb366004610169565b60405163f03efa3760e01b81526001600160a01b0385169063f03efa37906100fb908690869086906004016101ef565b5f604051808303815f87803b158015610112575f5ffd5b505af1158015610124573d5f5f3e3d5ffd5b5050505050505050565b80356001600160a01b0381168114610144575f5ffd5b919050565b5f60208284031215610159575f5ffd5b6101628261012e565b9392505050565b5f5f5f5f6060858703121561017c575f5ffd5b6101858561012e565b935060208501359250604085013567ffffffffffffffff8111156101a7575f5ffd5b8501601f810187136101b7575f5ffd5b803567ffffffffffffffff8111156101cd575f5ffd5b8760208260051b84010111156101e1575f5ffd5b949793965060200194505050565b83815260406020820181905281018290525f6001600160fb1b03831115610214575f5ffd5b8260051b808560608501379190910160600194935050505056fea264697066735822122021c42c50bb2dedd151dced29e84cc83a242a8948d6043f9339f91a25a2e6679a64736f6c634300081b0033")]
    contract L2ScrollMessengerTest {
        address public result;
        function setResult(address _result) external;
        function xDomainMessageSender() external view returns (address);
        function processDeposits(
            address rollup,
            uint256 _lastProcessedDepositId,
            bytes32[] calldata depositHashes
        ) external;
    }
}

// Minimal view interfaces for reading on-chain state during deposit relay.
alloy::sol! {
    #[sol(rpc)]
    contract LiquidityView {
        function getDepositDataHash(uint256 depositId) external view returns (bytes32);
        function getLastDepositId() external view returns (uint256);
    }
}

alloy::sol! {
    #[sol(rpc)]
    contract RollupView {
        function lastProcessedDepositId() external view returns (uint256);
    }
}

pub fn allocate_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("failed to bind ephemeral port");
    listener.local_addr().unwrap().port()
}

pub struct ServicePorts {
    pub store_vault: u16,
    pub balance_prover: u16,
    pub validity_prover: u16,
    pub withdrawal_server: u16,
    pub block_builder: u16,
}

impl ServicePorts {
    pub fn allocate() -> Self {
        Self {
            store_vault: allocate_port(),
            balance_prover: allocate_port(),
            validity_prover: allocate_port(),
            withdrawal_server: allocate_port(),
            block_builder: allocate_port(),
        }
    }
}

pub struct DbPools {
    pub store_vault: PgPool,
    pub validity_prover: PgPool,
    pub withdrawal: PgPool,
}

async fn create_database(admin_pool: &PgPool, db_name: &str) -> Result<()> {
    sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
        .execute(admin_pool)
        .await
        .with_context(|| format!("failed to create database {db_name}"))?;
    Ok(())
}

pub async fn setup_databases(postgres_url: &str) -> Result<DbPools> {
    // Connect to the default postgres database
    let admin_url = format!("{postgres_url}/postgres");
    let admin_pool = PgPool::connect(&admin_url)
        .await
        .context("failed to connect to postgres admin db")?;

    // Create service databases
    create_database(&admin_pool, "legacy_store_vault_server").await?;
    create_database(&admin_pool, "validity_prover").await?;
    create_database(&admin_pool, "withdrawal").await?;
    admin_pool.close().await;

    // Connect to each and run migrations
    let sv_url = format!("{postgres_url}/legacy_store_vault_server");
    let sv_pool = PgPool::connect(&sv_url)
        .await
        .context("connect to store_vault db")?;
    STORE_VAULT_MIGRATOR
        .run(&sv_pool)
        .await
        .context("store_vault migrations")?;

    let vp_url = format!("{postgres_url}/validity_prover");
    let vp_pool = PgPool::connect(&vp_url)
        .await
        .context("connect to validity_prover db")?;
    VALIDITY_PROVER_MIGRATOR
        .run(&vp_pool)
        .await
        .context("validity_prover migrations")?;

    let wd_url = format!("{postgres_url}/withdrawal");
    let wd_pool = PgPool::connect(&wd_url)
        .await
        .context("connect to withdrawal db")?;
    WITHDRAWAL_MIGRATOR
        .run(&wd_pool)
        .await
        .context("withdrawal migrations")?;

    Ok(DbPools {
        store_vault: sv_pool,
        validity_prover: vp_pool,
        withdrawal: wd_pool,
    })
}

pub struct DeployedContracts {
    pub rollup: Address,
    pub liquidity: Address,
    pub block_builder_registry: Address,
    pub withdrawal: Address,
    pub test_messenger: Address,
    pub test_erc20: Address,
}

pub async fn deploy_contracts(anvil: &AnvilInstance) -> Result<DeployedContracts> {
    let rpc_url = anvil.endpoint();
    let deployer_key = B256::from_slice(&anvil.keys()[0].to_bytes());
    let deployer_addr = anvil.addresses()[0];

    let provider = get_provider_with_fallback(std::slice::from_ref(&rpc_url))
        .context("create provider")?;

    let signer_provider = get_provider_with_signer(&provider, deployer_key);
    let random_addr = Address::random();

    // Deploy test scroll messenger first (needed by rollup
    // and liquidity for deposit relay)
    let test_messenger = L2ScrollMessengerTest::deploy(&signer_provider)
        .await
        .context("deploy test scroll messenger")?;
    let test_messenger_addr = *test_messenger.address();
    log::info!("Test scroll messenger: {:?}", test_messenger_addr);

    // Deploy test ERC20 token (mints 1e36 raw tokens to deployer)
    let erc20_contract =
        ERC20Contract::deploy(provider.clone(), deployer_key, deployer_addr)
            .await
            .context("deploy test ERC20")?;
    let erc20_addr = erc20_contract.address;
    log::info!("Test ERC20: {:?}", erc20_addr);

    // Deploy all intmax2 contracts
    let rollup_contract = RollupContract::deploy(provider.clone(), deployer_key)
        .await
        .context("deploy rollup")?;

    let liquidity_contract = LiquidityContract::deploy(provider.clone(), deployer_key)
        .await
        .context("deploy liquidity")?;
    let registry_contract =
        BlockBuilderRegistryContract::deploy(provider.clone(), deployer_key)
            .await
            .context("deploy registry")?;
    let withdrawal_contract = WithdrawalContract::deploy(provider.clone(), deployer_key)
        .await
        .context("deploy withdrawal")?;

    // Rollup: (admin, scroll_messenger, liquidity, contribution)
    rollup_contract
        .initialize(
            deployer_key,
            deployer_addr,
            test_messenger_addr,
            liquidity_contract.address,
            random_addr,
        )
        .await
        .context("initialize rollup")?;
    log::info!("Rollup contract: {:?}", rollup_contract.address);

    // Liquidity: (admin, scroll_messenger, rollup, withdrawal,
    //             claim, analyzer, contribution, erc20s)
    liquidity_contract
        .initialize(
            deployer_key,
            deployer_addr,
            test_messenger_addr,
            rollup_contract.address,
            withdrawal_contract.address,
            random_addr,
            random_addr,
            random_addr,
            vec![erc20_addr],
        )
        .await
        .context("initialize liquidity")?;
    log::info!("Liquidity contract: {:?}", liquidity_contract.address);

    log::info!("Registry contract: {:?}", registry_contract.address);

    // Withdrawal: (admin, scroll_messenger, verifier,
    //              liquidity, rollup, contribution,
    //              direct_withdrawal_token_indices)
    withdrawal_contract
        .initialize(
            deployer_key,
            deployer_addr,
            random_addr,
            random_addr,
            liquidity_contract.address,
            rollup_contract.address,
            random_addr,
            vec![U256::from(0), U256::from(1), U256::from(2)],
        )
        .await
        .context("initialize withdrawal")?;
    log::info!("Withdrawal contract: {:?}", withdrawal_contract.address);

    // Configure test messenger: xDomainMessageSender()
    // must return the liquidity address to satisfy
    // Rollup.onlyLiquidityContract modifier.
    test_messenger
        .setResult(liquidity_contract.address)
        .send()
        .await
        .context("setResult send")?
        .get_receipt()
        .await
        .context("setResult receipt")?;
    log::info!(
        "Test messenger configured: xDomainMessageSender → {:?}",
        liquidity_contract.address
    );

    Ok(DeployedContracts {
        rollup: rollup_contract.address,
        liquidity: liquidity_contract.address,
        block_builder_registry: registry_contract.address,
        withdrawal: withdrawal_contract.address,
        test_messenger: test_messenger_addr,
        test_erc20: erc20_addr,
    })
}

/// Relay all pending deposits from the liquidity contract to
/// the rollup via the test scroll messenger. This simulates
/// the Scroll L1→L2 message relay that happens in production.
///
/// Returns the relay transaction hash, or `None` if there were
/// no deposits to relay.
pub async fn relay_pending_deposits(
    anvil: &AnvilInstance,
    contracts: &DeployedContracts,
) -> Result<Option<B256>> {
    let rpc_url = anvil.endpoint();
    let provider = get_provider_with_fallback(std::slice::from_ref(&rpc_url))
        .context("relay: create provider")?;
    let deployer_key = B256::from_slice(&anvil.keys()[0].to_bytes());
    let signer_provider = get_provider_with_signer(&provider, deployer_key);

    // Read the last relayed deposit ID from rollup
    let rollup_view = RollupView::new(contracts.rollup, &provider);
    let last_relayed = rollup_view
        .lastProcessedDepositId()
        .call()
        .await
        .context("read lastProcessedDepositId")?;

    // Read the last deposit ID from liquidity
    let liquidity_view = LiquidityView::new(contracts.liquidity, &provider);
    let last_deposit = liquidity_view
        .getLastDepositId()
        .call()
        .await
        .context("read getLastDepositId")?;

    if last_deposit <= last_relayed {
        log::info!("No pending deposits to relay");
        return Ok(None);
    }

    let start = last_relayed.to::<u64>() + 1;
    let end = last_deposit.to::<u64>();

    let mut hashes = Vec::new();
    for id in start..=end {
        let hash = liquidity_view
            .getDepositDataHash(U256::from(id))
            .call()
            .await
            .context("read getDepositDataHash")?;
        if hash != B256::ZERO {
            hashes.push(hash);
        }
    }

    if hashes.is_empty() {
        log::info!("No non-zero deposit hashes to relay");
        return Ok(None);
    }

    let messenger =
        L2ScrollMessengerTest::new(contracts.test_messenger, &signer_provider);
    let receipt = messenger
        .processDeposits(contracts.rollup, last_deposit, hashes.clone())
        .send()
        .await
        .context("processDeposits send")?
        .get_receipt()
        .await
        .context("processDeposits receipt")?;

    log::info!(
        "Relayed {} deposits ({start}..={end}) to rollup, tx={}",
        hashes.len(),
        receipt.transaction_hash,
    );
    Ok(Some(receipt.transaction_hash))
}

pub struct ServiceHandle {
    pub server_handle: ServerHandle,
    pub join_handle: JoinHandle<()>,
}

impl ServiceHandle {
    pub async fn shutdown(self) {
        self.server_handle.stop(true).await;
        let _ = self.join_handle.await;
    }
}

pub struct LocalSetServiceHandle {
    pub server_handle: ServerHandle,
    pub thread_handle: std::thread::JoinHandle<()>,
}

impl LocalSetServiceHandle {
    pub async fn shutdown(self) {
        self.server_handle.stop(true).await;
        let _ = tokio::task::spawn_blocking(move || {
            self.thread_handle.join().ok();
        })
        .await;
    }
}

/// Start the legacy store vault server.
pub async fn start_store_vault(port: u16, postgres_url: &str) -> Result<ServiceHandle> {
    let env = legacy_store_vault_server::EnvVar {
        port,
        database_url: format!("{postgres_url}/legacy_store_vault_server"),
        database_max_connections: 5,
        database_timeout: 30,
    };

    let server =
        legacy_store_vault_server::app::store_vault_server::StoreVaultServer::new(&env)
            .await
            .context("init store vault server")?;
    let state = Data::new(legacy_store_vault_server::api::state::State::new(server));

    let http_server = HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(actix_web::web::JsonConfig::default().limit(35_000_000))
            .app_data(state.clone())
            .service(health_check)
            .service(legacy_store_vault_server::api::routes::store_vault_server_scope())
    })
    .workers(2)
    .bind(format!("127.0.0.1:{port}"))
    .context("bind store vault")?
    .disable_signals()
    .run();

    let server_handle = http_server.handle();
    let join_handle = tokio::spawn(async move {
        let _ = http_server.await;
    });

    log::info!("Store vault server started on port {port}");
    Ok(ServiceHandle {
        server_handle,
        join_handle,
    })
}

/// Start the balance prover.
pub async fn start_balance_prover(port: u16) -> Result<ServiceHandle> {
    // BalanceProver::new() is sync and loads circuit
    let prover = tokio::task::spawn_blocking(
        balance_prover::api::balance_prover::BalanceProver::new,
    )
    .await
    .context("spawn_blocking join")?
    .context("init balance prover")?;

    let state = Data::new(prover);

    let http_server = HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(state.clone())
            .service(health_check)
            .service(balance_prover::api::api::balance_prover_scope())
    })
    .workers(2)
    .bind(format!("127.0.0.1:{port}"))
    .context("bind balance prover")?
    .disable_signals()
    .run();

    let server_handle = http_server.handle();
    let join_handle = tokio::spawn(async move {
        let _ = http_server.await;
    });

    log::info!("Balance prover started on port {port}");
    Ok(ServiceHandle {
        server_handle,
        join_handle,
    })
}

/// Start the validity prover.
pub async fn start_validity_prover(
    port: u16,
    postgres_url: &str,
    redis_url: &str,
    anvil_rpc_url: &str,
    contracts: &DeployedContracts,
) -> Result<LocalSetServiceHandle> {
    let env = validity_prover::EnvVar {
        port,
        is_sync_mode: true,
        leader_lock_ttl: 3,
        witness_sync_interval: 2,
        validity_proof_interval: 2,
        add_tasks_interval: 2,
        cleanup_inactive_tasks_interval: 10,
        validity_prover_restart_interval: 10,
        // observer settings
        observer_event_block_interval: 10000,
        observer_max_query_times: 100,
        observer_sync_interval: 2,
        observer_restart_interval: 10,
        // onchain
        l1_rpc_url: anvil_rpc_url.to_string(),
        l2_rpc_url: anvil_rpc_url.to_string(),
        rollup_contract_address: contracts.rollup,
        rollup_contract_deployed_block_number: 1,
        liquidity_contract_address: contracts.liquidity,
        liquidity_contract_deployed_block_number: 1,
        // the graph (not used in the PoC)
        the_graph_l1_url: None,
        the_graph_l2_url: None,
        the_graph_l1_bearer: None,
        the_graph_l2_bearer: None,
        // db
        database_url: format!("{postgres_url}/validity_prover"),
        database_max_connections: 5,
        database_timeout: 30,
        // redis
        redis_url: redis_url.to_string(),
        task_ttl: 300,
        heartbeat_interval: 10,
        // cache
        dynamic_cache_ttl: 5,
        static_cache_ttl: 3600,
        // rate manager
        observer_error_threshold: 10,
        rate_manager_window: 600,
        rate_manager_timeout: 10,
        thread_heartbeat_timeout: 600,
    };

    let (tx, rx) = tokio::sync::oneshot::channel();

    let thread_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build validity prover runtime");

        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let state = validity_prover::api::state::State::new(&env)
                .await
                .expect("init validity prover state");
            let data = Data::new(state);

            let http_server = HttpServer::new(move || {
                App::new()
                    .wrap(Cors::permissive())
                    .app_data(data.clone())
                    .service(validity_prover::api::health::health_check)
                    .service(
                        validity_prover::api::validity_prover::validity_prover_scope(),
                    )
            })
            .workers(2)
            .bind(format!("127.0.0.1:{port}"))
            .expect("bind validity prover")
            .disable_signals()
            .run();

            let _ = tx.send(http_server.handle());
            http_server.await.ok();
        });
    });

    let server_handle = rx.await.context("get validity prover server handle")?;
    log::info!("Validity prover started on port {port}");

    Ok(LocalSetServiceHandle {
        server_handle,
        thread_handle,
    })
}

/// Start the validity prover worker.
pub async fn start_validity_worker(redis_url: &str) -> Result<JoinHandle<()>> {
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    let env = validity_prover_worker::EnvVar {
        redis_url: redis_url.to_string(),
        task_ttl: 300,
        heartbeat_interval: 10,
        num_process: 1,
    };

    let processor: Arc<ValidityTransitionProcessor<F, C, D>> = Arc::new(
        tokio::task::spawn_blocking(ValidityTransitionProcessor::new)
            .await
            .context("spawn_blocking ValidityTransitionProcessor")?,
    );

    let worker = validity_prover_worker::app::worker::Worker::new(&env, processor)
        .map_err(|e| anyhow::anyhow!("{e:?}"))
        .context("init validity worker")?;

    let handle = tokio::spawn(async move {
        worker.run().await;
    });

    log::info!("Validity prover worker started");
    Ok(handle)
}

/// Start the withdrawal server.
pub async fn start_withdrawal_server(
    port: u16,
    postgres_url: &str,
    store_vault_url: &str,
    validity_prover_url: &str,
    anvil_rpc_url: &str,
    contracts: &DeployedContracts,
) -> Result<ServiceHandle> {
    let view_pair: intmax2_interfaces::utils::key::ViewPair =
        "viewpair/0x195337dd9173b50e43aa61d8b74b838b2d83bae8c6a4379f645a97f2e82d91c7/0x1b426ef975dbaab3526101ac1d12f73c2ca49c7002f15df18a1cec4487979054"
            .parse()
            .expect("parse test view pair");

    let env = withdrawal_server::Env {
        port,
        database_url: format!("{postgres_url}/withdrawal"),
        database_max_connections: 5,
        database_timeout: 30,
        store_vault_server_base_url: store_vault_url.to_string(),
        use_s3: Some(false),
        validity_prover_base_url: validity_prover_url.to_string(),
        l2_rpc_url: anvil_rpc_url.to_string(),
        rollup_contract_address: contracts.rollup,
        withdrawal_contract_address: contracts.withdrawal,
        is_faster_mining: true,
        withdrawal_beneficiary_view_pair: view_pair,
        claim_beneficiary_view_pair: view_pair,
        direct_withdrawal_fee: Some("0:0".parse().unwrap()),
        claimable_withdrawal_fee: Some("0:0".parse().unwrap()),
        claim_fee: Some("0:0".parse().unwrap()),
    };

    let state = withdrawal_server::api::state::State::new(&env)
        .await
        .context("init withdrawal server state")?;
    let data = Data::new(state);

    let http_server = HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(data.clone())
            .service(health_check)
            .service(withdrawal_server::api::routes::withdrawal_server_scope())
    })
    .workers(2)
    .bind(format!("127.0.0.1:{port}"))
    .context("bind withdrawal server")?
    .disable_signals()
    .run();

    let server_handle = http_server.handle();
    let join_handle = tokio::spawn(async move {
        let _ = http_server.await;
    });

    log::info!("Withdrawal server started on port {port}");
    Ok(ServiceHandle {
        server_handle,
        join_handle,
    })
}

pub async fn start_block_builder(
    port: u16,
    store_vault_url: &str,
    validity_prover_url: &str,
    anvil_rpc_url: &str,
    contracts: &DeployedContracts,
    builder_private_key: B256,
) -> Result<LocalSetServiceHandle> {
    let env = block_builder::EnvVar {
        port,
        block_builder_url: format!("http://127.0.0.1:{port}"),
        redis_url: None,
        cluster_id: Some("1".to_string()),
        l2_rpc_url: anvil_rpc_url.to_string(),
        rollup_contract_address: contracts.rollup,
        block_builder_registry_contract_address: contracts.block_builder_registry,
        store_vault_server_base_url: store_vault_url.to_string(),
        use_s3: Some(false),
        validity_prover_base_url: validity_prover_url.to_string(),
        block_builder_private_key: builder_private_key,
        eth_allowance_for_block: "0.001".to_string(),
        tx_timeout: 80,
        accepting_tx_interval: 5,
        proposing_block_interval: 5,
        deposit_check_interval: Some(5),
        initial_heart_beat_delay: 5,
        heart_beat_interval: 85800,
        general_polling_interval: None,
        restart_job_interval: None,
        gas_limit_for_block_post: Some(400000),
        nonce_waiting_time: None,
        beneficiary: None,
        registration_fee: Some("0:0".parse().unwrap()),
        non_registration_fee: Some("0:0".parse().unwrap()),
        registration_collateral_fee: None,
        non_registration_collateral_fee: None,
    };

    // Channel to send ServerHandle back to the main thread
    let (tx, rx) = tokio::sync::oneshot::channel();

    let thread_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build block builder runtime");

        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let state = block_builder::api::state::State::new(&env)
                .await
                .expect("init block builder state");
            state.run();

            let data = Data::new(state);
            let http_server = HttpServer::new(move || {
                App::new()
                    .wrap(Cors::permissive())
                    .app_data(data.clone())
                    .service(health_check)
                    .service(block_builder::api::routes::block_builder_scope())
            })
            .workers(2)
            .bind(format!("127.0.0.1:{port}"))
            .expect("bind block builder")
            .disable_signals()
            .run();

            let _ = tx.send(http_server.handle());
            http_server.await.ok();
        });
    });

    let server_handle = rx.await.context("get block builder server handle")?;
    log::info!("Block builder started on port {port}");

    Ok(LocalSetServiceHandle {
        server_handle,
        thread_handle,
    })
}

pub async fn wait_for_health(base_url: &str, timeout: std::time::Duration) -> Result<()> {
    let client = reqwest::Client::new();
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > timeout {
            anyhow::bail!(
                "service at {base_url} did not become healthy within {timeout:?}"
            );
        }
        let result: Result<reqwest::Response, reqwest::Error> =
            client.get(format!("{base_url}/health-check")).send().await;
        match result {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}

pub struct TestEnv {
    pub ports: ServicePorts,
    pub anvil: AnvilInstance,
    pub contracts: DeployedContracts,
    pub db_pools: DbPools,
    pub service_handles: Vec<ServiceHandle>,
    pub worker_handle: Option<JoinHandle<()>>,
    pub validity_prover_handle: Option<LocalSetServiceHandle>,
    pub block_builder_handle: Option<LocalSetServiceHandle>,
    _postgres: ContainerAsync<GenericImage>,
    _redis: ContainerAsync<GenericImage>,
}

impl TestEnv {
    pub fn store_vault_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.ports.store_vault)
    }
    pub fn balance_prover_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.ports.balance_prover)
    }
    pub fn validity_prover_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.ports.validity_prover)
    }
    pub fn withdrawal_server_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.ports.withdrawal_server)
    }
    pub fn block_builder_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.ports.block_builder)
    }

    /// Create an ERC20Contract instance for the test token.
    pub fn erc20_contract(&self) -> Result<ERC20Contract> {
        let provider =
            get_provider_with_fallback(std::slice::from_ref(&self.anvil.endpoint()))
                .context("create erc20 provider")?;
        Ok(ERC20Contract::new(provider, self.contracts.test_erc20))
    }

    /// Build an intmax2 client SDK `Client` wired to
    /// this test environment's services and contracts.
    pub fn build_client(&self) -> Result<Intmax2Client> {
        let provider =
            get_provider_with_fallback(std::slice::from_ref(&self.anvil.endpoint()))
                .context("create client provider")?;

        Ok(Intmax2Client {
            config: ClientConfig {
                network: Network::Devnet,
                deposit_timeout: 120,
                tx_timeout: 60,
                block_builder_query_wait_time: 5,
                block_builder_query_interval: 2,
                block_builder_query_limit: 20,
                is_faster_mining: true,
            },
            block_builder: Box::new(BlockBuilderClient::new()),
            store_vault_server: Box::new(StoreVaultServerClient::new(
                &self.store_vault_url(),
            )),
            validity_prover: Box::new(ValidityProverClient::new(
                &self.validity_prover_url(),
            )),
            balance_prover: Box::new(BalanceProverClient::new(
                &self.balance_prover_url(),
            )),
            withdrawal_server: Box::new(WithdrawalServerClient::new(
                &self.withdrawal_server_url(),
            )),
            liquidity_contract: LiquidityContract::new(
                provider.clone(),
                self.contracts.liquidity,
            ),
            rollup_contract: RollupContract::new(provider.clone(), self.contracts.rollup),
            withdrawal_contract: WithdrawalContract::new(
                provider,
                self.contracts.withdrawal,
            ),
        })
    }

    pub async fn shutdown(self) {
        for handle in self.service_handles {
            handle.shutdown().await;
        }
        if let Some(h) = self.validity_prover_handle {
            h.shutdown().await;
        }
        if let Some(h) = self.block_builder_handle {
            h.shutdown().await;
        }
        if let Some(h) = self.worker_handle {
            h.abort();
            let _ = h.await;
        }
    }

    /// Starts postgres + redis containers, anvil, deploys
    /// contracts, runs migrations, and boots all services.
    pub async fn build() -> Result<Self> {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Info)
            .filter_module("tokio", log::LevelFilter::Warn)
            .filter_module("validity_prover", log::LevelFilter::Warn)
            .filter_module("actix_server", log::LevelFilter::Off)
            .filter_module("alloy_transport", log::LevelFilter::Warn)
            .filter_module("sqlx", log::LevelFilter::Off)
            .filter_module("tracing::span", log::LevelFilter::Off)
            .filter_module(
                "intmax2_client_sdk::external_api::utils::retry",
                log::LevelFilter::Off,
            )
            .try_init();

        log::info!("Starting PostgreSQL container...");
        let postgres: ContainerAsync<GenericImage> =
            GenericImage::new("postgres", "16.8-alpine")
                .with_exposed_port(ContainerPort::Tcp(5432))
                .with_wait_for(WaitFor::message_on_stderr(
                    "database system is ready to accept connections",
                ))
                .with_env_var("POSTGRES_PASSWORD", "password")
                .with_env_var("TZ", "UTC")
                .start()
                .await
                .context("start postgres container")?;

        let pg_port = postgres
            .get_host_port_ipv4(5432)
            .await
            .context("get postgres port")?;
        let postgres_url = format!("postgres://postgres:password@127.0.0.1:{pg_port}");
        log::info!("PostgreSQL running on port {pg_port}");

        log::info!("Starting Redis container...");
        let redis: ContainerAsync<GenericImage> = GenericImage::new("redis", "latest")
            .with_exposed_port(ContainerPort::Tcp(6379))
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
            .start()
            .await
            .context("start redis container")?;

        let redis_port = redis
            .get_host_port_ipv4(6379)
            .await
            .context("get redis port")?;
        let redis_url = format!("redis://127.0.0.1:{redis_port}");
        log::info!("Redis running on port {redis_port}");

        let ports = ServicePorts::allocate();

        log::info!("Setting up databases and running migrations...");
        let db_pools = setup_databases(&postgres_url).await?;
        log::info!("Databases ready.");

        log::info!("Starting anvil...");
        let anvil = Anvil::new().block_time(1).chain_id(31337).spawn();
        let anvil_rpc_url = anvil.endpoint();
        log::info!("Anvil running at {anvil_rpc_url}");

        log::info!("Deploying contracts...");
        let contracts = deploy_contracts(&anvil).await?;
        log::info!("Contracts deployed.");

        // Block builder uses anvil account[1]
        let builder_key = B256::from_slice(&anvil.keys()[1].to_bytes());

        let store_vault_handle =
            start_store_vault(ports.store_vault, &postgres_url).await?;

        let balance_prover_handle = start_balance_prover(ports.balance_prover).await?;

        let validity_prover_handle = start_validity_prover(
            ports.validity_prover,
            &postgres_url,
            &redis_url,
            &anvil_rpc_url,
            &contracts,
        )
        .await?;

        let store_vault_url = format!("http://127.0.0.1:{}", ports.store_vault);
        let validity_prover_url = format!("http://127.0.0.1:{}", ports.validity_prover);

        let worker_handle = start_validity_worker(&redis_url).await?;

        let withdrawal_handle = start_withdrawal_server(
            ports.withdrawal_server,
            &postgres_url,
            &store_vault_url,
            &validity_prover_url,
            &anvil_rpc_url,
            &contracts,
        )
        .await?;

        let block_builder_handle = start_block_builder(
            ports.block_builder,
            &store_vault_url,
            &validity_prover_url,
            &anvil_rpc_url,
            &contracts,
            builder_key,
        )
        .await?;

        // 8. Health check all HTTP services
        log::info!("Waiting for services to become healthy...");
        let timeout = std::time::Duration::from_secs(30);

        wait_for_health(&store_vault_url, timeout)
            .await
            .context("store vault health")?;
        wait_for_health(
            &format!("http://127.0.0.1:{}", ports.balance_prover),
            timeout,
        )
        .await
        .context("balance prover health")?;
        wait_for_health(&validity_prover_url, timeout)
            .await
            .context("validity prover health")?;
        wait_for_health(
            &format!("http://127.0.0.1:{}", ports.withdrawal_server),
            timeout,
        )
        .await
        .context("withdrawal server health")?;
        wait_for_health(
            &format!("http://127.0.0.1:{}", ports.block_builder),
            timeout,
        )
        .await
        .context("block builder health")?;

        log::info!("All services healthy!");

        Ok(TestEnv {
            ports,
            anvil,
            contracts,
            db_pools,
            service_handles: vec![
                store_vault_handle,
                balance_prover_handle,
                withdrawal_handle,
            ],
            worker_handle: Some(worker_handle),
            validity_prover_handle: Some(validity_prover_handle),
            block_builder_handle: Some(block_builder_handle),
            _postgres: postgres,
            _redis: redis,
        })
    }
}
