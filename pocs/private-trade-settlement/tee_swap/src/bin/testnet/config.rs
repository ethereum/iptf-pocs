use std::time::Duration;

use alloy::primitives::Address;
use serde::Deserialize;

/// Top-level testnet configuration loaded from TOML.
#[derive(Debug, Deserialize)]
pub struct TestnetConfig {
    pub sepolia: ChainConfig,
    pub layer2: ChainConfig,
    pub alice: PartyConfig,
    pub bob: PartyConfig,
    pub tee: Option<TeeConfig>,
    pub coordinator: Option<CoordinatorConfig>,
    pub swap: SwapConfig,
}

/// Per-chain configuration.
#[derive(Debug, Deserialize)]
pub struct ChainConfig {
    pub rpc_url: String,
    pub deployer_private_key: String,
    /// Block explorer base URL for transaction links (e.g. "https://sepolia.scrollscan.com/tx").
    /// When absent, raw tx hashes are printed instead.
    pub explorer_url: Option<String>,
    /// Block number at which contracts were deployed. Required when contract addresses are provided.
    pub deployment_block: Option<u64>,
    /// Pre-deployed PrivateUTXO address. If absent, the binary deploys a fresh contract.
    pub private_utxo_address: Option<Address>,
    /// Pre-deployed TeeLock address. If absent, the binary deploys a fresh contract.
    pub tee_lock_address: Option<Address>,
}

/// Which chain a party operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Sepolia,
    Layer2,
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::Sepolia => write!(f, "sepolia"),
            Chain::Layer2 => write!(f, "layer2"),
        }
    }
}

/// Per-party configuration.
#[derive(Debug, Deserialize)]
pub struct PartyConfig {
    pub private_key: String,
    /// Which chain this party operates on.
    pub chain: Chain,
    /// Amount in wei.
    pub amount: u64,
}

/// TEE private key configuration. Required when running a local coordinator.
#[derive(Debug, Deserialize)]
pub struct TeeConfig {
    pub private_key: String,
}

/// Coordinator configuration.
#[derive(Debug, Deserialize)]
pub struct CoordinatorConfig {
    /// External coordinator URL. If absent, a local coordinator is spawned.
    pub url: Option<String>,
    /// TEE signer address for TeeLock deployment. Required when deploying contracts
    /// with an external coordinator (since there's no local TEE keystore to derive it from).
    pub tee_address: Option<Address>,
}

/// Swap parameters.
#[derive(Debug, Deserialize)]
pub struct SwapConfig {
    /// Swap timeout duration (e.g. "24h", "1h30m"). Parsed via humantime.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
}

/// Errors from config loading and validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("validation error: {0}")]
    Validation(String),
}

impl TestnetConfig {
    /// Load and validate a config from a TOML file.
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Alice and Bob must be on different chains.
        if self.alice.chain == self.bob.chain {
            return Err(ConfigError::Validation(
                "alice.chain and bob.chain must be different".into(),
            ));
        }

        // TEE keystore required for local coordinator.
        let is_local_coordinator = match &self.coordinator {
            None => true,
            Some(c) => c.url.is_none(),
        };
        if is_local_coordinator && self.tee.is_none() {
            return Err(ConfigError::Validation(
                "tee.private_key required when running a local coordinator (no coordinator.url set)"
                    .into(),
            ));
        }

        // If contract addresses are provided, deployment_block must also be set.
        self.validate_chain_addresses("sepolia", &self.sepolia)?;
        self.validate_chain_addresses("layer2", &self.layer2)?;

        // If external coordinator and contracts need deploying, tee_address is required.
        let is_external_coordinator = !is_local_coordinator;
        let needs_deploy_sepolia = self.sepolia.private_utxo_address.is_none();
        let needs_deploy_layer2 = self.layer2.private_utxo_address.is_none();

        if is_external_coordinator && (needs_deploy_sepolia || needs_deploy_layer2) {
            let has_tee_address = self
                .coordinator
                .as_ref()
                .is_some_and(|c| c.tee_address.is_some());
            if !has_tee_address {
                return Err(ConfigError::Validation(
                    "coordinator.tee_address required when deploying contracts with an external coordinator".into(),
                ));
            }
        }

        Ok(())
    }

    fn validate_chain_addresses(
        &self,
        chain_name: &str,
        chain: &ChainConfig,
    ) -> Result<(), ConfigError> {
        let has_utxo = chain.private_utxo_address.is_some();
        let has_tee_lock = chain.tee_lock_address.is_some();
        let has_block = chain.deployment_block.is_some();

        // Both or neither contract address must be present.
        if has_utxo != has_tee_lock {
            return Err(ConfigError::Validation(format!(
                "{chain_name}: private_utxo_address and tee_lock_address must both be present or both absent"
            )));
        }

        // If addresses present, deployment_block required.
        if has_utxo && !has_block {
            return Err(ConfigError::Validation(format!(
                "{chain_name}: deployment_block required when contract addresses are provided"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
[sepolia]
rpc_url = "https://rpc.sepolia.org"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"

[layer2]
rpc_url = "https://sepolia-rpc.scroll.io"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"

[alice]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000002"
chain = "sepolia"
amount = 1000

[bob]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000003"
chain = "layer2"
amount = 50

[tee]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000004"

[swap]
timeout = "24h"
"#;
        let config: TestnetConfig = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.alice.chain, Chain::Sepolia);
        assert_eq!(config.bob.chain, Chain::Layer2);
        assert_eq!(config.swap.timeout, Duration::from_secs(86400));
    }

    #[test]
    fn test_same_chain_rejected() {
        let toml = r#"
[sepolia]
rpc_url = "https://rpc.sepolia.org"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"

[layer2]
rpc_url = "https://sepolia-rpc.scroll.io"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"

[alice]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000002"
chain = "sepolia"
amount = 1000

[bob]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000003"
chain = "sepolia"
amount = 50

[tee]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000004"

[swap]
timeout = "24h"
"#;
        let config: TestnetConfig = toml::from_str(toml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("must be different"));
    }

    #[test]
    fn test_missing_tee_keystore_for_local_coordinator() {
        let toml = r#"
[sepolia]
rpc_url = "https://rpc.sepolia.org"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"

[layer2]
rpc_url = "https://sepolia-rpc.scroll.io"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"

[alice]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000002"
chain = "sepolia"
amount = 1000

[bob]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000003"
chain = "layer2"
amount = 50

[swap]
timeout = "24h"
"#;
        let config: TestnetConfig = toml::from_str(toml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("tee.private_key required"));
    }

    #[test]
    fn test_addresses_without_deployment_block() {
        let toml = r#"
[sepolia]
rpc_url = "https://rpc.sepolia.org"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"
private_utxo_address = "0x1234567890123456789012345678901234567890"
tee_lock_address = "0x1234567890123456789012345678901234567891"

[layer2]
rpc_url = "https://sepolia-rpc.scroll.io"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"

[alice]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000002"
chain = "sepolia"
amount = 1000

[bob]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000003"
chain = "layer2"
amount = 50

[tee]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000004"

[swap]
timeout = "24h"
"#;
        let config: TestnetConfig = toml::from_str(toml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("deployment_block required"));
    }

    #[test]
    fn test_external_coordinator_no_tee_keystore_needed() {
        // External coordinator with pre-deployed contracts doesn't need tee_address
        let toml = r#"
[sepolia]
rpc_url = "https://rpc.sepolia.org"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"
deployment_block = 100
private_utxo_address = "0x1234567890123456789012345678901234567890"
tee_lock_address = "0x1234567890123456789012345678901234567891"

[layer2]
rpc_url = "https://sepolia-rpc.scroll.io"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"
deployment_block = 200
private_utxo_address = "0x2234567890123456789012345678901234567890"
tee_lock_address = "0x2234567890123456789012345678901234567891"

[alice]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000002"
chain = "sepolia"
amount = 1000

[bob]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000003"
chain = "layer2"
amount = 50

[coordinator]
url = "https://tee.example.com"

[swap]
timeout = "24h"
"#;
        let config: TestnetConfig = toml::from_str(toml).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn test_external_coordinator_needs_tee_address_for_deploy() {
        // External coordinator + fresh deploy needs tee_address
        let toml = r#"
[sepolia]
rpc_url = "https://rpc.sepolia.org"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"

[layer2]
rpc_url = "https://sepolia-rpc.scroll.io"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"

[alice]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000002"
chain = "sepolia"
amount = 1000

[bob]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000003"
chain = "layer2"
amount = 50

[coordinator]
url = "https://tee.example.com"

[swap]
timeout = "24h"
"#;
        let config: TestnetConfig = toml::from_str(toml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("tee_address required"));
    }

    #[test]
    fn test_external_coordinator_with_tee_address_for_deploy() {
        let toml = r#"
[sepolia]
rpc_url = "https://rpc.sepolia.org"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"

[layer2]
rpc_url = "https://sepolia-rpc.scroll.io"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"

[alice]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000002"
chain = "sepolia"
amount = 1000

[bob]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000003"
chain = "layer2"
amount = 50

[coordinator]
url = "https://tee.example.com"
tee_address = "0x1234567890123456789012345678901234567890"

[swap]
timeout = "24h"
"#;
        let config: TestnetConfig = toml::from_str(toml).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn test_predeployed_contracts_valid() {
        let toml = r#"
[sepolia]
rpc_url = "https://rpc.sepolia.org"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"
deployment_block = 12345
private_utxo_address = "0x1234567890123456789012345678901234567890"
tee_lock_address = "0x1234567890123456789012345678901234567891"

[layer2]
rpc_url = "https://sepolia-rpc.scroll.io"
deployer_private_key = "0xdead000000000000000000000000000000000000000000000000000000000001"

[alice]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000002"
chain = "sepolia"
amount = 1000

[bob]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000003"
chain = "layer2"
amount = 50

[tee]
private_key = "0xdead000000000000000000000000000000000000000000000000000000000004"

[swap]
timeout = "24h"
"#;
        let config: TestnetConfig = toml::from_str(toml).unwrap();
        config.validate().unwrap();
    }
}
