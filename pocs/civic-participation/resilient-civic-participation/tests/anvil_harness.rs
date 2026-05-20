//! Anvil harness: spawns anvil + `forge script Deploy.s.sol --broadcast`.

use std::{
    path::PathBuf,
    process::Command,
};

use alloy::{
    network::EthereumWallet,
    node_bindings::{
        Anvil,
        AnvilInstance,
    },
    primitives::Address as AlloyAddress,
    providers::{
        DynProvider,
        Provider,
        ProviderBuilder,
    },
    signers::local::PrivateKeySigner,
};
use resilient_civic_participation::{
    imt::IndexedMerkleTree,
    poseidon::fr_to_be_bytes,
};

/// Anvil's first prefunded account.
const DEPLOYER_PK: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

pub struct AnvilDeployment {
    /// Held so anvil stays alive; dropping it kills the process.
    pub _anvil_guard: AnvilInstance,
    pub endpoint: String,
    pub deployer_addr: AlloyAddress,
    pub provider: DynProvider,
    pub bounty_token: AlloyAddress,
    pub petition_registry: AlloyAddress,
}

impl AnvilDeployment {
    pub fn start_and_deploy(use_mock_verifier: bool) -> Self {
        // Raise EIP-170 limit so the ~25KiB bb Honk verifier deploys.
        let anvil = Anvil::new()
            .arg("--hardfork")
            .arg("cancun")
            .arg("--code-size-limit")
            .arg("65536")
            .spawn();
        let endpoint = anvil.endpoint();

        let signer: PrivateKeySigner = DEPLOYER_PK.parse().unwrap();
        let deployer_addr = signer.address();
        let wallet = EthereumWallet::from(signer);

        let provider = ProviderBuilder::new()
            .with_simple_nonce_management()
            .wallet(wallet)
            .connect_http(anvil.endpoint_url())
            .erased();

        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let deployments_path = project_root.join("deployments.toml");
        let _deployments_guard = DeploymentsBackup::new(deployments_path.clone());

        let use_mock_str = if use_mock_verifier { "true" } else { "false" };
        let empty_imt_root = {
            let imt = IndexedMerkleTree::new();
            fr_to_be_bytes(&imt.root_fr())
        };
        let empty_imt_root_hex = format!("0x{}", hex::encode(empty_imt_root));

        // Read signer VK hash from generate-verifiers.sh output.
        let signer_vk_hash_path = project_root
            .join("circuits")
            .join("signer")
            .join("target")
            .join("vk_hash");
        let signer_vk_hash_bytes = std::fs::read(&signer_vk_hash_path).unwrap_or_else(|e| {
            panic!(
                "read signer vk_hash from {}: {e}. Run scripts/generate-verifiers.sh first.",
                signer_vk_hash_path.display()
            )
        });
        let signer_vk_hash_hex = format!("0x{}", hex::encode(&signer_vk_hash_bytes));

        let out = Command::new("forge")
            .args([
                "script",
                "contracts/script/Deploy.s.sol:Deploy",
                "--rpc-url",
                &endpoint,
                "--private-key",
                DEPLOYER_PK,
                "--broadcast",
                "--disable-code-size-limit",
            ])
            .env("USE_MOCK_VERIFIER", use_mock_str)
            .env("GOVERNANCE", format!("{deployer_addr:#x}"))
            .env("EMPTY_IMT_ROOT", &empty_imt_root_hex)
            .env("PINNED_SIGNER_VK_HASH", &signer_vk_hash_hex)
            .current_dir(&project_root)
            .output()
            .expect("spawn forge script");

        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() {
            panic!("forge script failed:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}");
        }
        let blob = format!("{stdout}\n{stderr}");

        AnvilDeployment {
            _anvil_guard: anvil,
            endpoint,
            deployer_addr,
            provider,
            bounty_token: parse_addr(&blob, "MockERC20:"),
            petition_registry: parse_addr(&blob, "PetitionRegistry:"),
        }
    }
}

/// RAII guard that restores `deployments.toml` on drop, including panic paths.
/// The forge script overwrites the file in place; we want every exit path
/// (Ok, Err, panic) to return it to its committed state.
struct DeploymentsBackup {
    path: PathBuf,
    original: String,
}

impl DeploymentsBackup {
    fn new(path: PathBuf) -> Self {
        let original = std::fs::read_to_string(&path).expect("read deployments.toml");
        Self { path, original }
    }
}

impl Drop for DeploymentsBackup {
    fn drop(&mut self) {
        if let Err(e) = std::fs::write(&self.path, &self.original) {
            eprintln!(
                "DeploymentsBackup: failed to restore {}: {e}",
                self.path.display()
            );
        }
    }
}

fn parse_addr(blob: &str, label: &str) -> AlloyAddress {
    for line in blob.lines() {
        if let Some(rest) = line.trim().strip_prefix(label)
            && let Ok(a) = rest.trim().parse::<AlloyAddress>()
        {
            return a;
        }
    }
    panic!("Could not parse address `{label}` from forge output:\n{blob}");
}
