import { HardhatUserConfig, vars } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@fhevm/hardhat-plugin";
import { HDNodeWallet } from "ethers";

// Optional: Set these for Sepolia deployment
// npx hardhat vars set MNEMONIC (or PRIVATE_KEY)
// npx hardhat vars set INFURA_API_KEY
// npx hardhat vars set ZAMA_FHEVM_API_KEY
function getPrivateKey(): string {
  if (vars.has("PRIVATE_KEY")) {
    return vars.get("PRIVATE_KEY");
  }
  if (vars.has("MNEMONIC")) {
    const value = vars.get("MNEMONIC");
    // Check if it's a hex private key (64 chars or 66 with 0x prefix)
    if (value.startsWith("0x") || /^[a-fA-F0-9]{64}$/.test(value)) {
      return value.startsWith("0x") ? value : `0x${value}`;
    }
    // Otherwise treat as mnemonic phrase
    const wallet = HDNodeWallet.fromPhrase(value);
    return wallet.privateKey;
  }
  return "";
}

const PRIVATE_KEY = getPrivateKey();
const INFURA_API_KEY = vars.has("INFURA_API_KEY")
  ? vars.get("INFURA_API_KEY")
  : "";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.27",
    settings: {
      evmVersion: "cancun",
      optimizer: {
        enabled: true,
        runs: 800,
      },
      metadata: {
        bytecodeHash: "none",
      },
    },
  },
  networks: {
    hardhat: {
      chainId: 31337,
    },
    sepolia: {
      chainId: 11155111,
      url: `https://sepolia.infura.io/v3/${INFURA_API_KEY}`,
      accounts: PRIVATE_KEY ? [PRIVATE_KEY] : [],
      gas: 5_000_000,
      gasPrice: "auto",
      timeout: 300000,
    },
  },
  mocha: {
    timeout: 600000,
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS !== undefined,
  },
  typechain: {
    outDir: "types",
    target: "ethers-v6",
  },
};

export default config;
