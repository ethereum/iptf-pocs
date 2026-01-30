import { HardhatUserConfig, vars } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@fhevm/hardhat-plugin";

// Optional: Set these for Sepolia deployment
// npx hardhat vars set PRIVATE_KEY
// npx hardhat vars set INFURA_API_KEY
const PRIVATE_KEY = vars.has("PRIVATE_KEY") ? vars.get("PRIVATE_KEY") : "";
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
