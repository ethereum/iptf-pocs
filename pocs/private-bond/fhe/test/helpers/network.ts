import hre from "hardhat";
import type { ContractTransactionResponse } from "ethers";

export function isSepoliaNetwork(): boolean {
  return hre.network.name === "sepolia";
}

export function isMockNetwork(): boolean {
  return hre.network.name === "hardhat";
}

export async function waitForTx(tx: ContractTransactionResponse) {
  const receipt = await tx.wait();
  if (isSepoliaNetwork()) {
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }
  return receipt;
}
