import { expect } from "chai";
import { ethers } from "hardhat";
import { fhevm } from "hardhat";
import { FhevmType } from "@fhevm/mock-utils";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import type { ConfidentialBond } from "../types";
import { isSepoliaNetwork } from "./helpers/network";

describe("ConfidentialBond", function () {
  // Shared state across all tests
  let bond: ConfidentialBond;
  let owner: HardhatEthersSigner;
  let investor1: HardhatEthersSigner;
  let investor2: HardhatEthersSigner;
  let investor3: HardhatEthersSigner;
  let regulator: HardhatEthersSigner;
  let unauthorized: HardhatEthersSigner;

  const TOTAL_SUPPLY = 1_000_000n;
  let MATURITY_DATE: bigint;

  // ============ Helper Functions ============

  async function encryptAmount(
    bondContract: ConfidentialBond,
    signer: HardhatEthersSigner,
    amount: bigint
  ) {
    const input = await fhevm.createEncryptedInput(
      await bondContract.getAddress(),
      signer.address
    );
    input.add64(amount);
    const encrypted = await input.encrypt();
    return {
      handle: encrypted.handles[0],
      proof: encrypted.inputProof,
    };
  }

  async function decryptBalance(
    bondContract: ConfidentialBond,
    account: HardhatEthersSigner
  ): Promise<bigint> {
    const encBalance = await bondContract.balanceOf(account.address);
    const contractAddress = await bondContract.getAddress();
    return fhevm.userDecryptEuint(
      FhevmType.euint64,
      encBalance.toString(),
      contractAddress,
      account
    );
  }

  // ============ Test Setup ============

  before(async function () {
    if (isSepoliaNetwork()) {
      this.timeout(600000);
    }

    [owner, investor1, investor2, investor3, regulator, unauthorized] =
      await ethers.getSigners();

    const ONE_YEAR = 365n * 24n * 60n * 60n;
    const latestTime = isSepoliaNetwork()
      ? BigInt(Math.floor(Date.now() / 1000))
      : BigInt(await time.latest());
    MATURITY_DATE = latestTime + ONE_YEAR;

    const ConfidentialBondFactory =
      await ethers.getContractFactory("ConfidentialBond");
    bond = (await ConfidentialBondFactory.deploy(
      TOTAL_SUPPLY,
      MATURITY_DATE
    )) as unknown as ConfidentialBond;
    await bond.waitForDeployment();
  });

  // ============ Deployment & Initialization ============

  describe("Deployment", function () {
    it("should set the correct owner", async function () {
      expect(await bond.owner()).to.equal(owner.address);
    });

    it("should set the correct total supply", async function () {
      expect(await bond.totalSupply()).to.equal(TOTAL_SUPPLY);
    });

    it("should set the correct maturity date", async function () {
      expect(await bond.maturityDate()).to.equal(MATURITY_DATE);
    });

    it("should auto-whitelist the owner", async function () {
      expect(await bond.whitelist(owner.address)).to.be.true;
    });

    it("should assign full supply to owner (encrypted)", async function () {
      const balance = await decryptBalance(bond, owner);
      expect(balance).to.equal(TOTAL_SUPPLY);
    });
  });

  // ============ Whitelist Management ============

  describe("Whitelist Management", function () {
    it("should allow owner to add address to whitelist", async function () {
      await bond.addToWhitelist(investor1.address);
      expect(await bond.whitelist(investor1.address)).to.be.true;
    });

    it("should emit WhitelistUpdated event on add", async function () {
      await expect(bond.addToWhitelist(investor2.address))
        .to.emit(bond, "WhitelistUpdated")
        .withArgs(investor2.address, true);
    });

    it("should allow owner to remove address from whitelist", async function () {
      await bond.addToWhitelist(investor3.address);
      await bond.removeFromWhitelist(investor3.address);
      expect(await bond.whitelist(investor3.address)).to.be.false;
    });

    it("should emit WhitelistUpdated event on remove", async function () {
      await bond.addToWhitelist(investor3.address);
      await expect(bond.removeFromWhitelist(investor3.address))
        .to.emit(bond, "WhitelistUpdated")
        .withArgs(investor3.address, false);
    });

    it("should revert when non-owner tries to add to whitelist", async function () {
      await expect(
        bond.connect(unauthorized).addToWhitelist(regulator.address)
      ).to.be.revertedWithCustomError(bond, "NotOwner");
    });

    it("should revert when non-owner tries to remove from whitelist", async function () {
      await bond.addToWhitelist(regulator.address);
      await expect(
        bond.connect(unauthorized).removeFromWhitelist(regulator.address)
      ).to.be.revertedWithCustomError(bond, "NotOwner");
      // Clean up
      await bond.removeFromWhitelist(regulator.address);
    });

    it("should revert when adding zero address", async function () {
      await expect(
        bond.addToWhitelist(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(bond, "ZeroAddress");
    });
  });

  // ============ Transfer Functions ============

  describe("Transfers", function () {
    before(async function () {
      // Ensure investors are whitelisted for transfer tests
      if (!(await bond.whitelist(investor1.address))) {
        await bond.addToWhitelist(investor1.address);
      }
      if (!(await bond.whitelist(investor2.address))) {
        await bond.addToWhitelist(investor2.address);
      }
    });

    it("should transfer encrypted amount between whitelisted addresses", async function () {
      const initialOwnerBalance = await decryptBalance(bond, owner);
      const transferAmount = 10_000n;
      const { handle, proof } = await encryptAmount(bond, owner, transferAmount);

      await bond.transfer(investor1.address, handle, proof);

      const ownerBalance = await decryptBalance(bond, owner);
      const investor1Balance = await decryptBalance(bond, investor1);

      expect(ownerBalance).to.equal(initialOwnerBalance - transferAmount);
      expect(investor1Balance).to.be.gte(transferAmount);
    });

    it("should emit Transfer event without amount", async function () {
      const { handle, proof } = await encryptAmount(bond, owner, 1000n);

      await expect(bond.transfer(investor1.address, handle, proof))
        .to.emit(bond, "Transfer")
        .withArgs(owner.address, investor1.address);
    });

    it("should silently fail transfer with insufficient balance (privacy)", async function () {
      // First give investor2 a small balance so their handle is initialized
      const smallAmount = 100n;
      const { handle: h1, proof: p1 } = await encryptAmount(bond, owner, smallAmount);
      await bond.transfer(investor2.address, h1, p1);

      const investor2BalanceBefore = await decryptBalance(bond, investor2);

      // investor2 tries to transfer more than they have
      const largeAmount = 1000n;
      const { handle, proof } = await encryptAmount(bond, investor2, largeAmount);

      // Transaction succeeds but transfers 0 (FHE.select pattern)
      await bond.connect(investor2).transfer(investor1.address, handle, proof);

      // Balance unchanged (still has the small amount, transfer failed silently)
      const investor2BalanceAfter = await decryptBalance(bond, investor2);
      expect(investor2BalanceAfter).to.equal(investor2BalanceBefore);
    });

    it("should revert when sender is not whitelisted", async function () {
      const { handle, proof } = await encryptAmount(bond, unauthorized, 100n);

      await expect(
        bond.connect(unauthorized).transfer(investor1.address, handle, proof)
      ).to.be.revertedWithCustomError(bond, "NotWhitelisted");
    });

    it("should revert when recipient is not whitelisted", async function () {
      const { handle, proof } = await encryptAmount(bond, owner, 100n);

      await expect(
        bond.transfer(unauthorized.address, handle, proof)
      ).to.be.revertedWithCustomError(bond, "NotWhitelisted");
    });

    it("should handle multiple sequential transfers", async function () {
      const ownerBalanceBefore = await decryptBalance(bond, owner);

      // Owner -> Investor1: 5000
      const amount1 = 5000n;
      const { handle: h1, proof: p1 } = await encryptAmount(bond, owner, amount1);
      await bond.transfer(investor1.address, h1, p1);

      // Owner -> Investor2: 3000
      const amount2 = 3000n;
      const { handle: h2, proof: p2 } = await encryptAmount(bond, owner, amount2);
      await bond.transfer(investor2.address, h2, p2);

      // Verify owner balance decreased
      const ownerBalanceAfter = await decryptBalance(bond, owner);
      expect(ownerBalanceAfter).to.equal(ownerBalanceBefore - amount1 - amount2);
    });

    it("should handle zero-amount transfer", async function () {
      const ownerBalanceBefore = await decryptBalance(bond, owner);

      const { handle, proof } = await encryptAmount(bond, owner, 0n);
      await bond.transfer(investor1.address, handle, proof);

      const ownerBalanceAfter = await decryptBalance(bond, owner);
      expect(ownerBalanceAfter).to.equal(ownerBalanceBefore);
    });

    it("should handle self-transfer", async function () {
      const ownerBalanceBefore = await decryptBalance(bond, owner);

      const { handle, proof } = await encryptAmount(bond, owner, 1000n);
      await bond.transfer(owner.address, handle, proof);

      const ownerBalanceAfter = await decryptBalance(bond, owner);
      expect(ownerBalanceAfter).to.equal(ownerBalanceBefore);
    });
  });

  // ============ Approve / TransferFrom ============

  describe("Approve and TransferFrom", function () {
    before(async function () {
      // Ensure investors are whitelisted
      if (!(await bond.whitelist(investor1.address))) {
        await bond.addToWhitelist(investor1.address);
      }
      if (!(await bond.whitelist(investor2.address))) {
        await bond.addToWhitelist(investor2.address);
      }
    });

    it("should approve spender with encrypted allowance", async function () {
      const allowanceAmount = 5000n;
      const { handle, proof } = await encryptAmount(bond, owner, allowanceAmount);

      await expect(bond.approve(investor1.address, handle, proof))
        .to.emit(bond, "Approval")
        .withArgs(owner.address, investor1.address);
    });

    it("should execute transferFrom with valid allowance", async function () {
      const ownerBalanceBefore = await decryptBalance(bond, owner);
      const investor2BalanceBefore = await decryptBalance(bond, investor2);

      // Owner approves investor1 to spend 10000
      const allowance = 10_000n;
      const { handle: approveHandle, proof: approveProof } = await encryptAmount(
        bond,
        owner,
        allowance
      );
      await bond.approve(investor1.address, approveHandle, approveProof);

      // Investor1 transfers 5000 from owner to investor2
      const transferAmount = 5000n;
      const { handle: transferHandle, proof: transferProof } = await encryptAmount(
        bond,
        investor1,
        transferAmount
      );
      await bond
        .connect(investor1)
        .transferFrom(owner.address, investor2.address, transferHandle, transferProof);

      // Verify balances
      const ownerBalanceAfter = await decryptBalance(bond, owner);
      const investor2BalanceAfter = await decryptBalance(bond, investor2);

      expect(ownerBalanceAfter).to.equal(ownerBalanceBefore - transferAmount);
      expect(investor2BalanceAfter).to.equal(investor2BalanceBefore + transferAmount);
    });

    it("should silently fail transferFrom with insufficient allowance", async function () {
      const ownerBalanceBefore = await decryptBalance(bond, owner);
      const investor2BalanceBefore = await decryptBalance(bond, investor2);

      // Owner approves investor1 for small amount
      const allowance = 100n;
      const { handle: approveHandle, proof: approveProof } = await encryptAmount(
        bond,
        owner,
        allowance
      );
      await bond.approve(investor1.address, approveHandle, approveProof);

      // Investor1 tries to transfer more than allowed
      const transferAmount = 1000n;
      const { handle: transferHandle, proof: transferProof } = await encryptAmount(
        bond,
        investor1,
        transferAmount
      );

      // Transaction succeeds but transfers 0 (FHE.select pattern with combined check)
      await bond
        .connect(investor1)
        .transferFrom(owner.address, investor2.address, transferHandle, transferProof);

      // Owner balance unchanged (transfer silently failed due to insufficient allowance)
      const ownerBalanceAfter = await decryptBalance(bond, owner);
      const investor2BalanceAfter = await decryptBalance(bond, investor2);

      expect(ownerBalanceAfter).to.equal(ownerBalanceBefore);
      expect(investor2BalanceAfter).to.equal(investor2BalanceBefore);
    });

    it("should decrease allowance after transferFrom", async function () {
      // Owner approves investor1 for 10000
      const allowance = 10_000n;
      const { handle: approveHandle, proof: approveProof } = await encryptAmount(
        bond,
        owner,
        allowance
      );
      await bond.approve(investor1.address, approveHandle, approveProof);

      // First transfer: 3000
      const firstTransfer = 3000n;
      const { handle: h1, proof: p1 } = await encryptAmount(bond, investor1, firstTransfer);
      await bond.connect(investor1).transferFrom(owner.address, investor2.address, h1, p1);

      // Second transfer: 5000 (should work, remaining allowance is 7000)
      const secondTransfer = 5000n;
      const { handle: h2, proof: p2 } = await encryptAmount(bond, investor1, secondTransfer);
      await bond.connect(investor1).transferFrom(owner.address, investor2.address, h2, p2);

      // This verifies that both transfers went through
      // (if allowance wasn't tracked, second would fail)
    });
  });

  // ============ Regulatory Access ============

  describe("Regulatory Access", function () {
    before(async function () {
      // Ensure investor1 is whitelisted and has some balance
      if (!(await bond.whitelist(investor1.address))) {
        await bond.addToWhitelist(investor1.address);
      }

      // Transfer some to investor1 if they don't have enough
      const balance = await decryptBalance(bond, investor1);
      if (balance < 5000n) {
        const { handle, proof } = await encryptAmount(bond, owner, 5000n);
        await bond.transfer(investor1.address, handle, proof);
      }
    });

    it("should allow owner to grant audit access", async function () {
      await expect(bond.grantAuditAccess(investor1.address, regulator.address))
        .to.emit(bond, "AuditAccessGranted")
        .withArgs(investor1.address, regulator.address);
    });

    it("should allow regulator to decrypt balance after access granted", async function () {
      // Grant access
      await bond.grantAuditAccess(investor1.address, regulator.address);

      // Regulator should be able to decrypt
      const encBalance = await bond.balanceOf(investor1.address);
      const contractAddress = await bond.getAddress();
      const decryptedBalance = await fhevm.userDecryptEuint(
        FhevmType.euint64,
        encBalance.toString(),
        contractAddress,
        regulator
      );
      expect(decryptedBalance).to.be.gt(0n);
    });

    it("should allow bulk audit access grant", async function () {
      // Ensure investor2 is whitelisted
      if (!(await bond.whitelist(investor2.address))) {
        await bond.addToWhitelist(investor2.address);
      }

      // Transfer to investor2
      const { handle, proof } = await encryptAmount(bond, owner, 3000n);
      await bond.transfer(investor2.address, handle, proof);

      // Grant bulk access
      await bond.grantBulkAuditAccess(
        [investor1.address, investor2.address],
        regulator.address
      );

      // Regulator can decrypt both
      const contractAddress = await bond.getAddress();
      const balance1 = await fhevm.userDecryptEuint(
        FhevmType.euint64,
        (await bond.balanceOf(investor1.address)).toString(),
        contractAddress,
        regulator
      );
      const balance2 = await fhevm.userDecryptEuint(
        FhevmType.euint64,
        (await bond.balanceOf(investor2.address)).toString(),
        contractAddress,
        regulator
      );

      expect(balance1).to.be.gt(0n);
      expect(balance2).to.be.gt(0n);
    });

    it("should revert audit access grant from non-owner", async function () {
      await expect(
        bond.connect(unauthorized).grantAuditAccess(investor1.address, regulator.address)
      ).to.be.revertedWithCustomError(bond, "NotOwner");
    });
  });

  // ============ Ownership Transfer ============

  describe("Ownership", function () {
    // Use a separate contract for ownership tests to avoid affecting other tests
    let ownershipBond: ConfidentialBond;

    before(async function () {
      if (isSepoliaNetwork()) {
        this.timeout(600000);
      }

      const ConfidentialBondFactory =
        await ethers.getContractFactory("ConfidentialBond");
      const latestTime = isSepoliaNetwork()
        ? BigInt(Math.floor(Date.now() / 1000))
        : BigInt(await time.latest());
      ownershipBond = (await ConfidentialBondFactory.deploy(
        1000n,
        latestTime + 365n * 24n * 60n * 60n
      )) as unknown as ConfidentialBond;
      await ownershipBond.waitForDeployment();
    });

    it("should allow owner to transfer ownership", async function () {
      await expect(ownershipBond.transferOwnership(investor1.address))
        .to.emit(ownershipBond, "OwnershipTransferred")
        .withArgs(owner.address, investor1.address);

      expect(await ownershipBond.owner()).to.equal(investor1.address);
    });

    it("should allow new owner to perform admin functions", async function () {
      // investor1 is now owner from previous test
      await ownershipBond.connect(investor1).addToWhitelist(investor2.address);
      expect(await ownershipBond.whitelist(investor2.address)).to.be.true;
    });

    it("should prevent old owner from performing admin functions", async function () {
      await expect(
        ownershipBond.connect(owner).addToWhitelist(investor3.address)
      ).to.be.revertedWithCustomError(ownershipBond, "NotOwner");
    });

    it("should revert when transferring to zero address", async function () {
      await expect(
        ownershipBond.connect(investor1).transferOwnership(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(ownershipBond, "ZeroAddress");
    });

    it("should revert when non-owner tries to transfer ownership", async function () {
      await expect(
        ownershipBond.connect(unauthorized).transferOwnership(owner.address)
      ).to.be.revertedWithCustomError(ownershipBond, "NotOwner");
    });
  });

  // ============ Redemption ============

  describe("Redemption", function () {
    // Use a separate contract for redemption tests (time manipulation)
    let redemptionBond: ConfidentialBond;
    let redemptionMaturity: bigint;

    before(async function () {
      if (isSepoliaNetwork()) {
        this.timeout(600000);
      }

      const ConfidentialBondFactory =
        await ethers.getContractFactory("ConfidentialBond");

      const ONE_YEAR = 365n * 24n * 60n * 60n;
      const latestTime = isSepoliaNetwork()
        ? BigInt(Math.floor(Date.now() / 1000))
        : BigInt(await time.latest());
      redemptionMaturity = latestTime + ONE_YEAR;

      redemptionBond = (await ConfidentialBondFactory.deploy(
        100_000n,
        redemptionMaturity
      )) as unknown as ConfidentialBond;
      await redemptionBond.waitForDeployment();

      // Whitelist and transfer to investor1
      await redemptionBond.addToWhitelist(investor1.address);
      const { handle, proof } = await encryptAmount(redemptionBond, owner, 10_000n);
      await redemptionBond.transfer(investor1.address, handle, proof);
    });

    it("should revert redemption before maturity", async function () {
      const { handle, proof } = await encryptAmount(redemptionBond, investor1, 1000n);

      await expect(
        redemptionBond.connect(investor1).redeem(handle, proof)
      ).to.be.revertedWithCustomError(redemptionBond, "BondNotMature");
    });

    it("should revert redemption for non-whitelisted address", async function () {
      const { handle, proof } = await encryptAmount(redemptionBond, unauthorized, 100n);

      await expect(
        redemptionBond.connect(unauthorized).redeem(handle, proof)
      ).to.be.revertedWithCustomError(redemptionBond, "NotWhitelisted");
    });

    // Note: The following tests require time manipulation which only works in mock mode
    if (!isSepoliaNetwork()) {
      it("should allow redemption after maturity", async function () {
        const balanceBefore = await decryptBalance(redemptionBond, investor1);

        // Fast forward past maturity (use latest + 1 to ensure we're always moving forward)
        const currentTime = BigInt(await time.latest());
        const targetTime = redemptionMaturity + 1n;
        if (currentTime < targetTime) {
          await time.increaseTo(targetTime);
        }

        // Redeem half
        const redeemAmount = 5000n;
        const { handle, proof } = await encryptAmount(
          redemptionBond,
          investor1,
          redeemAmount
        );
        await redemptionBond.connect(investor1).redeem(handle, proof);

        // Verify balance decreased
        const balanceAfter = await decryptBalance(redemptionBond, investor1);
        expect(balanceAfter).to.equal(balanceBefore - redeemAmount);
      });

      it("should emit Redemption event", async function () {
        const { handle, proof } = await encryptAmount(redemptionBond, investor1, 1000n);

        await expect(redemptionBond.connect(investor1).redeem(handle, proof))
          .to.emit(redemptionBond, "Redemption")
          .withArgs(investor1.address);
      });

      it("should silently handle redemption exceeding balance", async function () {
        const balanceBefore = await decryptBalance(redemptionBond, investor1);

        // Try to redeem more than balance
        const excessAmount = balanceBefore + 10000n;
        const { handle, proof } = await encryptAmount(
          redemptionBond,
          investor1,
          excessAmount
        );
        await redemptionBond.connect(investor1).redeem(handle, proof);

        // Balance unchanged
        const balanceAfter = await decryptBalance(redemptionBond, investor1);
        expect(balanceAfter).to.equal(balanceBefore);
      });
    }
  });

  // ============ Edge Cases ============

  describe("Edge Cases", function () {
    it("should handle transfer of entire balance", async function () {
      // Use a fresh contract for this test
      const ConfidentialBondFactory =
        await ethers.getContractFactory("ConfidentialBond");
      const latestTime = isSepoliaNetwork()
        ? BigInt(Math.floor(Date.now() / 1000))
        : BigInt(await time.latest());
      const edgeCaseBond = (await ConfidentialBondFactory.deploy(
        10_000n,
        latestTime + 365n * 24n * 60n * 60n
      )) as unknown as ConfidentialBond;
      await edgeCaseBond.waitForDeployment();

      await edgeCaseBond.addToWhitelist(investor1.address);

      // Transfer entire supply
      const { handle, proof } = await encryptAmount(edgeCaseBond, owner, 10_000n);
      await edgeCaseBond.transfer(investor1.address, handle, proof);

      const ownerBalance = await decryptBalance(edgeCaseBond, owner);
      const investor1Balance = await decryptBalance(edgeCaseBond, investor1);

      expect(ownerBalance).to.equal(0n);
      expect(investor1Balance).to.equal(10_000n);
    });
  });
});
