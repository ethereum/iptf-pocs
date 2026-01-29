import { expect } from "chai";
import { ethers } from "hardhat";
import { fhevm } from "hardhat";
import { FhevmType } from "@fhevm/mock-utils";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";
import type { ConfidentialBond } from "../types";

describe("ConfidentialBond", function () {
  // ============ Test Fixture ============

  async function deployBondFixture() {
    const [owner, investor1, investor2, investor3, regulator, unauthorized] =
      await ethers.getSigners();

    const TOTAL_SUPPLY = 1_000_000n;
    const ONE_YEAR = 365n * 24n * 60n * 60n;
    const MATURITY_DATE = BigInt(await time.latest()) + ONE_YEAR;

    const ConfidentialBondFactory = await ethers.getContractFactory("ConfidentialBond");
    const bond = (await ConfidentialBondFactory.deploy(
      TOTAL_SUPPLY,
      MATURITY_DATE
    )) as unknown as ConfidentialBond;
    await bond.waitForDeployment();

    return {
      bond,
      owner,
      investor1,
      investor2,
      investor3,
      regulator,
      unauthorized,
      TOTAL_SUPPLY,
      MATURITY_DATE,
    };
  }

  // ============ Helper Functions ============

  /**
   * Create an encrypted input for a uint64 value
   */
  async function encryptAmount(
    bond: ConfidentialBond,
    signer: HardhatEthersSigner,
    amount: bigint
  ) {
    const input = await fhevm.createEncryptedInput(
      await bond.getAddress(),
      signer.address
    );
    input.add64(amount);
    const encrypted = await input.encrypt();
    return {
      handle: encrypted.handles[0],
      proof: encrypted.inputProof,
    };
  }

  /**
   * Decrypt a user's balance
   */
  async function decryptBalance(
    bond: ConfidentialBond,
    account: HardhatEthersSigner
  ): Promise<bigint> {
    const encBalance = await bond.balanceOf(account.address);
    const contractAddress = await bond.getAddress();
    return fhevm.userDecryptEuint(
      FhevmType.euint64,
      encBalance.toString(),
      contractAddress,
      account
    );
  }

  // ============ Deployment & Initialization ============

  describe("Deployment", function () {
    it("should set the correct owner", async function () {
      const { bond, owner } = await loadFixture(deployBondFixture);
      expect(await bond.owner()).to.equal(owner.address);
    });

    it("should set the correct total supply", async function () {
      const { bond, TOTAL_SUPPLY } = await loadFixture(deployBondFixture);
      expect(await bond.totalSupply()).to.equal(TOTAL_SUPPLY);
    });

    it("should set the correct maturity date", async function () {
      const { bond, MATURITY_DATE } = await loadFixture(deployBondFixture);
      expect(await bond.maturityDate()).to.equal(MATURITY_DATE);
    });

    it("should auto-whitelist the owner", async function () {
      const { bond, owner } = await loadFixture(deployBondFixture);
      expect(await bond.whitelist(owner.address)).to.be.true;
    });

    it("should assign full supply to owner (encrypted)", async function () {
      const { bond, owner, TOTAL_SUPPLY } = await loadFixture(deployBondFixture);
      const balance = await decryptBalance(bond, owner);
      expect(balance).to.equal(TOTAL_SUPPLY);
    });
  });

  // ============ Whitelist Management ============

  describe("Whitelist Management", function () {
    it("should allow owner to add address to whitelist", async function () {
      const { bond, investor1 } = await loadFixture(deployBondFixture);

      await bond.addToWhitelist(investor1.address);
      expect(await bond.whitelist(investor1.address)).to.be.true;
    });

    it("should emit WhitelistUpdated event on add", async function () {
      const { bond, investor1 } = await loadFixture(deployBondFixture);

      await expect(bond.addToWhitelist(investor1.address))
        .to.emit(bond, "WhitelistUpdated")
        .withArgs(investor1.address, true);
    });

    it("should allow owner to remove address from whitelist", async function () {
      const { bond, investor1 } = await loadFixture(deployBondFixture);

      await bond.addToWhitelist(investor1.address);
      await bond.removeFromWhitelist(investor1.address);
      expect(await bond.whitelist(investor1.address)).to.be.false;
    });

    it("should emit WhitelistUpdated event on remove", async function () {
      const { bond, investor1 } = await loadFixture(deployBondFixture);

      await bond.addToWhitelist(investor1.address);
      await expect(bond.removeFromWhitelist(investor1.address))
        .to.emit(bond, "WhitelistUpdated")
        .withArgs(investor1.address, false);
    });

    it("should revert when non-owner tries to add to whitelist", async function () {
      const { bond, investor1, unauthorized } = await loadFixture(deployBondFixture);

      await expect(
        bond.connect(unauthorized).addToWhitelist(investor1.address)
      ).to.be.revertedWithCustomError(bond, "NotOwner");
    });

    it("should revert when non-owner tries to remove from whitelist", async function () {
      const { bond, investor1, unauthorized } = await loadFixture(deployBondFixture);

      await bond.addToWhitelist(investor1.address);
      await expect(
        bond.connect(unauthorized).removeFromWhitelist(investor1.address)
      ).to.be.revertedWithCustomError(bond, "NotOwner");
    });

    it("should revert when adding zero address", async function () {
      const { bond } = await loadFixture(deployBondFixture);

      await expect(
        bond.addToWhitelist(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(bond, "ZeroAddress");
    });
  });

  // ============ Transfer Functions ============

  describe("Transfers", function () {
    it("should transfer encrypted amount between whitelisted addresses", async function () {
      const { bond, owner, investor1, TOTAL_SUPPLY } = await loadFixture(
        deployBondFixture
      );

      // Whitelist investor
      await bond.addToWhitelist(investor1.address);

      // Transfer 10,000 bonds
      const transferAmount = 10_000n;
      const { handle, proof } = await encryptAmount(bond, owner, transferAmount);

      await bond.transfer(investor1.address, handle, proof);

      // Verify balances
      const ownerBalance = await decryptBalance(bond, owner);
      const investor1Balance = await decryptBalance(bond, investor1);

      expect(ownerBalance).to.equal(TOTAL_SUPPLY - transferAmount);
      expect(investor1Balance).to.equal(transferAmount);
    });

    it("should emit Transfer event without amount", async function () {
      const { bond, owner, investor1 } = await loadFixture(deployBondFixture);

      await bond.addToWhitelist(investor1.address);
      const { handle, proof } = await encryptAmount(bond, owner, 1000n);

      await expect(bond.transfer(investor1.address, handle, proof))
        .to.emit(bond, "Transfer")
        .withArgs(owner.address, investor1.address);
    });

    it("should silently fail transfer with insufficient balance (privacy)", async function () {
      const { bond, owner, investor1, investor2 } = await loadFixture(
        deployBondFixture
      );

      await bond.addToWhitelist(investor1.address);
      await bond.addToWhitelist(investor2.address);

      // Transfer small amount to investor1
      const smallAmount = 100n;
      const { handle: h1, proof: p1 } = await encryptAmount(bond, owner, smallAmount);
      await bond.transfer(investor1.address, h1, p1);

      // Investor1 tries to transfer more than they have
      const largeAmount = 1000n;
      const { handle: h2, proof: p2 } = await encryptAmount(
        bond,
        investor1,
        largeAmount
      );

      // Transaction succeeds but transfers 0 (FHE.select pattern)
      await bond.connect(investor1).transfer(investor2.address, h2, p2);

      // Verify investor1 still has their balance (transfer was effectively 0)
      const investor1Balance = await decryptBalance(bond, investor1);
      expect(investor1Balance).to.equal(smallAmount);

      // Investor2 received nothing
      const investor2Balance = await decryptBalance(bond, investor2);
      expect(investor2Balance).to.equal(0n);
    });

    it("should revert when sender is not whitelisted", async function () {
      const { bond, investor1, investor2 } = await loadFixture(deployBondFixture);

      // Only whitelist investor2 (recipient)
      await bond.addToWhitelist(investor2.address);

      const { handle, proof } = await encryptAmount(bond, investor1, 100n);

      await expect(
        bond.connect(investor1).transfer(investor2.address, handle, proof)
      ).to.be.revertedWithCustomError(bond, "NotWhitelisted");
    });

    it("should revert when recipient is not whitelisted", async function () {
      const { bond, owner, investor1 } = await loadFixture(deployBondFixture);

      // investor1 is not whitelisted
      const { handle, proof } = await encryptAmount(bond, owner, 100n);

      await expect(
        bond.transfer(investor1.address, handle, proof)
      ).to.be.revertedWithCustomError(bond, "NotWhitelisted");
    });

    it("should handle multiple sequential transfers", async function () {
      const { bond, owner, investor1, investor2, TOTAL_SUPPLY } = await loadFixture(
        deployBondFixture
      );

      await bond.addToWhitelist(investor1.address);
      await bond.addToWhitelist(investor2.address);

      // Owner -> Investor1: 5000
      const amount1 = 5000n;
      const { handle: h1, proof: p1 } = await encryptAmount(bond, owner, amount1);
      await bond.transfer(investor1.address, h1, p1);

      // Owner -> Investor2: 3000
      const amount2 = 3000n;
      const { handle: h2, proof: p2 } = await encryptAmount(bond, owner, amount2);
      await bond.transfer(investor2.address, h2, p2);

      // Investor1 -> Investor2: 2000
      const amount3 = 2000n;
      const { handle: h3, proof: p3 } = await encryptAmount(bond, investor1, amount3);
      await bond.connect(investor1).transfer(investor2.address, h3, p3);

      // Verify final balances
      expect(await decryptBalance(bond, owner)).to.equal(
        TOTAL_SUPPLY - amount1 - amount2
      );
      expect(await decryptBalance(bond, investor1)).to.equal(amount1 - amount3);
      expect(await decryptBalance(bond, investor2)).to.equal(amount2 + amount3);
    });
  });

  // ============ Approve / TransferFrom ============

  describe("Approve and TransferFrom", function () {
    it("should approve spender with encrypted allowance", async function () {
      const { bond, owner, investor1 } = await loadFixture(deployBondFixture);

      const allowanceAmount = 5000n;
      const { handle, proof } = await encryptAmount(bond, owner, allowanceAmount);

      await expect(bond.approve(investor1.address, handle, proof))
        .to.emit(bond, "Approval")
        .withArgs(owner.address, investor1.address);
    });

    it("should execute transferFrom with valid allowance", async function () {
      const { bond, owner, investor1, investor2, TOTAL_SUPPLY } = await loadFixture(
        deployBondFixture
      );

      await bond.addToWhitelist(investor1.address);
      await bond.addToWhitelist(investor2.address);

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
      expect(await decryptBalance(bond, owner)).to.equal(TOTAL_SUPPLY - transferAmount);
      expect(await decryptBalance(bond, investor2)).to.equal(transferAmount);
    });

    it("should silently fail transferFrom with insufficient allowance", async function () {
      const { bond, owner, investor1, investor2, TOTAL_SUPPLY } = await loadFixture(
        deployBondFixture
      );

      await bond.addToWhitelist(investor1.address);
      await bond.addToWhitelist(investor2.address);

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

      // Transaction succeeds but transfers 0
      await bond
        .connect(investor1)
        .transferFrom(owner.address, investor2.address, transferHandle, transferProof);

      // Owner still has full balance
      expect(await decryptBalance(bond, owner)).to.equal(TOTAL_SUPPLY);
      // Investor2 received nothing
      expect(await decryptBalance(bond, investor2)).to.equal(0n);
    });

    it("should decrease allowance after transferFrom", async function () {
      const { bond, owner, investor1, investor2 } = await loadFixture(
        deployBondFixture
      );

      await bond.addToWhitelist(investor1.address);
      await bond.addToWhitelist(investor2.address);

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

      // Investor2 should have 8000 total
      expect(await decryptBalance(bond, investor2)).to.equal(firstTransfer + secondTransfer);
    });
  });

  // ============ Redemption ============

  describe("Redemption", function () {
    it("should allow redemption after maturity", async function () {
      const { bond, owner, investor1, MATURITY_DATE } = await loadFixture(
        deployBondFixture
      );

      await bond.addToWhitelist(investor1.address);

      // Transfer some bonds to investor
      const bondAmount = 10_000n;
      const { handle: transferHandle, proof: transferProof } = await encryptAmount(
        bond,
        owner,
        bondAmount
      );
      await bond.transfer(investor1.address, transferHandle, transferProof);

      // Fast forward past maturity
      await time.increaseTo(MATURITY_DATE + 1n);

      // Redeem half
      const redeemAmount = 5000n;
      const { handle: redeemHandle, proof: redeemProof } = await encryptAmount(
        bond,
        investor1,
        redeemAmount
      );
      await bond.connect(investor1).redeem(redeemHandle, redeemProof);

      // Verify balance decreased
      expect(await decryptBalance(bond, investor1)).to.equal(bondAmount - redeemAmount);
    });

    it("should emit Redemption event", async function () {
      const { bond, owner, investor1, MATURITY_DATE } = await loadFixture(
        deployBondFixture
      );

      await bond.addToWhitelist(investor1.address);

      const bondAmount = 1000n;
      const { handle: transferHandle, proof: transferProof } = await encryptAmount(
        bond,
        owner,
        bondAmount
      );
      await bond.transfer(investor1.address, transferHandle, transferProof);

      await time.increaseTo(MATURITY_DATE + 1n);

      const { handle: redeemHandle, proof: redeemProof } = await encryptAmount(
        bond,
        investor1,
        bondAmount
      );

      await expect(bond.connect(investor1).redeem(redeemHandle, redeemProof))
        .to.emit(bond, "Redemption")
        .withArgs(investor1.address);
    });

    it("should revert redemption before maturity", async function () {
      const { bond, owner, investor1 } = await loadFixture(deployBondFixture);

      await bond.addToWhitelist(investor1.address);

      const bondAmount = 1000n;
      const { handle: transferHandle, proof: transferProof } = await encryptAmount(
        bond,
        owner,
        bondAmount
      );
      await bond.transfer(investor1.address, transferHandle, transferProof);

      const { handle: redeemHandle, proof: redeemProof } = await encryptAmount(
        bond,
        investor1,
        bondAmount
      );

      await expect(
        bond.connect(investor1).redeem(redeemHandle, redeemProof)
      ).to.be.revertedWithCustomError(bond, "BondNotMature");
    });

    it("should revert redemption for non-whitelisted address", async function () {
      const { bond, unauthorized, MATURITY_DATE } = await loadFixture(deployBondFixture);

      await time.increaseTo(MATURITY_DATE + 1n);

      const { handle, proof } = await encryptAmount(bond, unauthorized, 100n);

      await expect(
        bond.connect(unauthorized).redeem(handle, proof)
      ).to.be.revertedWithCustomError(bond, "NotWhitelisted");
    });

    it("should silently handle redemption exceeding balance", async function () {
      const { bond, owner, investor1, MATURITY_DATE } = await loadFixture(
        deployBondFixture
      );

      await bond.addToWhitelist(investor1.address);

      const bondAmount = 1000n;
      const { handle: transferHandle, proof: transferProof } = await encryptAmount(
        bond,
        owner,
        bondAmount
      );
      await bond.transfer(investor1.address, transferHandle, transferProof);

      await time.increaseTo(MATURITY_DATE + 1n);

      // Try to redeem more than balance
      const excessAmount = 5000n;
      const { handle: redeemHandle, proof: redeemProof } = await encryptAmount(
        bond,
        investor1,
        excessAmount
      );
      await bond.connect(investor1).redeem(redeemHandle, redeemProof);

      // Balance should remain unchanged (redeem was effectively 0)
      expect(await decryptBalance(bond, investor1)).to.equal(bondAmount);
    });
  });

  // ============ Regulatory Access ============

  describe("Regulatory Access", function () {
    it("should allow owner to grant audit access", async function () {
      const { bond, owner, investor1, regulator } = await loadFixture(deployBondFixture);

      await bond.addToWhitelist(investor1.address);

      // Transfer to investor
      const { handle, proof } = await encryptAmount(bond, owner, 5000n);
      await bond.transfer(investor1.address, handle, proof);

      // Grant regulator access to investor1's balance
      await expect(bond.grantAuditAccess(investor1.address, regulator.address))
        .to.emit(bond, "AuditAccessGranted")
        .withArgs(investor1.address, regulator.address);
    });

    it("should allow regulator to decrypt balance after access granted", async function () {
      const { bond, owner, investor1, regulator } = await loadFixture(deployBondFixture);

      await bond.addToWhitelist(investor1.address);

      const transferAmount = 7500n;
      const { handle, proof } = await encryptAmount(bond, owner, transferAmount);
      await bond.transfer(investor1.address, handle, proof);

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
      expect(decryptedBalance).to.equal(transferAmount);
    });

    it("should allow bulk audit access grant", async function () {
      const { bond, owner, investor1, investor2, regulator } = await loadFixture(
        deployBondFixture
      );

      await bond.addToWhitelist(investor1.address);
      await bond.addToWhitelist(investor2.address);

      // Transfer to both investors
      const amount1 = 5000n;
      const amount2 = 3000n;
      const { handle: h1, proof: p1 } = await encryptAmount(bond, owner, amount1);
      const { handle: h2, proof: p2 } = await encryptAmount(bond, owner, amount2);
      await bond.transfer(investor1.address, h1, p1);
      await bond.transfer(investor2.address, h2, p2);

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

      expect(balance1).to.equal(amount1);
      expect(balance2).to.equal(amount2);
    });

    it("should revert audit access grant from non-owner", async function () {
      const { bond, investor1, regulator, unauthorized } = await loadFixture(
        deployBondFixture
      );

      await expect(
        bond.connect(unauthorized).grantAuditAccess(investor1.address, regulator.address)
      ).to.be.revertedWithCustomError(bond, "NotOwner");
    });
  });

  // ============ Ownership Transfer ============

  describe("Ownership", function () {
    it("should allow owner to transfer ownership", async function () {
      const { bond, owner, investor1 } = await loadFixture(deployBondFixture);

      await expect(bond.transferOwnership(investor1.address))
        .to.emit(bond, "OwnershipTransferred")
        .withArgs(owner.address, investor1.address);

      expect(await bond.owner()).to.equal(investor1.address);
    });

    it("should allow new owner to perform admin functions", async function () {
      const { bond, investor1, investor2 } = await loadFixture(deployBondFixture);

      await bond.transferOwnership(investor1.address);

      // New owner can add to whitelist
      await bond.connect(investor1).addToWhitelist(investor2.address);
      expect(await bond.whitelist(investor2.address)).to.be.true;
    });

    it("should prevent old owner from performing admin functions", async function () {
      const { bond, owner, investor1, investor2 } = await loadFixture(deployBondFixture);

      await bond.transferOwnership(investor1.address);

      await expect(
        bond.connect(owner).addToWhitelist(investor2.address)
      ).to.be.revertedWithCustomError(bond, "NotOwner");
    });

    it("should revert when transferring to zero address", async function () {
      const { bond } = await loadFixture(deployBondFixture);

      await expect(
        bond.transferOwnership(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(bond, "ZeroAddress");
    });

    it("should revert when non-owner tries to transfer ownership", async function () {
      const { bond, investor1, unauthorized } = await loadFixture(deployBondFixture);

      await expect(
        bond.connect(unauthorized).transferOwnership(investor1.address)
      ).to.be.revertedWithCustomError(bond, "NotOwner");
    });
  });

  // ============ Edge Cases ============

  describe("Edge Cases", function () {
    it("should handle zero-amount transfer", async function () {
      const { bond, owner, investor1, TOTAL_SUPPLY } = await loadFixture(
        deployBondFixture
      );

      await bond.addToWhitelist(investor1.address);

      const { handle, proof } = await encryptAmount(bond, owner, 0n);
      await bond.transfer(investor1.address, handle, proof);

      // Balances unchanged
      expect(await decryptBalance(bond, owner)).to.equal(TOTAL_SUPPLY);
      expect(await decryptBalance(bond, investor1)).to.equal(0n);
    });

    it("should handle self-transfer", async function () {
      const { bond, owner, TOTAL_SUPPLY } = await loadFixture(deployBondFixture);

      const { handle, proof } = await encryptAmount(bond, owner, 1000n);
      await bond.transfer(owner.address, handle, proof);

      // Balance unchanged (transferred to self)
      expect(await decryptBalance(bond, owner)).to.equal(TOTAL_SUPPLY);
    });

    it("should handle transfer of entire balance", async function () {
      const { bond, owner, investor1, TOTAL_SUPPLY } = await loadFixture(
        deployBondFixture
      );

      await bond.addToWhitelist(investor1.address);

      const { handle, proof } = await encryptAmount(bond, owner, TOTAL_SUPPLY);
      await bond.transfer(investor1.address, handle, proof);

      expect(await decryptBalance(bond, owner)).to.equal(0n);
      expect(await decryptBalance(bond, investor1)).to.equal(TOTAL_SUPPLY);
    });

    it("should handle full redemption at maturity", async function () {
      const { bond, owner, investor1, MATURITY_DATE } = await loadFixture(
        deployBondFixture
      );

      await bond.addToWhitelist(investor1.address);

      const bondAmount = 10_000n;
      const { handle: transferHandle, proof: transferProof } = await encryptAmount(
        bond,
        owner,
        bondAmount
      );
      await bond.transfer(investor1.address, transferHandle, transferProof);

      await time.increaseTo(MATURITY_DATE + 1n);

      // Redeem full amount
      const { handle: redeemHandle, proof: redeemProof } = await encryptAmount(
        bond,
        investor1,
        bondAmount
      );
      await bond.connect(investor1).redeem(redeemHandle, redeemProof);

      expect(await decryptBalance(bond, investor1)).to.equal(0n);
    });
  });
});
