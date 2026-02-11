use aztec::macros::aztec;

/// Stateless DvP (Delivery vs Payment) coordinator contract.
/// Orchestrates an atomic bond for stablecoin swap via cross contract calls.
/// Both parties must pre-create authwits authorizing this contract to move their assets.
#[aztec]
pub contract DvP {
    use aztec::{
        macros::{functions::external, storage::storage},
        protocol_types::address::AztecAddress,
    };
    use private_bonds::PrivateBonds;
    use stablecoin::Stablecoin;

    #[storage]
    struct Storage<Context> {}

    /// Executes an atomic bond-for-stablecoin swap.
    ///
    /// Prerequisites:
    /// - Seller created a private authwit authorizing this DvP contract
    ///   to call bond_contract.transfer_from(seller, buyer, bond_amount, bond_nonce)
    /// - Buyer created a private authwit authorizing this DvP contract
    ///   to call stablecoin_contract.transfer_from(buyer, seller, stablecoin_amount, stablecoin_nonce)
    ///
    /// Atomicity: Both transfers happen in the same transaction.
    /// If either fails, the entire transaction reverts.
    #[external("private")]
    fn execute_swap(
        bond_contract: AztecAddress,
        stablecoin_contract: AztecAddress,
        seller: AztecAddress,
        buyer: AztecAddress,
        bond_amount: u64,
        stablecoin_amount: u64,
        bond_nonce: Field,
        stablecoin_nonce: Field,
    ) {
        // Transfer bonds: seller -> buyer
        PrivateBonds::at(bond_contract).transfer_from(seller, buyer, bond_amount, bond_nonce).call(
            self.context,
        );

        // Transfer stablecoins: buyer -> seller
        Stablecoin::at(stablecoin_contract)
            .transfer_from(buyer, seller, stablecoin_amount, stablecoin_nonce)
            .call(self.context);
    }
}
