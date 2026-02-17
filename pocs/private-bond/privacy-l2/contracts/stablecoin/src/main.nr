use aztec::macros::aztec;

/// Minimal private ERC20 stablecoin for DvP benchmarking.
/// Permissionless no whitelist or maturity logic.
#[aztec]
pub contract Stablecoin {
    use aztec::{
        macros::{functions::{authorize_once, external, initializer, only_self}, storage::storage},
        protocol_types::address::AztecAddress,
        state_vars::{Owned, public_mutable::PublicMutable},
    };
    use aztec::messages::message_delivery::MessageDelivery;
    use balance_set::BalanceSet;

    #[storage]
    struct Storage<Context> {
        admin: PublicMutable<AztecAddress, Context>,
        private_balances: Owned<BalanceSet<Context>, Context>,
        total_supply: PublicMutable<u64, Context>,
    }

    #[initializer]
    #[external("private")]
    fn constructor(total_supply: u64) {
        let deployer = self.msg_sender().unwrap();

        self.enqueue_self._set_admin(deployer);
        self.enqueue_self._set_total_supply(total_supply);

        // Mint entire supply to deployer's private balance
        self.storage.private_balances.at(deployer).add(total_supply as u128).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );
    }

    #[external("public")]
    #[only_self]
    fn _set_admin(admin: AztecAddress) {
        self.storage.admin.write(admin);
    }

    #[external("public")]
    #[only_self]
    fn _set_total_supply(total_supply: u64) {
        self.storage.total_supply.write(total_supply);
    }

    #[external("private")]
    fn transfer_private(to: AztecAddress, amount: u64) {
        let sender = self.msg_sender().unwrap();

        self.storage.private_balances.at(sender).sub(amount as u128).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );
        self.storage.private_balances.at(to).add(amount as u128).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );
    }

    /// Delegated transfer for DvP and other authorized scenarios.
    /// Requires `from` to have created an authwit for this exact call.
    #[authorize_once("from", "nonce")]
    #[external("private")]
    fn transfer_from(from: AztecAddress, to: AztecAddress, amount: u64, nonce: Field) {
        self.storage.private_balances.at(from).sub(amount as u128).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );
        self.storage.private_balances.at(to).add(amount as u128).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );
    }

    #[external("utility")]
    unconstrained fn private_balance_of(owner: AztecAddress) -> pub u128 {
        self.storage.private_balances.at(owner).balance_of()
    }

    #[external("utility")]
    unconstrained fn get_total_supply() -> pub u64 {
        self.storage.total_supply.read()
    }
}
