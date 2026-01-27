use aztec::macros::aztec;

#[aztec]
pub contract PrivateBonds {
    use aztec::{
        macros::{functions::{authorize_once, external, initializer, only_self}, storage::storage},
        protocol_types::address::AztecAddress,
        state_vars::{Map, Owned, public_mutable::PublicMutable},
    };
    use aztec::messages::message_delivery::MessageDelivery;
    use balance_set::BalanceSet;

    #[storage]
    struct Storage<Context> {
        owner: PublicMutable<AztecAddress, Context>,
        private_balances: Owned<BalanceSet<Context>, Context>,
        whitelist: Map<AztecAddress, PublicMutable<bool, Context>, Context>,
        total_supply: PublicMutable<u64, Context>,
        maturity_date: PublicMutable<u64, Context>,
    }

    #[initializer]
    #[external("private")]
    fn initialize(total_supply: u64, maturity: u64) {
        let issuer = self.msg_sender().unwrap();

        // Set public state via enqueued calls
        self.enqueue_self._set_owner(issuer);
        self.enqueue_self._set_maturity(maturity);
        self.enqueue_self._set_total_supply(total_supply);

        // Mint entire supply to issuer's private balance
        // This is the ONLY minting that ever happens
        self.storage.private_balances.at(issuer).add(total_supply as u128).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );
    }

    #[external("public")]
    #[only_self]
    fn _set_owner(owner: AztecAddress) {
        self.storage.owner.write(owner);
    }

    #[external("public")]
    #[only_self]
    fn _set_maturity(maturity: u64) {
        self.storage.maturity_date.write(maturity);
    }

    #[external("public")]
    #[only_self]
    fn _set_total_supply(total_supply: u64) {
        self.storage.total_supply.write(total_supply);
    }

    #[external("public")]
    fn add_to_whitelist(investor: AztecAddress) {
        assert_eq(
            self.msg_sender().unwrap(),
            self.storage.owner.read(),
            "Only owner can manage whitelist",
        );
        assert(!self.storage.whitelist.at(investor).read(), "Investor is already listed");

        self.storage.whitelist.at(investor).write(true);
    }

    #[external("public")]
    fn ban_from_whitelist(investor: AztecAddress) {
        assert_eq(
            self.msg_sender().unwrap(),
            self.storage.owner.read(),
            "Only owner can manage whitelist",
        );
        assert(self.storage.whitelist.at(investor).read(), "Investor is already unlisted");

        self.storage.whitelist.at(investor).write(false);
    }

    #[external("private")]
    fn distribute_private(investor: AztecAddress, amount: u64) {
        // Only issuer can distribute
        self.enqueue_self._assert_is_owner(self.msg_sender().unwrap());

        // Check investor is whitelisted
        self.enqueue_self._assert_is_whitelisted(investor);

        // Transfer from issuer's private balance to investor
        let issuer = self.msg_sender().unwrap();
        self.storage.private_balances.at(issuer).sub(amount as u128).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );
        self.storage.private_balances.at(investor).add(amount as u128).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );
    }

    #[external("private")]
    fn transfer_private(to: AztecAddress, amount: u64) {
        let sender = self.msg_sender().unwrap();

        // Check both sender and recipient are whitelisted
        self.enqueue_self._assert_is_whitelisted(sender);
        self.enqueue_self._assert_is_whitelisted(to);

        // Spend sender's notes
        self.storage.private_balances.at(sender).sub(amount as u128).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );

        // Create new notes for recipient
        self.storage.private_balances.at(to).add(amount as u128).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );
    }

    /// Delegated transfer for DvP and other authorized scenarios.
    /// Requires `from` to have created an authwit for this exact call.
    #[authorize_once("from", "nonce")]
    #[external("private")]
    fn transfer_from(from: AztecAddress, to: AztecAddress, amount: u64, nonce: Field) {
        self.enqueue_self._assert_is_whitelisted(from);
        self.enqueue_self._assert_is_whitelisted(to);

        self.storage.private_balances.at(from).sub(amount as u128).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );
        self.storage.private_balances.at(to).add(amount as u128).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );
    }

    /// Redeem bonds at maturity. Investor burns their bonds directly.
    /// In production, a DvP contract would use transfer_from (with authwit) for atomic settlement.
    /// For PoC, investor calls this directly and stablecoin settlement happens off-chain.
    #[external("private")]
    fn redeem(amount: u64) {
        let investor = self.msg_sender().unwrap();
        self.enqueue_self._assert_is_whitelisted(investor);
        self.enqueue_self._assert_maturity_reached();

        self.storage.private_balances.at(investor).sub(amount as u128).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );
    }

    #[external("public")]
    fn transfer_ownership(new_owner: AztecAddress) {
        assert_eq(
            self.msg_sender().unwrap(),
            self.storage.owner.read(),
            "Only current owner can transfer ownership",
        );
        self.storage.owner.write(new_owner);
    }

    #[external("utility")]
    unconstrained fn private_balance_of(owner: AztecAddress) -> pub u128 {
        self.storage.private_balances.at(owner).balance_of()
    }

    #[external("utility")]
    unconstrained fn get_total_supply() -> pub u64 {
        self.storage.total_supply.read()
    }

    #[external("utility")]
    unconstrained fn get_maturity_date() -> pub u64 {
        self.storage.maturity_date.read()
    }

    #[external("utility")]
    unconstrained fn is_whitelisted(address: AztecAddress) -> pub bool {
        self.storage.whitelist.at(address).read()
    }

    #[external("public")]
    #[only_self]
    fn _assert_is_owner(address: AztecAddress) {
        assert_eq(address, self.storage.owner.read(), "Only the Issuer can perform this action");
    }

    #[external("public")]
    #[only_self]
    fn _assert_is_whitelisted(address: AztecAddress) {
        assert(self.storage.whitelist.at(address).read(), "Address is not whitelisted");
    }

    #[external("public")]
    #[only_self]
    fn _assert_maturity_reached() {
        let block_timestamp = self.context.timestamp();
        let maturity_date = self.storage.maturity_date.read();
        assert(block_timestamp >= maturity_date, "Bond has not reached maturity yet");
    }

}
