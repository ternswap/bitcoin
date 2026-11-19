use std::str::FromStr;
use std::sync::LazyLock;

use bitcoin::key::XOnlyPublicKey;
use bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_DROP, OP_EQUALVERIFY, OP_SHA256, OP_SIZE,
};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::sighash::TaprootError;
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{Address, KnownHrp, Network, ScriptBuf};

pub(crate) static SECP: LazyLock<Secp256k1<All>> = LazyLock::new(Secp256k1::new);

/// BIP-341's provably unspendable point `H`: only the three leaves can spend the escrow.
pub static NUMS: LazyLock<XOnlyPublicKey> = LazyLock::new(|| {
    XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        .expect("BIP-341 H is a valid x-only key")
});

/// Below this, `OP_CHECKLOCKTIMEVERIFY` reads the value as a block height instead of a Unix time.
pub const MIN_EXPIRES_AT: u32 = 500_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leaf {
    Fulfill,
    Expire,
    Reject,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error(
        "expires_at {0} is below 500,000,000, where OP_CHECKLOCKTIMEVERIFY reads a block height"
    )]
    ExpiryIsHeight(u32),
    #[error("sender and receiver are the same key")]
    SameParty,
    #[error("cannot compute the sighash")]
    Sighash(#[from] TaprootError),
}

/// The escrow terms the script commits to. The asset is always BTC and the amount is the UTXO's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escrow {
    sender: XOnlyPublicKey,
    receiver: XOnlyPublicKey,
    condition: [u8; 32],
    expires_at: u32,
}

impl Escrow {
    pub fn new(
        sender: XOnlyPublicKey,
        receiver: XOnlyPublicKey,
        condition: [u8; 32],
        expires_at: u32,
    ) -> Result<Self, Error> {
        if expires_at < MIN_EXPIRES_AT {
            return Err(Error::ExpiryIsHeight(expires_at));
        }
        if sender == receiver {
            return Err(Error::SameParty);
        }
        Ok(Self {
            sender,
            receiver,
            condition,
            expires_at,
        })
    }

    pub fn expires_at(&self) -> u32 {
        self.expires_at
    }

    pub fn leaf_script(&self, leaf: Leaf) -> ScriptBuf {
        match leaf {
            Leaf::Fulfill => ScriptBuf::builder()
                .push_opcode(OP_SIZE)
                .push_int(32)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_SHA256)
                .push_slice(self.condition)
                .push_opcode(OP_EQUALVERIFY)
                .push_slice(self.receiver.serialize())
                .push_opcode(OP_CHECKSIG)
                .into_script(),
            Leaf::Expire => ScriptBuf::builder()
                .push_int(i64::from(self.expires_at))
                .push_opcode(OP_CLTV)
                .push_opcode(OP_DROP)
                .push_slice(self.sender.serialize())
                .push_opcode(OP_CHECKSIG)
                .into_script(),
            Leaf::Reject => ScriptBuf::builder()
                .push_slice(self.sender.serialize())
                .push_opcode(OP_CHECKSIGVERIFY)
                .push_slice(self.receiver.serialize())
                .push_opcode(OP_CHECKSIG)
                .into_script(),
        }
    }

    pub fn leaf_hash(&self, leaf: Leaf) -> TapLeafHash {
        TapLeafHash::from_script(&self.leaf_script(leaf), LeafVersion::TapScript)
    }

    /// Fulfill sits at depth 1 because it is the usual spend; its control block is 32 bytes shorter.
    pub fn spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(1, self.leaf_script(Leaf::Fulfill))
            .expect("depth 1 is free")
            .add_leaf(2, self.leaf_script(Leaf::Expire))
            .expect("depth 2 is free")
            .add_leaf(2, self.leaf_script(Leaf::Reject))
            .expect("depth 2 is free")
            .finalize(&SECP, *NUMS)
            .expect("leaves at depths 1, 2 and 2 complete the tree")
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.spend_info().output_key())
    }

    pub fn address(&self, network: Network) -> Address {
        Address::p2tr_tweaked(self.spend_info().output_key(), KnownHrp::from(network))
    }

    pub fn control_block(&self, leaf: Leaf) -> ControlBlock {
        self.spend_info()
            .control_block(&(self.leaf_script(leaf), LeafVersion::TapScript))
            .expect("every leaf is in the tree")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{CONDITION, EXPIRES_AT, escrow, key};

    #[test]
    fn fulfill_leaf_is_spec_section_8() {
        let mut want = vec![0x82, 0x01, 0x20, 0x88, 0xa8, 0x20];
        want.extend(CONDITION);
        want.extend([0x88, 0x20]);
        want.extend(key(2).serialize());
        want.push(0xac);
        assert_eq!(escrow().leaf_script(Leaf::Fulfill).as_bytes(), want);
    }

    #[test]
    fn expire_leaf_is_spec_section_8() {
        // 1_800_000_000 is 0x6b49d200, pushed as a 4-byte little-endian script number.
        let mut want = vec![0x04, 0x00, 0xd2, 0x49, 0x6b, 0xb1, 0x75, 0x20];
        want.extend(key(1).serialize());
        want.push(0xac);
        assert_eq!(escrow().leaf_script(Leaf::Expire).as_bytes(), want);
    }

    #[test]
    fn reject_leaf_is_spec_section_8() {
        let mut want = vec![0x20];
        want.extend(key(1).serialize());
        want.extend([0xad, 0x20]);
        want.extend(key(2).serialize());
        want.push(0xac);
        assert_eq!(escrow().leaf_script(Leaf::Reject).as_bytes(), want);
    }

    #[test]
    fn an_expiry_below_500_million_is_refused() {
        assert_eq!(
            Escrow::new(key(1), key(2), CONDITION, 499_999_999),
            Err(Error::ExpiryIsHeight(499_999_999))
        );
        assert!(Escrow::new(key(1), key(2), CONDITION, MIN_EXPIRES_AT).is_ok());
    }

    #[test]
    fn sender_and_receiver_must_differ() {
        assert_eq!(
            Escrow::new(key(1), key(1), CONDITION, EXPIRES_AT),
            Err(Error::SameParty)
        );
    }

    #[test]
    fn the_address_is_regtest_taproot_and_commits_to_every_term() {
        let base = escrow();
        assert!(
            base.address(Network::Regtest)
                .to_string()
                .starts_with("bcrt1p")
        );
        let variants = [
            Escrow::new(key(3), key(2), CONDITION, EXPIRES_AT),
            Escrow::new(key(1), key(3), CONDITION, EXPIRES_AT),
            Escrow::new(key(1), key(2), [0x12; 32], EXPIRES_AT),
            Escrow::new(key(1), key(2), CONDITION, EXPIRES_AT + 1),
        ];
        for variant in variants {
            assert_ne!(
                variant.expect("valid terms").script_pubkey(),
                base.script_pubkey()
            );
        }
    }

    #[test]
    fn the_internal_key_is_bip341_nums() {
        assert_eq!(escrow().spend_info().internal_key(), *NUMS);
    }

    #[test]
    fn each_control_block_proves_its_leaf_at_its_depth() {
        let escrow = escrow();
        let output_key = escrow.spend_info().output_key().to_x_only_public_key();
        for (leaf, len) in [(Leaf::Fulfill, 65), (Leaf::Expire, 97), (Leaf::Reject, 97)] {
            let block = escrow.control_block(leaf);
            assert!(block.verify_taproot_commitment(&SECP, output_key, &escrow.leaf_script(leaf)));
            assert_eq!(block.serialize().len(), len, "{leaf:?}");
        }
    }
}
