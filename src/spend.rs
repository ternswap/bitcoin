use std::borrow::Borrow;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::Signature;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Witness,
};

use crate::escrow::{Error, Escrow, Leaf, SECP};

/// Covers one input and the output at the same index, nothing else: whoever broadcasts can add an input to
/// pay the fee, and pairs from many escrows can share one transaction (ADR-0001).
pub const PAIR_SIGHASH: TapSighashType = TapSighashType::SinglePlusAnyoneCanPay;

impl Escrow {
    pub fn spend_tx(
        &self,
        leaf: Leaf,
        utxo: OutPoint,
        pay_to: ScriptBuf,
        amount: Amount,
    ) -> Transaction {
        let lock_time = match leaf {
            // OP_CHECKLOCKTIMEVERIFY compares the script's expiry with the spending transaction's nLockTime.
            Leaf::Expire => LockTime::from_consensus(self.expires_at()),
            Leaf::Fulfill | Leaf::Reject => LockTime::ZERO,
        };
        Transaction {
            version: Version::TWO,
            lock_time,
            input: vec![TxIn {
                previous_output: utxo,
                script_sig: ScriptBuf::new(),
                // Despite the name, any sequence below 0xffffffff keeps nLockTime binding; this one also
                // signals replaceability.
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: amount,
                script_pubkey: pay_to,
            }],
        }
    }

    pub fn sign<T: Borrow<TxOut>>(
        &self,
        tx: &Transaction,
        input: usize,
        prevouts: &Prevouts<T>,
        leaf: Leaf,
        sighash_type: TapSighashType,
        keypair: &Keypair,
    ) -> Result<Signature, Error> {
        let sighash = SighashCache::new(tx).taproot_script_spend_signature_hash(
            input,
            prevouts,
            self.leaf_hash(leaf),
            sighash_type,
        )?;
        let message = Message::from_digest(sighash.to_raw_hash().to_byte_array());
        Ok(Signature {
            signature: SECP.sign_schnorr_no_aux_rand(&message, keypair),
            sighash_type,
        })
    }

    pub fn fulfill_witness(&self, receiver: &Signature, fulfillment: &[u8; 32]) -> Witness {
        self.witness(Leaf::Fulfill, &[&receiver.to_vec(), fulfillment])
    }

    pub fn expire_witness(&self, sender: &Signature) -> Witness {
        self.witness(Leaf::Expire, &[&sender.to_vec()])
    }

    /// `OP_CHECKSIGVERIFY` checks the sender first, so the sender's signature goes on top of the stack.
    pub fn reject_witness(&self, sender: &Signature, receiver: &Signature) -> Witness {
        self.witness(Leaf::Reject, &[&receiver.to_vec(), &sender.to_vec()])
    }

    /// The fulfillment a fulfill spend of this escrow revealed; `None` for its other spends.
    pub fn fulfillment_in(&self, witness: &Witness) -> Option<[u8; 32]> {
        let items = witness.len() - usize::from(witness.taproot_annex().is_some());
        if items != 4
            || witness.taproot_leaf_script()?.script != self.leaf_script(Leaf::Fulfill).as_script()
        {
            return None;
        }
        witness.nth(1)?.try_into().ok()
    }

    fn witness(&self, leaf: Leaf, stack: &[&[u8]]) -> Witness {
        let mut witness = Witness::new();
        for item in stack {
            witness.push(item);
        }
        witness.push(self.leaf_script(leaf).as_bytes());
        witness.push(self.control_block(leaf).serialize());
        witness
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Txid;

    use super::*;
    use crate::fixtures::{EXPIRES_AT, escrow, funded, key, keypair, utxo};

    fn pay_to() -> ScriptBuf {
        ScriptBuf::new_p2tr(&SECP, key(9), None)
    }

    fn pair_sighash(tx: &Transaction, input: usize, prevout: &TxOut, leaf: Leaf) -> [u8; 32] {
        SighashCache::new(tx)
            .taproot_script_spend_signature_hash(
                input,
                &Prevouts::One(input, prevout.clone()),
                escrow().leaf_hash(leaf),
                PAIR_SIGHASH,
            )
            .expect("sighash")
            .to_raw_hash()
            .to_byte_array()
    }

    fn sign_pair(leaf: Leaf, tx: &Transaction, prevout: &TxOut, seed: u8) -> Signature {
        escrow()
            .sign(
                tx,
                0,
                &Prevouts::One(0, prevout.clone()),
                leaf,
                PAIR_SIGHASH,
                &keypair(seed),
            )
            .expect("sign")
    }

    #[test]
    fn an_expire_binds_its_expiry_and_keeps_the_timelock_on() {
        let escrow = escrow();
        let amount = Amount::from_sat(100_000);
        let expire = escrow.spend_tx(Leaf::Expire, utxo(), pay_to(), amount);
        assert_eq!(expire.lock_time.to_consensus_u32(), EXPIRES_AT);
        assert_ne!(
            expire.input[0].sequence,
            Sequence::MAX,
            "0xffffffff switches the timelock off"
        );
        for leaf in [Leaf::Fulfill, Leaf::Reject] {
            assert_eq!(
                escrow.spend_tx(leaf, utxo(), pay_to(), amount).lock_time,
                LockTime::ZERO
            );
        }
    }

    #[test]
    fn a_pair_signature_is_65_bytes_and_names_its_type() {
        let prevout = funded(&escrow());
        let tx = escrow().spend_tx(Leaf::Expire, utxo(), pay_to(), prevout.value);
        let bytes = sign_pair(Leaf::Expire, &tx, &prevout, 1).to_vec();
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[64], 0x83, "SIGHASH_SINGLE|ANYONECANPAY");
    }

    #[test]
    fn a_signature_verifies_against_the_key_its_leaf_names() {
        let prevout = funded(&escrow());
        let tx = escrow().spend_tx(Leaf::Fulfill, utxo(), pay_to(), prevout.value);
        let signature = sign_pair(Leaf::Fulfill, &tx, &prevout, 2);
        let message = Message::from_digest(pair_sighash(&tx, 0, &prevout, Leaf::Fulfill));
        SECP.verify_schnorr(&signature.signature, &message, &key(2))
            .expect("the receiver's key verifies a fulfill signature");
    }

    #[test]
    fn a_pair_signature_survives_moving_to_another_index() {
        let prevout = funded(&escrow());
        let pair = escrow().spend_tx(Leaf::Fulfill, utxo(), pay_to(), prevout.value);
        let filler_in = |n: u8| TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([n; 32]), 0),
            ..pair.input[0].clone()
        };
        let filler_out = TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: pay_to(),
        };
        let mut batch = pair.clone();
        batch.input = vec![
            filler_in(1),
            filler_in(2),
            filler_in(3),
            pair.input[0].clone(),
        ];
        batch.output = vec![
            filler_out.clone(),
            filler_out.clone(),
            filler_out,
            pair.output[0].clone(),
        ];
        assert_eq!(
            pair_sighash(&pair, 0, &prevout, Leaf::Fulfill),
            pair_sighash(&batch, 3, &prevout, Leaf::Fulfill)
        );
    }

    #[test]
    fn expire_pairs_batch_only_with_the_same_lock_time() {
        let prevout = funded(&escrow());
        let pair = escrow().spend_tx(Leaf::Expire, utxo(), pay_to(), prevout.value);
        let mut later = pair.clone();
        later.lock_time = LockTime::from_consensus(EXPIRES_AT + 1);
        assert_ne!(
            pair_sighash(&pair, 0, &prevout, Leaf::Expire),
            pair_sighash(&later, 0, &prevout, Leaf::Expire)
        );
    }

    #[test]
    fn the_fulfillment_is_read_back_from_a_fulfill_witness_only() {
        let escrow = escrow();
        let prevout = funded(&escrow);
        let tx = escrow.spend_tx(Leaf::Fulfill, utxo(), pay_to(), prevout.value);
        let signature = sign_pair(Leaf::Fulfill, &tx, &prevout, 2);
        assert_eq!(
            escrow.fulfillment_in(&escrow.fulfill_witness(&signature, &[7; 32])),
            Some([7; 32])
        );
        assert_eq!(
            escrow.fulfillment_in(&escrow.reject_witness(&signature, &signature)),
            None
        );
        assert_eq!(
            escrow.fulfillment_in(&escrow.expire_witness(&signature)),
            None
        );
    }

    #[test]
    fn the_fulfillment_is_read_back_past_an_annex() {
        let escrow = escrow();
        let prevout = funded(&escrow);
        let tx = escrow.spend_tx(Leaf::Fulfill, utxo(), pay_to(), prevout.value);
        let signature = sign_pair(Leaf::Fulfill, &tx, &prevout, 2);
        let mut witness = escrow.fulfill_witness(&signature, &[7; 32]);
        // BIP-341: a last element starting 0x50 is an annex. Relay refuses it, but a miner can include it.
        witness.push([0x50, 0x01]);
        assert_eq!(escrow.fulfillment_in(&witness), Some([7; 32]));
    }

    #[test]
    fn a_sighash_error_keeps_its_cause() {
        let prevout = funded(&escrow());
        let tx = escrow().spend_tx(Leaf::Expire, utxo(), pay_to(), prevout.value);
        let err = escrow()
            .sign(
                &tx,
                1,
                &Prevouts::One(1, prevout),
                Leaf::Expire,
                PAIR_SIGHASH,
                &keypair(1),
            )
            .expect_err("the transaction has no input 1");
        assert!(std::error::Error::source(&err).is_some(), "{err:?}");
    }

    #[test]
    fn a_reject_witness_puts_the_sender_signature_on_top() {
        let escrow = escrow();
        let prevout = funded(&escrow);
        let tx = escrow.spend_tx(Leaf::Reject, utxo(), pay_to(), prevout.value);
        let (sender, receiver) = (
            sign_pair(Leaf::Reject, &tx, &prevout, 1),
            sign_pair(Leaf::Reject, &tx, &prevout, 2),
        );
        let witness = escrow.reject_witness(&sender, &receiver);
        assert_eq!(witness.nth(0), Some(receiver.to_vec().as_slice()));
        assert_eq!(witness.nth(1), Some(sender.to_vec().as_slice()));
    }
}
