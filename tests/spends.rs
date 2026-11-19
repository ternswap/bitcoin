mod common;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::sighash::Prevouts;
use bitcoin::{Amount, Sequence, TapSighashType, Witness};
use common::{Regtest, condition, key, keypair, pay_to};
use tern_bitcoin_script::{Escrow, Leaf};

const FULFILLMENT: [u8; 32] = [7; 32];
const AMOUNT: Amount = Amount::from_sat(100_000);
/// A party spending for itself pays the fee out of the escrow.
const PAID: Amount = Amount::from_sat(98_000);

/// Sender is key 1 (the user), receiver key 2 (the solver); expires an hour after the chain's clock.
fn escrow(node: &Regtest) -> Escrow {
    Escrow::new(
        key(1),
        key(2),
        condition(&FULFILLMENT),
        node.median_time_past() + 3_600,
    )
    .expect("valid terms")
}

#[test]
fn the_receiver_claims_with_the_fulfillment_and_it_can_be_read_back() {
    let node = Regtest::start();
    let escrow = escrow(&node);
    let (utxo, prevout) = node.fund(&escrow, AMOUNT);

    let mut tx = escrow.spend_tx(Leaf::Fulfill, utxo, pay_to(2), PAID);
    let signature = escrow
        .sign(
            &tx,
            0,
            &Prevouts::All(&[prevout]),
            Leaf::Fulfill,
            TapSighashType::Default,
            &keypair(2),
        )
        .expect("sign");
    tx.input[0].witness = escrow.fulfill_witness(&signature, &FULFILLMENT);

    node.confirm(&tx);
    assert!(node.is_spent(utxo));
    assert_eq!(
        escrow.fulfillment_in(&tx.input[0].witness),
        Some(FULFILLMENT)
    );
}

fn refused_by_script(node: &Regtest, tx: &bitcoin::Transaction) {
    let reason = node
        .check(tx)
        .expect_err("consensus must refuse this spend");
    assert!(reason.contains("script-verify-flag-failed"), "{reason}");
}

#[test]
fn a_wrong_fulfillment_is_refused() {
    let node = Regtest::start();
    let escrow = escrow(&node);
    let (utxo, prevout) = node.fund(&escrow, AMOUNT);
    let mut tx = escrow.spend_tx(Leaf::Fulfill, utxo, pay_to(2), PAID);
    let signature = escrow
        .sign(
            &tx,
            0,
            &Prevouts::All(&[prevout]),
            Leaf::Fulfill,
            TapSighashType::Default,
            &keypair(2),
        )
        .expect("sign");
    tx.input[0].witness = escrow.fulfill_witness(&signature, &[8; 32]);
    refused_by_script(&node, &tx);
}

#[test]
fn a_33_byte_fulfillment_is_refused_even_when_it_hashes_to_the_condition() {
    let node = Regtest::start();
    let long = [7u8; 33];
    let condition = sha256::Hash::hash(&long).to_byte_array();
    let escrow = Escrow::new(key(1), key(2), condition, node.median_time_past() + 3_600)
        .expect("valid terms");
    let (utxo, prevout) = node.fund(&escrow, AMOUNT);
    let mut tx = escrow.spend_tx(Leaf::Fulfill, utxo, pay_to(2), PAID);
    let signature = escrow
        .sign(
            &tx,
            0,
            &Prevouts::All(&[prevout]),
            Leaf::Fulfill,
            TapSighashType::Default,
            &keypair(2),
        )
        .expect("sign");
    let (signature, script) = (signature.to_vec(), escrow.leaf_script(Leaf::Fulfill));
    let block = escrow.control_block(Leaf::Fulfill).serialize();
    let stack: [&[u8]; 4] = [&signature, &long, script.as_bytes(), &block];
    tx.input[0].witness = Witness::from_slice(&stack);
    refused_by_script(&node, &tx);
}

#[test]
fn a_fulfill_signed_by_the_sender_is_refused() {
    let node = Regtest::start();
    let escrow = escrow(&node);
    let (utxo, prevout) = node.fund(&escrow, AMOUNT);
    let mut tx = escrow.spend_tx(Leaf::Fulfill, utxo, pay_to(1), PAID);
    let signature = escrow
        .sign(
            &tx,
            0,
            &Prevouts::All(&[prevout]),
            Leaf::Fulfill,
            TapSighashType::Default,
            &keypair(1),
        )
        .expect("sign");
    tx.input[0].witness = escrow.fulfill_witness(&signature, &FULFILLMENT);
    refused_by_script(&node, &tx);
}

#[test]
fn an_expire_waits_for_median_time_past_to_pass_the_expiry() {
    let node = Regtest::start();
    let escrow = escrow(&node);
    let (utxo, prevout) = node.fund(&escrow, AMOUNT);
    let mut tx = escrow.spend_tx(Leaf::Expire, utxo, pay_to(1), PAID);
    let signature = escrow
        .sign(
            &tx,
            0,
            &Prevouts::All(&[prevout]),
            Leaf::Expire,
            TapSighashType::Default,
            &keypair(1),
        )
        .expect("sign");
    tx.input[0].witness = escrow.expire_witness(&signature);

    let reason = node.check(&tx).expect_err("too early");
    assert!(reason.contains("non-final"), "{reason}");

    // A transaction is final once its nLockTime is below median time past (BIP-113).
    node.advance_to(escrow.expires_at() + 1);
    node.confirm(&tx);
    assert!(node.is_spent(utxo));
}

#[test]
fn a_reject_needs_both_signatures() {
    let node = Regtest::start();
    let escrow = escrow(&node);
    let (utxo, prevout) = node.fund(&escrow, AMOUNT);
    let mut tx = escrow.spend_tx(Leaf::Reject, utxo, pay_to(1), PAID);
    let sign = |seed| {
        escrow
            .sign(
                &tx,
                0,
                &Prevouts::All(std::slice::from_ref(&prevout)),
                Leaf::Reject,
                TapSighashType::Default,
                &keypair(seed),
            )
            .expect("sign")
    };
    let (sender, receiver) = (sign(1), sign(2));

    let (sender_bytes, receiver_bytes) = (sender.to_vec(), receiver.to_vec());
    let script = escrow.leaf_script(Leaf::Reject);
    let block = escrow.control_block(Leaf::Reject).serialize();
    // An empty signature is a failed check rather than a malformed one (BIP-342). On a Bitcoin source the
    // receiver is the solver, so the second stack is the one that would let it take the BTC alone.
    let stacks: [[&[u8]; 4]; 2] = [
        [&[], &sender_bytes, script.as_bytes(), &block],
        [&receiver_bytes, &[], script.as_bytes(), &block],
    ];
    for stack in stacks {
        tx.input[0].witness = Witness::from_slice(&stack);
        refused_by_script(&node, &tx);
    }

    tx.input[0].witness = escrow.reject_witness(&sender, &receiver);
    node.confirm(&tx);
    assert!(node.is_spent(utxo));
}

#[test]
fn past_expiry_the_leaf_itself_refuses_an_expire_without_its_lock_time() {
    let node = Regtest::start();
    let escrow = escrow(&node);
    let (utxo, prevout) = node.fund(&escrow, AMOUNT);
    // Past expiry, finality no longer stops these transactions; only OP_CHECKLOCKTIMEVERIFY does (BIP-65).
    node.advance_to(escrow.expires_at() + 1);

    let mut below = escrow.spend_tx(Leaf::Expire, utxo, pay_to(1), PAID);
    below.lock_time = LockTime::from_consensus(escrow.expires_at() - 1);
    let mut final_input = escrow.spend_tx(Leaf::Expire, utxo, pay_to(1), PAID);
    final_input.input[0].sequence = Sequence::MAX;
    for mut tx in [below, final_input] {
        let signature = escrow
            .sign(
                &tx,
                0,
                &Prevouts::All(std::slice::from_ref(&prevout)),
                Leaf::Expire,
                TapSighashType::Default,
                &keypair(1),
            )
            .expect("sign");
        tx.input[0].witness = escrow.expire_witness(&signature);
        let reason = node.check(&tx).expect_err("the expire leaf must refuse it");
        assert!(
            reason.contains("Locktime requirement not satisfied"),
            "{reason}"
        );
    }
}
