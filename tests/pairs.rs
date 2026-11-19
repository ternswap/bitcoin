mod common;

use bitcoin::Amount;
use bitcoin::sighash::Prevouts;
use common::{Regtest, condition, key, keypair, pay_to};
use tern_bitcoin_script::{Escrow, Leaf, PAIR_SIGHASH};

const AMOUNT: Amount = Amount::from_sat(100_000);

#[test]
fn a_keeper_completes_a_presigned_refund_and_pays_the_fee() {
    let node = Regtest::start();
    // Bitcoin source: the OTA is the sender.
    let escrow = Escrow::new(
        key(1),
        key(2),
        condition(&[7; 32]),
        node.median_time_past() + 3_600,
    )
    .expect("valid terms");
    let (utxo, prevout) = node.fund(&escrow, AMOUNT);

    let mut pair = escrow.spend_tx(Leaf::Expire, utxo, pay_to(9), AMOUNT);
    let ota = escrow
        .sign(
            &pair,
            0,
            &Prevouts::One(0, prevout.clone()),
            Leaf::Expire,
            PAIR_SIGHASH,
            &keypair(1),
        )
        .expect("sign");
    pair.input[0].witness = escrow.expire_witness(&ota);

    node.advance_to(escrow.expires_at() + 1);
    let tx = node.add_fee(pair, &[prevout]);
    node.confirm(&tx);
    assert!(node.is_spent(utxo));
    assert_eq!(
        tx.output[0].value, AMOUNT,
        "the refund is the whole escrow; the keeper's input paid the fee"
    );
}

#[test]
fn a_relayer_completes_a_presigned_claim_once_the_fulfillment_is_revealed() {
    let node = Regtest::start();
    // Bitcoin destination: the solver is the sender, the OTA the receiver.
    let fulfillment = [7; 32];
    let escrow = Escrow::new(
        key(2),
        key(1),
        condition(&fulfillment),
        node.median_time_past() + 3_600,
    )
    .expect("valid terms");
    let (utxo, prevout) = node.fund(&escrow, AMOUNT);

    let mut pair = escrow.spend_tx(Leaf::Fulfill, utxo, pay_to(9), AMOUNT);
    let ota = escrow
        .sign(
            &pair,
            0,
            &Prevouts::One(0, prevout.clone()),
            Leaf::Fulfill,
            PAIR_SIGHASH,
            &keypair(1),
        )
        .expect("sign");
    // The app sends the signature with the fulfillment; the relayer builds the witness.
    pair.input[0].witness = escrow.fulfill_witness(&ota, &fulfillment);

    let tx = node.add_fee(pair, &[prevout]);
    node.confirm(&tx);
    assert!(node.is_spent(utxo));
    assert_eq!(tx.output[0].value, AMOUNT);
}

#[test]
fn a_relayer_completes_an_instant_refund_from_both_halves() {
    let node = Regtest::start();
    let escrow = Escrow::new(
        key(1),
        key(2),
        condition(&[7; 32]),
        node.median_time_past() + 3_600,
    )
    .expect("valid terms");
    let (utxo, prevout) = node.fund(&escrow, AMOUNT);

    let mut pair = escrow.spend_tx(Leaf::Reject, utxo, pay_to(9), AMOUNT);
    let half = |seed| {
        escrow
            .sign(
                &pair,
                0,
                &Prevouts::One(0, prevout.clone()),
                Leaf::Reject,
                PAIR_SIGHASH,
                &keypair(seed),
            )
            .expect("sign")
    };
    let (ota, solver) = (half(1), half(2));
    pair.input[0].witness = escrow.reject_witness(&ota, &solver);

    let tx = node.add_fee(pair, &[prevout]);
    node.confirm(&tx);
    assert!(node.is_spent(utxo));
    assert_eq!(tx.output[0].value, AMOUNT);
}

#[test]
fn two_presigned_claims_share_one_transaction_without_new_signatures() {
    let node = Regtest::start();
    let expires_at = node.median_time_past() + 3_600;
    let claims: Vec<_> = [[7u8; 32], [8u8; 32]]
        .iter()
        .map(|fulfillment| {
            let escrow = Escrow::new(key(2), key(1), condition(fulfillment), expires_at)
                .expect("valid terms");
            let (utxo, prevout) = node.fund(&escrow, AMOUNT);
            let mut pair = escrow.spend_tx(Leaf::Fulfill, utxo, pay_to(9), AMOUNT);
            let ota = escrow
                .sign(
                    &pair,
                    0,
                    &Prevouts::One(0, prevout.clone()),
                    Leaf::Fulfill,
                    PAIR_SIGHASH,
                    &keypair(1),
                )
                .expect("sign");
            pair.input[0].witness = escrow.fulfill_witness(&ota, fulfillment);
            (pair, prevout)
        })
        .collect();

    // Each pair was signed alone at index 0; the second now sits at index 1.
    let mut batch = claims[0].0.clone();
    batch.input.push(claims[1].0.input[0].clone());
    batch.output.push(claims[1].0.output[0].clone());
    let tx = node.add_fee(batch, &[claims[0].1.clone(), claims[1].1.clone()]);
    node.confirm(&tx);
    assert!(node.is_spent(claims[0].0.input[0].previous_output));
    assert!(node.is_spent(claims[1].0.input[0].previous_output));
}
