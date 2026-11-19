use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, XOnlyPublicKey};
use bitcoin::{Amount, OutPoint, TxOut, Txid};

use crate::Escrow;
use crate::escrow::SECP;

pub const EXPIRES_AT: u32 = 1_800_000_000;
pub const CONDITION: [u8; 32] = [0x11; 32];

pub fn keypair(seed: u8) -> Keypair {
    Keypair::from_seckey_slice(&SECP, &[seed; 32]).expect("non-zero seed")
}

pub fn key(seed: u8) -> XOnlyPublicKey {
    keypair(seed).x_only_public_key().0
}

/// Sender is key 1, receiver key 2.
pub fn escrow() -> Escrow {
    Escrow::new(key(1), key(2), CONDITION, EXPIRES_AT).expect("valid terms")
}

pub fn utxo() -> OutPoint {
    OutPoint::new(Txid::from_byte_array([0x22; 32]), 0)
}

pub fn funded(escrow: &Escrow) -> TxOut {
    TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: escrow.script_pubkey(),
    }
}
