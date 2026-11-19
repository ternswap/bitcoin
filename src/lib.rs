//! Tern's Bitcoin escrow: the Taproot output of spec section 8, and the transactions that spend it.

mod escrow;
#[cfg(test)]
mod fixtures;
mod spend;

pub use escrow::{Error, Escrow, Leaf, MIN_EXPIRES_AT, NUMS};
pub use spend::PAIR_SIGHASH;
