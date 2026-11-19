// Each test file uses a different subset of these helpers.
#![allow(dead_code)]

use bitcoin::consensus::deserialize;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::hex::FromHex;
use bitcoin::key::{Keypair, XOnlyPublicKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use corepc_node::Node;
use corepc_node::serde_json::{Value, json};
use tern_bitcoin_script::Escrow;

pub fn keypair(seed: u8) -> Keypair {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[seed; 32]).expect("non-zero seed")
}

pub fn key(seed: u8) -> XOnlyPublicKey {
    keypair(seed).x_only_public_key().0
}

pub fn pay_to(seed: u8) -> ScriptBuf {
    ScriptBuf::new_p2tr(&Secp256k1::new(), key(seed), None)
}

pub fn condition(fulfillment: &[u8; 32]) -> [u8; 32] {
    sha256::Hash::hash(fulfillment).to_byte_array()
}

/// A regtest `bitcoind` of its own (temp data dir, free ports), stopped when dropped.
pub struct Regtest {
    node: Node,
}

impl Regtest {
    /// Mines 101 blocks so the wallet holds a spendable coinbase.
    pub fn start() -> Self {
        let exe = corepc_node::exe_path()
            .expect("bitcoind: set BITCOIND_EXE or keep the download feature");
        let regtest = Self {
            node: Node::new(exe).expect("start bitcoind"),
        };
        regtest.mine(101);
        regtest
    }

    fn rpc(&self, method: &str, params: &[Value]) -> Value {
        self.node
            .client
            .call::<Value>(method, params)
            .unwrap_or_else(|e| panic!("{method}: {e}"))
    }

    fn decode(hex: &str) -> Transaction {
        deserialize(&Vec::<u8>::from_hex(hex).expect("hex")).expect("transaction")
    }

    pub fn mine(&self, blocks: u64) {
        let address = self.rpc("getnewaddress", &[]);
        self.rpc("generatetoaddress", &[json!(blocks), address]);
    }

    pub fn median_time_past(&self) -> u32 {
        let time = self.rpc("getblockchaininfo", &[])["mediantime"]
            .as_u64()
            .expect("mediantime");
        u32::try_from(time).expect("before 2106")
    }

    /// Sets the node's clock to `time` and mines 11 blocks stamped with it, so median time past reaches `time`.
    pub fn advance_to(&self, time: u32) {
        self.rpc("setmocktime", &[json!(time)]);
        self.mine(11);
    }

    /// Pays `amount` to the escrow's address from the wallet and confirms it.
    pub fn fund(&self, escrow: &Escrow, amount: Amount) -> (OutPoint, TxOut) {
        let address = escrow.address(Network::Regtest).to_string();
        let txid = self.rpc("sendtoaddress", &[json!(address), json!(amount.to_btc())]);
        self.mine(1);
        let hex = self.rpc("gettransaction", &[txid])["hex"]
            .as_str()
            .expect("hex")
            .to_owned();
        let tx = Self::decode(&hex);
        let script = escrow.script_pubkey();
        let vout = tx
            .output
            .iter()
            .position(|out| out.script_pubkey == script)
            .expect("escrow output");
        (
            OutPoint::new(tx.compute_txid(), vout as u32),
            tx.output[vout].clone(),
        )
    }

    /// `Err(reject-reason)` when the mempool would refuse `tx`.
    pub fn check(&self, tx: &Transaction) -> Result<(), String> {
        let result = &self.rpc("testmempoolaccept", &[json!([serialize_hex(tx)])])[0];
        match result["allowed"].as_bool() {
            Some(true) => Ok(()),
            _ => Err(result["reject-reason"].to_string()),
        }
    }

    /// Broadcasts `tx` (panicking on rejection) and mines it.
    pub fn confirm(&self, tx: &Transaction) {
        self.rpc("sendrawtransaction", &[json!(serialize_hex(tx))]);
        self.mine(1);
    }

    pub fn is_spent(&self, utxo: OutPoint) -> bool {
        self.rpc(
            "gettxout",
            &[json!(utxo.txid.to_string()), json!(utxo.vout)],
        )
        .is_null()
    }

    /// What the relayer and keeper do with pre-signed pairs (ADR-0001, decision 7): add a wallet input that pays
    /// the fee and an output for its change, then sign that input. `prevouts` are what the existing inputs spend.
    pub fn add_fee(&self, mut tx: Transaction, prevouts: &[TxOut]) -> Transaction {
        let coin = self
            .rpc("listunspent", &[])
            .as_array()
            .expect("array")
            .iter()
            .find(|coin| coin["amount"].as_f64().unwrap_or(0.0) >= 0.01)
            .expect("a spendable wallet coin")
            .clone();
        let value = Amount::from_btc(coin["amount"].as_f64().expect("amount")).expect("amount");
        let txid: Txid = coin["txid"].as_str().expect("txid").parse().expect("txid");
        let vout = u32::try_from(coin["vout"].as_u64().expect("vout")).expect("vout");
        let change =
            ScriptBuf::from_hex(coin["scriptPubKey"].as_str().expect("script")).expect("script");

        tx.input.push(TxIn {
            previous_output: OutPoint::new(txid, vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
        tx.output.push(TxOut {
            value: value - Amount::from_sat(2_000),
            script_pubkey: change,
        });

        let witnesses: Vec<Witness> = tx.input.iter().map(|input| input.witness.clone()).collect();
        let known: Vec<Value> = tx
            .input
            .iter()
            .zip(prevouts)
            .map(|(input, prevout)| {
                json!({
                    "txid": input.previous_output.txid.to_string(),
                    "vout": input.previous_output.vout,
                    "scriptPubKey": prevout.script_pubkey.to_hex_string(),
                    "amount": prevout.value.to_btc(),
                })
            })
            .collect();
        let signed = self.rpc(
            "signrawtransactionwithwallet",
            &[json!(serialize_hex(&tx)), json!(known)],
        );
        let mut tx = Self::decode(signed["hex"].as_str().expect("hex"));
        // The wallet can't sign the escrow inputs and may drop their witnesses, so put them back.
        for (input, witness) in tx.input.iter_mut().zip(witnesses) {
            if !witness.is_empty() {
                input.witness = witness;
            }
        }
        tx
    }
}
