# bitcoin

Tern's Bitcoin escrow script (`tern-bitcoin-script`): the Taproot output of the protocol spec's section 8, and the
transactions that fulfill, expire and reject it.

## Tests

    cargo test

Unit tests need nothing. The regtest tests in `tests/` start their own `bitcoind`: by default the Bitcoin Core
release that `corepc-node` downloads and checks at build time, or the binary named by `BITCOIND_EXE`.

Part of Tern, built by Unit Labs.
