# FROST Signing State Machine for Bitcoin

## CLI

```shell
Usage: frost-demo <COMMAND>

Commands:
keygen         Generate threshold key shares
group-address  Derives and prints the group address for a given network to be funded
spend          Spend from a threshold address
help           Print this message or the help of the given subcommand(s)

Options:
-h, --help  Print help
```

*By default, application is pre-configured to connect to Bitcoin Testnet (see [main.rs](src/main.rs#10))

## TL;DR

This project is a command-line application that provides a complete, end-to-end demonstration of 
**FROST (Flexible Round-Optimized Schnorr Threshold) signatures** for Bitcoin Taproot transactions. 
It demonstrates how multi-party computation (MPC) can be applied to create secure, distributed 
Bitcoin wallets.

The application orchestrates the entire lifecycle of a threshold signature transaction:

1.  **Key Generation using Trusted Dealer (non-DKG)**: 
    Generate a set of cryptographic key shares using a **trusted dealer model**, where a central 
    coordinator creates and distributes the shares to participants.

2.  **Collaborative Signing Ceremony**: Simulate the multi-round FROST protocol where a threshold 
    of participants work together to produce a single, valid Schnorr signature for a transaction, 
    without revealing their individual key shares.

3.  **Live Bitcoin Network Interaction**: Connect to a Bitcoin node 
    (defaults to pre-configured public Bitcoin Testnet node) to fetch the necessary 
    UTXO data for signing and to broadcast the final, signed transaction to the network.

## Architecture
- See: [ARCHITECTURE.md](ARCHITECTURE.md)


## Development environment setup

1. `rustup update nightly`
2. `rustup component add rustfmt clippy`

### Note:
- This application is using bitcoin JSON-RPC to communicate with blockchain and depends on `rust-bitcoincore-rpc`,
    which at the time of writing does not support HTTPS, so it has been patched (and overwritten in [Cargo.toml](Cargo.toml)) with HTTPS client: https://github.com/andreasbros/rust-bitcoincore-rpc/tree/fix/https 

## Running Demo

### Step 1: Generate threshold keys

First, you need to create the set of key shares for your signing group. This command will create 
a 2-of-3 setup, meaning you have 3 participants, and any 2 of them are required to sign a 
transaction.

**Run the following command in your terminal:**

```shell
cargo run -p frost-demo -- keygen --threshold 2 --parties 3 --output keys.json
```

### Step 2: Fund group address

Use the `group-address` command to derive and display the public bitcoin address for the multiseg group.

**Run the following comman:**

```shell
cargo run -p frost-demo -- group-address --keys keys.json --network testnet
```

**Fund the group address using one of the Bitcoin Faucets:**
- Testnet: https://bitcoinfaucet.uo1.net/, https://coinfaucet.eu/en/btc-testnet/

**Block Explorer:**
- Testnet: https://mempool.space/testnet/address/tb1py0wg4a969ary6zugut7dw4jrtvkm09avmrkuh49l02pms3dak26qwx5j06

### Step 3: Spend from group address

Use the `spend` command to send funds from group address to some other address (e.g. `tb1pfxu44k5mxv52vw379jkcj9mal7mg2wwreddwr55ugzzsscptlrdsu0tt44`).

By default, frost-demo application is configured to connect to public Bitcoin Testnet, you can override to your own network by providing params: `--network`, `--rpc-url`, `--rpc-user`, `--rpc-pass`

```shell
cargo run -p frost-demo -- spend --keys keys.json --network testnet --utxo "ae896675014b9d70667d0e947dc1e2e044e9e033f8313e63bcc5da66734d0b6c:1" --to "tb1pxaymxlg6kus0kfj6fs42t5306jjnxteam99x2jyyjf7qwen7qjjseqxpcq" --amount 1000
```

**Output:**
```log
INFO Spending 1000 sats to tb1pxaymxlg6kus0kfj6fs42t5306jjnxteam99x2jyyjf7qwen7qjjseqxpcq on the Testnet network...
INFO Starting FROST signing ceremony...
INFO run_signing_ceremony{session_id=12803949026742368891}: Starting signing ceremony.
INFO run_signing_ceremony{session_id=12803949026742368891}: Initiating Round 1: Generating and broadcasting commitments.
INFO run_signing_ceremony{session_id=12803949026742368891}: Collecting nonce commitments from all participants.
INFO run_signing_ceremony{session_id=12803949026742368891}: Initiating Round 2: Generating and broadcasting signature shares.
INFO run_signing_ceremony{session_id=12803949026742368891}: Collecting signature shares from all participants.
INFO run_signing_ceremony{session_id=12803949026742368891}: Signing ceremony complete, transaction is finalized.
INFO Broadcasting signed transaction to the network...
INFO Transaction signed and broadcasted!
INFO TxID: 463c0bf03321b405093c78ab08dee735a9f16e3374aa655536b0ce54836ab9cb
```

and check block explorer to find your spend tx:
https://mempool.space/testnet/tx/463c0bf03321b405093c78ab08dee735a9f16e3374aa655536b0ce54836ab9cb

## Testing

- To run all tests: `cargo test -- --nocapture`
- To run specific tests: 
  - `cargo test --test test_main`
  - `cargo test --test test_frost_state_machine test_parallel_signing_ceremonies_are_isolated`
