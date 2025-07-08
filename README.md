# FROST Signing State Machine for Bitcoin

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
    (a local `regtest` node for development or a public `signet` node) to fetch the necessary 
    UTXO data for signing and to broadcast the final, signed transaction to the network.


## Development environment setup

1. `rustup update nightly`
2. `rustup component add rustfmt clippy`

## Running Demo

### Step 1: Generate threshold keys

First, you need to create the set of key shares for your signing group. This command will create 
a 2-of-3 setup, meaning you have 3 participants, and any 2 of them are required to sign a 
transaction.

Run the following command in your terminal:

```shell
cargo run -p frost-demo -- keygen --threshold 2 --parties 3 --output keys.json
```

### Step 2: Fund group address

Use the `fund` command to derive and display the address for the network you want to use (`signet`).

Run the following command to derive group address:

```shell
cargo run -p frost-demo -- fund --keys keys.json --network signet
```

Fund the group address using one of Bitcoin Faucets: 
- Signet: https://signetfaucet.com/
- Testnet: https://bitcoinfaucet.uo1.net/

Block Explorer:
- Signet: https://mempool.space/signet/address/tb1pfxu44k5mxv52vw379jkcj9mal7mg2wwreddwr55ugzzsscptlrdsu0tt44
- Testnet: https://mempool.space/testnet/address/tb1pfxu44k5mxv52vw379jkcj9mal7mg2wwreddwr55ugzzsscptlrdsu0tt44

### Step 3: Spend from group address

Use the `spend` command to send funds from group address to some other address (e.g. `tb1pfxu44k5mxv52vw379jkcj9mal7mg2wwreddwr55ugzzsscptlrdsu0tt44`).

```shell
cargo run -p frost-demo -- spend --keys keys.json --network testnet --utxo "1366804a53d06733099536f4d9341830d7d80876fa2f407d5e7c0661bd288faa:0" --to "tb1pxaymxlg6kus0kfj6fs42t5306jjnxteam99x2jyyjf7qwen7qjjseqxpcq" --amount 1000
```

and check block explorer to find your spend tx: https://mempool.space/signet/address/tb1pxaymxlg6kus0kfj6fs42t5306jjnxteam99x2jyyjf7qwen7qjjseqxpcq

## Testing

### Bitcoint Networks

1. Develop and debug on `regtest`:

   1. Run a local bitcoin node in `regtest` mode:
        ```shell
        docker stop regtest-node &> /dev/null; docker rm regtest-node &> /dev/null

        docker run -d --name regtest-node \
        -v ~/bitcoin-regtest-data:/home/bitcoin/.bitcoin \
        -p 18443:18443 \
        ruimarinho/bitcoin-core:0.21.1 \
        -regtest \
        -server=1 \
        -txindex \
        -rpcbind=0.0.0.0 \
        -rpcallowip=0.0.0.0/0
        ```

2. Create wallet:
```shell
docker exec regtest-node bitcoin-cli -regtest createwallet "mywallet"
```

3. Generate spendable coins:
   docker exec regtest-node bitcoin-cli -regtest -generate 101
      
   2. Run your spend command pointing to it:

2. Validate and stage on `sigtest`
