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
    (a local `regtest` node for development or a public `testnet` node) to fetch the necessary 
    UTXO data for signing and to broadcast the final, signed transaction to the network.


## Development environment setup

1. `rustup update nightly`
2. `rustup component add rustfmt clippy`

## Running Demo

### Step 1: Generate Your Threshold Keys

First, you need to create the set of key shares for your signing group. This command will create 
a 2-of-3 setup, meaning you have 3 participants, and any 2 of them are required to sign a 
transaction.

Run the following command in your terminal:

```shell
cargo run -p frost-demo -- keygen --threshold 2 --parties 3 --output keys.json
```

This will create a keys.json file in your project directory. This file contains the public group 
key and the private shares for each of the three participants.

## Testing

### Bitcoint Networks

1. Develop and debug on `regtest`:

   1. Run a local bitcoin node in `regtest` mode:
        ```shell
        # The -fallbackfee is useful to avoid issues with fee estimation
        bitcoind -regtest -txindex=1 -fallbackfee=0.0001
        ```
   2. Run your spend command pointing to it:

2. Validate and stage on `testnet`
