# frost-btc-state-machine

## Development environment setup

1. `rustup update nightly`
2. `rustup component add rustfmt clippy`

## Background

### FROST

FROST protocol is split into two sub-protocols
1. DKG protocol - sets up a signing group so that each party receives a fairly computed and verifiable signing share.
2. Signing protocol - utilises at least t of n signing shares to construct a signature.


