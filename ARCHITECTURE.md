# FROST Demo Application Architecture

## Background

### FROST

FROST protocol is split into two sub-protocols:

1. DKG protocol - sets up a signing group so that each party receives a fairly computed and verifiable signing share.
2. Signing protocol - utilises at least t of n signing shares to construct a signature:
    1. Round 1 - commitment messages for t participants
    2. Round 2 - incomming signature shares

[TBD] ...
