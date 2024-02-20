# Atomic BlockChain Data Exchange (BDE) with Fairness

BDE protocols allow a server and a client to exchange a KZG committed data securely and fairly. 
The server holds the entire data, while the client only knows a KZG (polynomial commitment) to the data. For more details on the protocol we refer to our research paper.

Title: Atomic BlockChain Data Exchange with Fairness

Authors: Ertem Nusret Tas, Valeria Nikolaenko, István A. Seres, Márk Melczer, Yinuo Zhang, Mahimna Kelkar, Joseph Bonneau. 

Currently available at the following links:
* IACR [eprint link](https://eprint.iacr.org/2024/420.pdf). (Gotta update this later)
* Researchgate [link](). (Gotta update this later)

## Quickstart

Requires [Foundry](https://book.getfoundry.sh/getting-started/installation).

Install: `forge install`

Build: `forge build`

Differential tests: `forge test --match-test testRef --ffi`

Other tests: `forge test --no-match-test testRef`


## Implemented BDE protocols

### ElGamal encryption-based

### Paillier encryption-based

## On-chain components of our protocols

## Benchmarks
