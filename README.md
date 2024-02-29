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

Below follows a short introduction to the implementation of the protocols in the paper.
**IMPORTANT** this is an unaudited, proof-of-concept implementation used mainly for benchmarking and exploring practical feasibility and limitations. Do not use this code in a production environment.

### ElGamal encryption-based

This [version](https://github.com/PopcornPaws/fde/tree/main/src/veck/kzg/elgamal) of the protocol uses exponential ElGamal encryption for generating the ciphertexts. Plaintext data is represented by scalar field elements of the BLS12-381 curve. Since exponential ElGamal relies on a brute-force approach to decrypt the ciphertexts, we needed to ensure that the encrypted scalar field elements are split up into multiple `u32` shards that are easier to decrypt than a single 256 bit scalar. Thus we needed an additional [encryption proof](https://github.com/PopcornPaws/fde/blob/main/src/veck/kzg/elgamal/encryption.rs) whose goal is to prove that the plaintext shards are indeed in the range of `0..u32::MAX` and we also needed to ensure that the plaintext shards can be used to reconstruct the original 256 bit scalar. For this we used simple [`DLEQ` proofs](https://github.com/PopcornPaws/fde/blob/main/src/dleq.rs). For the [range proofs](https://github.com/PopcornPaws/fde/tree/main/src/range_proof), we used a slightly modified version of [this](https://github.com/roynalnaruto/range_proof) implementation, that is based on the work of [Boneh-Fisch-Gabizon-Williamson](https://hackmd.io/@dabo/B1U4kx8XI) with further details discussed in [this blogpost](https://decentralizedthoughts.github.io/2020-03-03-range-proofs-from-polynomial-commitments-reexplained/).

### Paillier encryption-based

This [version](https://github.com/PopcornPaws/fde/blob/main/src/veck/kzg/paillier/mod.rs) of the protocol uses the Paillier encryption scheme to encrypt the plaintext data. It utilizes the [num-bigint](https://crates.io/crates/num-bigint) crate for proof generation due to working in an RSA group instead of a elliptic curve. Computations are therefore slightly less performant than working with [arkworks](https://github.com/arkworks-rs) libraries, but we gain a lot in the decryption phase where there is no need to split up the original plaintext, generate range proofs and use a brute-force approach for decryption.

## On-chain components of our protocols

## Benchmarks
