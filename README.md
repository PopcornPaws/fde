# Atomic BlockChain Data Exchange with Fairness

FDE protocols allow a server and a client to exchange KZG-committed data securely and fairly. 
The server holds all the data, while the client only knows a KZG (polynomial commitment) to the data. For more details on the protocol, refer to our research paper.
This protocol is useful for Ethereum in a post [EIP-4844](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4844.md) world. In particular, blocks will contain blob data (KZG commitments) that commit to rollup data. The block header only contains KZG commitments, while full nodes store the entire data. It is reasonable to assume that an efficient market will emerge for downloading rollup data from full nodes.
This work creates protocols that allow full nodes to exchange the committed data for money in an atomic and fair manner.

Title: Atomic BlockChain Data Exchange with Fairness

Authors: Ertem Nusret Tas, Valeria Nikolaenko, István A. Seres, Márk Melczer, Yinuo Zhang, Mahimna Kelkar, Joseph Bonneau. 

Currently available at the following link:
* IACR [eprint link](https://eprint.iacr.org/2024/418.pdf).

## Quickstart

The protocols in the paper are implemented in the [Rust programming language](https://www.rust-lang.org/), relying heavily on cryptographic libraries from [arkworks](https://github.com/arkworks-rs). The source code is found in [src](https://github.com/PopcornPaws/fde/tree/main/src). Respective smart contracts were implemented in [Solidity](https://soliditylang.org/) and they are found in [contracts](https://github.com/PopcornPaws/fde/tree/main/contracts).

### Installing, building, and running tests

First, you must install `rustup` by following the steps outlined [here](https://www.rust-lang.org/learn/get-started).

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone the repository and jump into the cloned directory
```sh
git clone https://github.com/PopcornPaws/fde.git
cd fde
```
- build: `cargo build --release` (the `release` flag is optional)
- test: `cargo test --release` (the `release` flag is optional)
- benchmark: `cargo bench`

### Contracts
Requires [Foundry](https://book.getfoundry.sh/getting-started/installation).

Install: `forge install`

Build: `forge build`

Differential tests: `forge test --match-test testRef --ffi`

Other tests: `forge test --no-match-test testRef`


## Implemented BDE protocols

Below is a short introduction to the implementation of the protocols in the paper.
**IMPORTANT** This is an unaudited, proof-of-concept implementation used mainly for benchmarking and exploring practical feasibility and limitations. Do not use this code in a production environment.

### ElGamal encryption-based

This [version](https://github.com/PopcornPaws/fde/tree/main/src/veck/kzg/elgamal) of the protocol uses exponential ElGamal encryption for generating the ciphertexts. Plaintext data is represented by scalar field elements of the BLS12-381 curve. Since exponential ElGamal relies on a brute-force approach to decrypt the ciphertexts, we needed to ensure that the encrypted scalar field elements are split up into multiple `u32` shards that are easier to decrypt than a single 256-bit scalar. Thus we needed an additional [encryption proof](https://github.com/PopcornPaws/fde/blob/main/src/veck/kzg/elgamal/encryption.rs) whose goal is to prove that the plaintext shards are indeed in the range of `0..u32::MAX` and we also needed to ensure that the plaintext shards can be used to reconstruct the original 256 bit scalar. For this, we used simple [`DLEQ` proofs](https://github.com/PopcornPaws/fde/blob/main/src/dleq.rs). For the [range proofs](https://github.com/PopcornPaws/fde/tree/main/src/range_proof), we used a slightly modified version of [this](https://github.com/roynalnaruto/range_proof) implementation, that is based on the work of [Boneh-Fisch-Gabizon-Williamson](https://hackmd.io/@dabo/B1U4kx8XI) with further details discussed in [this blogpost](https://decentralizedthoughts.github.io/2020-03-03-range-proofs-from-polynomial-commitments-reexplained/).

### Paillier encryption-based

This [version](https://github.com/PopcornPaws/fde/blob/main/src/veck/kzg/paillier/mod.rs) of the protocol uses the Paillier encryption scheme to encrypt the plaintext data. It utilizes the [num-bigint](https://crates.io/crates/num-bigint) crate for proof generation due to working in an RSA group instead of an elliptic curve. Computations are, therefore, slightly less performant than working with [arkworks](https://github.com/arkworks-rs) libraries, but we gain a lot in the decryption phase where there is no need to split up the original plaintext, generate range proofs, and use a brute-force approach for decryption.

## On-chain components of our protocols
Our protocols apply smart contracts to achieve atomicity and fairness. Have a look at our [implemented FDE smart contracts](https://github.com/PopcornPaws/fde/blob/main/contracts/FDE.sol).
## Benchmarks
We provide benchmarks in [this folder](https://github.com/PopcornPaws/fde/tree/main/benches).
## Contributing
We welcome any contributions. Feel free to [open new issues](https://github.com/PopcornPaws/fde/issues/new) or [resolve existing ones](https://github.com/PopcornPaws/fde/issues).

## Disclaimer
*The code is being provided as is. No guarantee, representation or warranty is being made, express or implied, as to the safety or correctness of the code. The code has not been audited and as such there can be no assurance it will work as intended, and users may experience delays, failures, errors, omissions or loss of transmitted information. THE CODE CONTAINED HEREIN IS FURNISHED AS IS, WHERE IS, WITH ALL FAULTS AND WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING ANY WARRANTY OF MERCHANTABILITY, NON- INFRINGEMENT OR FITNESS FOR ANY PARTICULAR PURPOSE. Further, use of any of the smart contracts may be restricted or prohibited under applicable law, including securities laws, and it is therefore strongly advised for you to contact a reputable attorney in any jurisdiction where these smart contracts may be accessible for any questions or concerns with respect thereto. Further, no information provided in this repo should be construed as investment advice or legal advice for any particular facts or circumstances, and is not meant to replace competent counsel. The authors are not liable for any use of the foregoing, and users should proceed with caution and use at their own risk.*
