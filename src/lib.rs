#![deny(clippy::all)]
#![deny(clippy::dbg_macro)]
#![deny(unused_crate_dependencies)]

pub mod adaptor_sig;
pub mod commit;
pub mod dleq;
pub mod encrypt;
pub mod hash;
pub mod range_proof;
#[cfg(test)]
mod tests;
pub mod veck;

use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("couldn't generate valid FFT domain of size {0}")]
    InvalidFftDomain(usize),
    #[error(transparent)]
    RangeProof(#[from] range_proof::Error),
    #[error(transparent)]
    KzgElgamalProofError(#[from] veck::kzg::elgamal::Error),
    #[error(transparent)]
    KzgPaillierProofError(#[from] veck::kzg::paillier::Error),
}
