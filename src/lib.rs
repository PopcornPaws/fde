#![deny(clippy::all)]
#![deny(clippy::dbg_macro)]
#![deny(unused_crate_dependencies)]

pub mod adaptor_sig;
pub mod backend;
pub mod commit;
pub mod dleq;
pub mod encrypt;
pub mod hash;

#[cfg(feature = "parallel")]
use rayon as _;

#[cfg(test)]
mod test {
    use criterion as _;
}
