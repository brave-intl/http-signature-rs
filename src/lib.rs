#![feature(external_doc)]
//!
#[doc(include = "../README.md")]
mod digest;
mod ed25519;
pub mod key;
mod signature;

pub use digest::*;
pub use signature::*;
