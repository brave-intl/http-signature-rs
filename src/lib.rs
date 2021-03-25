#![cfg_attr(feature = "nightly", feature(external_doc))]
//!
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
mod digest;
mod ed25519;
pub mod key;
mod signature;

pub use digest::*;
pub use signature::*;
