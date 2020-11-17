use core::fmt::{self, Display};
use std::error::Error;

#[derive(Clone, Debug, PartialEq)]
pub enum Algorithm {
    Ed25519,
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Algorithm::Ed25519 => write!(f, "ed25519"),
        }
    }
}

pub trait SigningKey {
    fn algorithm() -> Algorithm;
    fn sign_string(&self, message: &str) -> Result<String, Box<dyn Error>>;
}

pub trait VerificationKey {
    fn algorithm() -> Algorithm;
    fn verify_signature_string(&self, message: &str, sig: &str) -> Result<(), Box<dyn Error>>;
}
