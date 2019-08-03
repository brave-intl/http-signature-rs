use core::fmt::{self, Display};

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
    fn sign(&self, message: &str) -> Result<String, String>;
}

pub trait VerificationKey {
    fn algorithm() -> Algorithm;
    fn verify(&self, message: &str, sig: &str) -> Result<(), String>;
}
