//! Keys for signing and verifying http signatures
use core::fmt::{self, Display};
use std::error::Error;
use std::str::FromStr;

/// Supported signature algorithms
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

impl FromStr for Algorithm {
    type Err = Box<dyn Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ed25519" => Ok(Algorithm::Ed25519),
            _ => Err("Unsupported algorithm".to_string().into()),
        }
    }
}

/// A key which can be used for either signing or verifying
pub trait Key {
    const ALGORITHM: Algorithm;
}

/// A key which can be used to sign an http request
pub trait SigningKey {
    fn sign_string(&self, message: &str) -> Result<String, Box<dyn Error>>;
}

/// A key which can be used to verify a signed http request
pub trait VerificationKey {
    fn verify_signature_string(&self, message: &str, sig: &str) -> Result<(), Box<dyn Error>>;
}
