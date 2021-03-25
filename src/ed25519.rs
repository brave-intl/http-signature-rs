use std::convert::TryFrom;
use std::error::Error;

use data_encoding::BASE64;
use ed25519_dalek::{Signature, Signer, Verifier};

use crate::key::{Algorithm, Key, SigningKey, VerificationKey};

impl SigningKey for ed25519_dalek::Keypair {
    fn sign_string(&self, message: &str) -> Result<String, Box<dyn Error>> {
        let sig = self.sign(message.as_bytes());
        Ok(BASE64.encode(&sig.to_bytes()))
    }
}

impl<T> Key for T
where
    T: Verifier<Signature>,
{
    const ALGORITHM: Algorithm = Algorithm::Ed25519;
}

impl<T> VerificationKey for T
where
    T: Verifier<Signature>,
{
    fn verify_signature_string(&self, message: &str, sig: &str) -> Result<(), Box<dyn Error>> {
        let sig = BASE64.decode(sig.as_bytes())?;
        let signature = Signature::try_from(sig.as_slice())?;
        Ok(self.verify(message.as_bytes(), &signature)?)
    }
}
