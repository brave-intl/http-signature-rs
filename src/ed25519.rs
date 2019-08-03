use data_encoding::BASE64;
use ed25519_dalek;

use crate::key::{Algorithm, SigningKey, VerificationKey};

impl SigningKey for ed25519_dalek::Keypair {
    fn algorithm() -> Algorithm {
        Algorithm::Ed25519
    }

    fn sign(&self, message: &str) -> Result<String, String> {
        let sig = self.sign(message.as_bytes());
        Ok(BASE64.encode(&sig.to_bytes()))
    }
}

impl VerificationKey for ed25519_dalek::PublicKey {
    fn algorithm() -> Algorithm {
        Algorithm::Ed25519
    }

    fn verify(&self, message: &str, sig: &str) -> Result<(), String> {
        let sig = BASE64.decode(sig.as_bytes()).map_err(|e| e.to_string())?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig).map_err(|e| e.to_string())?;
        self.verify(message.as_bytes(), &signature)
            .map_err(|e| e.to_string())
    }
}
