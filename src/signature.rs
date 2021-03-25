use core::fmt::{self, Display};
use std::error::Error;

use crate::digest::{DigestAlgorithm, DIGEST_HEADER};
use crate::key::{Algorithm, SigningKey, VerificationKey};
use http;

/// SignatureHeader is the header consisting the HTTP signature
pub static SIGNATURE_HEADER: &str = "signature";
/// RequestTargetHeader is a pseudo header consisting of the HTTP method and request uri
pub static REQUEST_TARGET_HEADER: &str = "(request-target)";

/// Signature represents an http signature and it's parameters
#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    sig: String,
    params: SignatureParams,
}

impl Signature {
    pub(crate) fn new(params: &SignatureParams, sig: &str) -> Self {
        return Signature {
            params: params.clone(),
            sig: sig.to_string(),
        };
    }

    /// Verify that the request was signed according to the signature parameters using keypair K
    pub fn verify<K, T>(
        params: &SignatureParams,
        key: K,
        req: &http::Request<T>,
    ) -> Result<(), Box<dyn Error>>
    where
        K: VerificationKey,
        T: AsRef<[u8]>,
    {
        // TODO allow for parameters signed to include additional headers
        let signing_string = params.signing_string(req)?;

        let signature_header = req
            .headers()
            .get(SIGNATURE_HEADER)
            .ok_or("Header did not exist in the request")?
            .to_str()
            .map_err(|e| e.to_string())?;

        let sig = signature_header
            .split(',')
            .find(|x| x.starts_with("signature="))
            .ok_or("Could not find signature".to_string())?
            .to_string();
        let (_, sig) = sig.split_at(sig.find("=").ok_or("Signature was malformed".to_string())?);

        key.verify_signature_string(&signing_string, sig)
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let headers = self
            .params
            .headers
            .as_ref()
            .map(|headers| -> Vec<String> {
                headers.iter().map(|h| h.as_str().to_string()).collect()
            })
            .map(|headers| format!(",headers=\"{}\"", headers.join(" ")).to_string())
            .unwrap_or("".to_string());

        write!(
            f,
            "keyId=\"{}\",algorithm=\"{}\"{},signature=\"{}\"",
            self.params.key_id, self.params.algorithm, headers, self.sig
        )
    }
}

/// SignatureParams contains parameters needed to create and verify signatures
#[derive(Clone, Debug, PartialEq)]
pub struct SignatureParams {
    algorithm: Algorithm,
    key_id: String,
    headers: Option<Vec<String>>,
}

impl SignatureParams {
    pub fn new<K>(_key: &K, key_id: &str, headers: &[&str]) -> Self
    where
        K: SigningKey,
    {
        SignatureParams {
            algorithm: K::algorithm(),
            key_id: key_id.to_string(),
            headers: headers.first().and(Some(
                headers.iter().map(|header| header.to_string()).collect(),
            )),
        }
    }

    /// signing_string builds the signing string according to the SignatureParams s and
    /// HTTP request req. it recalculates the digest header to ensure it is correct
    pub fn signing_string<T>(&self, req: &http::Request<T>) -> Result<String, Box<dyn Error>>
    where
        T: AsRef<[u8]>,
    {
        let header_strings: Result<Vec<String>, Box<dyn Error>> = self
            .headers
            .as_ref()
            .unwrap_or(&vec![http::header::DATE.to_string()])
            .iter()
            .map(|header| -> Result<String, Box<dyn Error>> {
                Ok(match header.as_str() {
                    "(request-target)" => format!(
                        "{}: {} {}",
                        REQUEST_TARGET_HEADER,
                        req.method().as_str().to_lowercase(),
                        req.uri()
                            .path_and_query()
                            .ok_or("Could not retrieve path and query".to_string())?
                            .as_str(),
                    ),
                    "digest" => {
                        let digest = req
                            .headers()
                            .get(DIGEST_HEADER)
                            .ok_or("Digest header did not exist in the request")?
                            .to_str()
                            .map_err(|e| e.to_string())?;

                        let algorithm = DigestAlgorithm::from_digest(digest)?;
                        if algorithm.calculate(req) != digest {
                            return Err(
                                "The included digest header did not match the calculated value"
                                    .into(),
                            );
                        }
                        format!("{}: {}", header, digest)
                    }
                    _ => format!(
                        "{}: {}",
                        header,
                        req.headers()
                            .get(header)
                            .ok_or("Header did not exist in the request")?
                            .to_str()
                            .map_err(|e| e.to_string())?
                    ),
                })
            })
            .collect();

        Ok(header_strings?.join("\n"))
    }

    /// Sign the provided HTTP request req using key and these parameters
    pub fn sign<K, T>(
        &self,
        key: K,
        mut req: http::Request<T>,
    ) -> Result<http::Request<T>, Box<dyn Error>>
    where
        K: SigningKey,
        T: AsRef<[u8]>,
    {
        let sig = key.sign_string(&self.signing_string(&mut req)?)?;

        let s = Signature::new(self, &sig);

        req.headers_mut().insert(
            SIGNATURE_HEADER,
            http::header::HeaderValue::from_str(&s.to_string()).map_err(|e| e.to_string())?,
        );

        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;
    use ed25519_dalek::Keypair;
    use http;

    use super::*;
    use crate::digest::WithDigest;

    #[test]
    fn test_vector() {
        let mut builder = http::Request::builder();
        builder.method("PUT");
        builder.uri("https://example.com/");

        let req = builder
            .body("{\"destination\":\"15258332-6f54-4b5f-8b2e-3b074c3be78a\",\"denomination\":{\"currency\":\"BAT\",\"amount\":\"20\"}}".as_bytes().to_vec())
            .unwrap()
            .with_digest(DigestAlgorithm::SHA256)
            .unwrap();

        let keypair: Keypair = Keypair::from_bytes(&HEXLOWER.decode(b"38a27e71c47efe0d50a30dd12eb4dc97e9057a11b04f4e3b58c6f0796caeb2e1d391c6f6cf8778e0801d2bfb32441d40ae4b6864040e92cb063449eb8d2a39e1").unwrap()).unwrap();

        let headers = vec!["digest"];
        let params = SignatureParams::new(&keypair, "primary", &headers);

        let req = params.sign(keypair, req).unwrap();

        assert_eq!(
            req.headers().get("digest").unwrap().to_str().unwrap(),
            "SHA-256=b1AfsYDe45TF9w9h6jv/xuvEYdchYzJ67PFMifsDwIA=",
        );

        assert_eq!(
            req.headers().get("signature").unwrap().to_str().unwrap(), 
            "keyId=\"primary\",algorithm=\"ed25519\",headers=\"digest\",signature=\"3Jibr+qWVQ+HhRQDt4gEoaD7lLcJggLLyX2yYODs4Y4tluo6EDLGqUDkrc+dGoatNDE/BbrXx686Z9zJeMjKCA==\"",
        );
    }
}
