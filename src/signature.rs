use core::fmt::{self, Display};
use std::error::Error;
use std::str::FromStr;
use std::collections::HashMap;

use crate::digest::{DigestAlgorithm, DIGEST_HEADER};
use crate::key::{Key, Algorithm, SigningKey, VerificationKey};

/// DATE_HEADER is the header containing the date the request originated
pub static DATE_HEADER: &str = "date";
/// REQUEST_TARGET_HEADER is a pseudo header consisting of the HTTP method and request uri
pub static REQUEST_TARGET_HEADER: &str = "(request-target)";
/// SIGNATURE_HEADER is the header consisting the HTTP signature
pub static SIGNATURE_HEADER: &str = "signature";

/// Signature represents an http signature and it's parameters
#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    sig: String,
    params: SignatureParams,
}

impl Signature {
    pub(crate) fn new(params: &SignatureParams, sig: &str) -> Self {
        Signature {
            params: params.clone(),
            sig: sig.to_string(),
        }
    }

    /// Verify that the request was signed according to the passed signature params using keypair K
    /// NOTE: this ignores the parameters within the signature header
    pub fn verify<K, T>(
        params: &SignatureParams,
        key: &K,
        req: &http::Request<T>,
    ) -> Result<(), Box<dyn Error>>
    where
        K: VerificationKey,
        T: AsRef<[u8]>,
    {
        // TODO allow for signature to include additional headers, currently must be
        // strictly equal to those in the parameters
        let signing_string = params.signing_string(req)?;

        let signature_header = req
            .headers()
            .get(SIGNATURE_HEADER)
            .ok_or("Header did not exist in the request")?
            .to_str()
            .map_err(|e| e.to_string())?;

        let sig: Signature = signature_header.parse()?;

        key.verify_signature_string(&signing_string, &sig.sig)
    }
}

impl FromStr for Signature {
    type Err = Box<dyn Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        println!("{:?}", s);
        let params: HashMap<&str,&str> = s.split(',')
                               .filter_map(|p| -> Option<(&str, &str)> {
                                   let mut p = p.splitn(2, '=');
                                   Some((p.next()?, p.next()?.trim_matches('"')))
                               })
                               .collect();
        println!("{:?}", params);
        let sig = params.get("signature").ok_or_else(|| "Missing required signature field".to_string())?.to_string();
        let algorithm = params.get("algorithm")
            .ok_or_else(|| "Missing required algorithm field".to_string())?
            .parse()?;
        let key_id = params.get("keyId").ok_or_else(|| "Missing required key_id field".to_string())?.to_string();
        let headers = params.get("headers").map(|h| h.split(' ').map(|s| s.to_string()).collect());

        Ok(Signature {
            sig: sig,
            params: SignatureParams {
                algorithm,
                key_id,
                headers,
            }
        })
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
            .map(|headers| format!(",headers=\"{}\"", headers.join(" ")))
            .unwrap_or_else(|| "".to_string());

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
        K: Key,
    {
        SignatureParams {
            algorithm: K::ALGORITHM,
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
            .unwrap_or(&vec![DATE_HEADER.to_string()])
            .iter()
            .map(|header| -> Result<String, Box<dyn Error>> {
                Ok(match header.as_str() {
                    "(request-target)" => format!(
                        "{}: {} {}",
                        REQUEST_TARGET_HEADER,
                        req.method().as_str().to_lowercase(),
                        req.uri()
                            .path_and_query()
                            .ok_or_else(|| "Could not retrieve path and query".to_string())?
                            .as_str(),
                    ),
                    "digest" => {
                        let digest = req
                            .headers()
                            .get(DIGEST_HEADER)
                            .ok_or("Digest header did not exist in the request")?
                            .to_str()
                            .map_err(|e| e.to_string())?;

                        let algorithm = DigestAlgorithm::from_digest_header(digest)?;
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
        key: &K,
        mut req: http::Request<T>,
    ) -> Result<http::Request<T>, Box<dyn Error>>
    where
        K: SigningKey,
        T: AsRef<[u8]>,
    {
        let sig = key.sign_string(&self.signing_string(&req)?)?;

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
    use ed25519_dalek::{Keypair, PublicKey};
    use http;

    use super::*;
    use crate::digest::WithDigest;

    // TODO add test to cover multiple headers with different capitalization
    // TODO add test covering request uri with query parameters
    // TODO add test covering no headers (date only)

    #[test]
    fn test_signing_string() {
        let keypair: Keypair = Keypair::from_bytes(&HEXLOWER.decode(b"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()).unwrap();
        let headers = vec![
            "(request-target)",
            "host",
            "date",
            "cache-control",
            "x-example",
        ];
        let params = SignatureParams::new(&keypair, "Test", &headers);

        let mut builder = http::Request::builder();
        builder.method("GET");
        builder.uri("https://example.com/foo");
        builder.header("Host", "example.org");
        builder.header("Date", "Tue, 07 Jun 2014 20:51:35 GMT");

        builder.header("X-Example", "Example header with some whitespace.");

        builder.header("Cache-Control", "max-age=60, must-revalidate");

        let req = builder.body(vec![]).unwrap();

        assert_eq!(
            params.signing_string(&req).unwrap(), 
"(request-target): get /foo\nhost: example.org\ndate: Tue, 07 Jun 2014 20:51:35 GMT\ncache-control: max-age=60, must-revalidate\nx-example: Example header with some whitespace."
        );
    }

    #[test]
    fn test_signature_to_string() {
        let mut sig = expected_signature();

	let expected = "keyId=\"Test\",algorithm=\"ed25519\",headers=\"(request-target) host date content-type digest content-length\",signature=\"Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9KaeQ4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0=\"";

        assert_eq!(sig.to_string(), expected);

	sig.params.headers = None;

	let expected = "keyId=\"Test\",algorithm=\"ed25519\",signature=\"Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9KaeQ4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0=\"";

        assert_eq!(sig.to_string(), expected);
    }

    fn expected_signature() -> Signature {
        let headers = vec!["(request-target)", "host", "date", "content-type", "digest", "content-length"];
	Signature {
            sig: "Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9KaeQ4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0=".to_string(),
            params: SignatureParams {
                algorithm: Algorithm::Ed25519,
                key_id: "Test".to_string(),
                headers: Some(headers.iter().map(|s| s.to_string()).collect()),
            }
        }
    }

    #[test]
    fn test_signature_from_str() {
	let marshalled = "keyId=\"Test\",algorithm=\"ed25519\",headers=\"(request-target) host date content-type digest content-length\",signature=\"Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9KaeQ4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0=\"";
        assert_eq!(marshalled.parse::<Signature>().unwrap(), expected_signature());
    }

    #[test]
    fn test_signature_from_str_duplicated() {
	let marshalled = "keyId=\"Foo\",algorithm=\"ed25519\",headers=\"(request-target) host date content-type digest content-length\",signature=\"Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9KaeQ4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0=\",keyId=\"Test\"";
        assert_eq!(marshalled.parse::<Signature>().unwrap(), expected_signature());
    }

    #[test]
    #[should_panic]
    fn test_signature_from_str_missing_required_field() {
	let marshalled = "algorithm=\"ed25519\",headers=\"(request-target) host date content-type digest content-length\",signature=\"Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9KaeQ4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0=\"";
        marshalled.parse::<Signature>().unwrap();
    }

    #[test]
    fn test_signature_from_str_optional() {
	let marshalled = "keyId=\"Test\",algorithm=\"ed25519\",signature=\"Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9KaeQ4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0=\"";
        let sig = marshalled.parse::<Signature>().unwrap();
        assert_eq!(sig.params.headers, None);
    }

    #[test]
    fn test_sign_string() {
        let keypair: Keypair = Keypair::from_bytes(&HEXLOWER.decode(b"96aa9ec42242a9a62196281045705196a64e12b15e9160bbb630e38385b82700e7876fd5cc3a228dad634816f4ec4b80a258b2a552467e5d26f30003211bc45d").unwrap()).unwrap();

        let headers = vec!["foo"];
        let params = SignatureParams::new(&keypair, "primary", &headers);

        let mut builder = http::Request::builder();
        builder.method("GET");
        builder.uri("https://example.com/foo");
        builder.header("Foo", "bar");

        let req = builder.body(vec![]).unwrap();

        let sig = keypair.sign_string(&params.signing_string(&req).unwrap()).unwrap();
        assert_eq!(
            sig,
            "RbGSX1MttcKCpCkq9nsPGkdJGUZsAU+0TpiXJYkwde+0ZwxEp9dXO3v17DwyGLXjv385253RdGI7URbrI7J6DQ==",
        );
    }

    #[test]
    fn test_sign_with_digest() {
        let keypair: Keypair = Keypair::from_bytes(&HEXLOWER.decode(b"38a27e71c47efe0d50a30dd12eb4dc97e9057a11b04f4e3b58c6f0796caeb2e1d391c6f6cf8778e0801d2bfb32441d40ae4b6864040e92cb063449eb8d2a39e1").unwrap()).unwrap();

        let headers = vec!["digest"];
        let params = SignatureParams::new(&keypair, "primary", &headers);

        let mut builder = http::Request::builder();
        builder.method("PUT");
        builder.uri("https://example.com/");

        let req = builder
            .body("{\"destination\":\"15258332-6f54-4b5f-8b2e-3b074c3be78a\",\"denomination\":{\"currency\":\"BAT\",\"amount\":\"20\"}}".as_bytes().to_vec())
            .unwrap()
            .with_digest(DigestAlgorithm::SHA256)
            .unwrap();

        let req = params.sign(&keypair, req).unwrap();

        assert_eq!(
            req.headers().get("digest").unwrap().to_str().unwrap(),
            "SHA-256=b1AfsYDe45TF9w9h6jv/xuvEYdchYzJ67PFMifsDwIA=",
        );

        assert_eq!(
            req.headers().get("signature").unwrap().to_str().unwrap(), 
            "keyId=\"primary\",algorithm=\"ed25519\",headers=\"digest\",signature=\"3Jibr+qWVQ+HhRQDt4gEoaD7lLcJggLLyX2yYODs4Y4tluo6EDLGqUDkrc+dGoatNDE/BbrXx686Z9zJeMjKCA==\"",
        );
    }

    #[test]
    fn test_verify() {
        let pub_key: PublicKey = PublicKey::from_bytes(&HEXLOWER.decode(b"e7876fd5cc3a228dad634816f4ec4b80a258b2a552467e5d26f30003211bc45d").unwrap()).unwrap();

        let headers = vec!["foo"];
        let params = SignatureParams::new(&pub_key, "primary", &headers);

        let sig = "RbGSX1MttcKCpCkq9nsPGkdJGUZsAU+0TpiXJYkwde+0ZwxEp9dXO3v17DwyGLXjv385253RdGI7URbrI7J6DQ==";

        let mut builder = http::Request::builder();
        builder.method("GET");
        builder.uri("https://example.com/foo");
        builder.header("Foo", "bar");

	builder.header("Signature", format!("keyId=\"primary\",algorithm=\"ed25519\",headers=\"foo\",signature=\"{}\"", sig));

        let req: http::Request<Vec<u8>> = builder.body(vec![]).unwrap();

        Signature::verify(&params, &pub_key, &req).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_verify_incorrect() {
        let pub_key: PublicKey = PublicKey::from_bytes(&HEXLOWER.decode(b"e7876fd5cc3a228dad634816f4ec4b80a258b2a552467e5d26f30003211bc45d").unwrap()).unwrap();

        let headers = vec!["foo"];
        let params = SignatureParams::new(&pub_key, "primary", &headers);

	let sig = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

        let mut builder = http::Request::builder();
        builder.method("GET");
        builder.uri("https://example.com/foo");
        builder.header("Foo", "bar");

	builder.header("Signature", format!("keyId=\"primary\",algorithm=\"ed25519\",headers=\"foo\",signature=\"{}\"", sig));

        let req: http::Request<Vec<u8>> = builder.body(vec![]).unwrap();

        Signature::verify(&params, &pub_key, &req).unwrap();
    }
}
