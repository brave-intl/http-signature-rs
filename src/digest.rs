use core::fmt::{self, Display};
use core::str::FromStr;
use std::error::Error;

use data_encoding::BASE64;
use sha2::{Digest, Sha256};

/// DIGEST_HEADER is the header where a digest of the body will be stored
pub static DIGEST_HEADER: &str = "digest";

/// Supported digest algorithms
#[derive(Clone, Debug, PartialEq)]
pub enum DigestAlgorithm {
    SHA256,
}

impl Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DigestAlgorithm::SHA256 => write!(f, "SHA-256"),
        }
    }
}

impl FromStr for DigestAlgorithm {
    type Err = Box<dyn Error>;

    fn from_str(s: &str) -> Result<Self, Box<dyn Error>> {
        match s {
            "SHA-256" => Ok(DigestAlgorithm::SHA256),
            _ => Err("Invalid digest type".into()),
        }
    }
}

impl DigestAlgorithm {
    pub fn new_hasher(&self) -> impl Digest {
        match *self {
            DigestAlgorithm::SHA256 => Sha256::new(),
        }
    }

    pub fn from_digest_header(s: &str) -> Result<Self, Box<dyn Error>> {
        match s.find('=') {
            Some(idx) => {
                let (alg, _) = s.split_at(idx);
                Self::from_str(alg)
            }
            _ => Err("Digest was malformed".into()),
        }
    }

    pub fn calculate<T>(&self, req: &http::Request<T>) -> String
    where
        T: AsRef<[u8]>,
    {
        let mut hasher = self.new_hasher();
        hasher.input(req.body());
        format!("{}={}", self, BASE64.encode(&hasher.result()))
    }
}

/// Extension trait for automatically exposing a method to add a digest to an http request
pub trait WithDigest {
    fn with_digest(self, digest: DigestAlgorithm) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized;
}

impl<T> WithDigest for http::Request<T>
where
    T: AsRef<[u8]>,
{
    /// Calculate and set the digest header for this http request
    fn with_digest(mut self, digest: DigestAlgorithm) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        let hash = digest.calculate(&self);
        self.headers_mut().insert(
            DIGEST_HEADER,
            http::header::HeaderValue::from_str(&hash).map_err(|e| e.to_string())?,
        );
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use http;

    use super::*;

    #[test]
    fn test_calculate() {
        let s = DigestAlgorithm::SHA256;

        let mut builder = http::Request::builder();
        builder.method("PUT");
        builder.uri("https://example.com/");

        let req = builder.body("hello world".as_bytes().to_vec()).unwrap();
        assert_eq!(
            s.calculate(&req),
            "SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=",
            "Incorrect hash",
        );

        let mut builder = http::Request::builder();
        builder.method("PUT");
        builder.uri("https://example.com/");

        let req = builder.body("foo bar".as_bytes().to_vec()).unwrap();
        assert_ne!(
            s.calculate(&req),
            "SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=",
            "The result must be different for different inputs",
        );
    }

    #[test]
    fn test_with_digest() {
        let s = DigestAlgorithm::SHA256;

        let mut builder = http::Request::builder();
        builder.method("PUT");
        builder.uri("https://example.com/");

        let req = builder.body("hello world".as_bytes().to_vec()).unwrap();
        assert_eq!(
            req.with_digest(s)
                .unwrap()
                .headers()
                .get("digest")
                .unwrap()
                .to_str()
                .unwrap(),
            "SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=",
            "The resulting request did not have the digest header set",
        );
    }

    #[test]
    fn test_from_digest_header() {
        assert_eq!(
            DigestAlgorithm::from_digest_header(
                "SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
            )
            .unwrap(),
            DigestAlgorithm::SHA256,
            "The digest algorithm was not successfully parsed from the digest header string",
        );
    }
}
