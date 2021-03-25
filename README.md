# http-signature-rs

Minimal implementation of HTTP request signatures including digest generation according to <https://tools.ietf.org/html/draft-cavage-http-signatures-08>.

Only supports the signature header (not authorization) with ed25519 signatures and sha256 digests.

```rust
use ed25519_dalek::Keypair;
use http;
use rand::rngs::OsRng;

use http_signature_rs::*;

fn main() {
    let mut builder = http::Request::builder();
    builder.method("PUT");
    builder.uri("https://example.com/");

    let req = builder
        .body("{\"hello\":\"world\"}".as_bytes().to_vec())
        .unwrap()
        .with_digest(DigestAlgorithm::SHA256)
        .unwrap();

    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);

    let headers = vec!["digest"];
    let params = SignatureParams::new(&keypair, "primary", &headers);

    let req = params.sign(&keypair, req).unwrap();
    println!("{:?}", req);
}
```
