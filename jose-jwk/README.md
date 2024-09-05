# [RustCrypto]: JOSE JWK

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the JSON Web Key ([JWK]) component of the
Javascript Object Signing and Encryption ([JOSE]) specification as described
in [RFC7517].

A JWK is a way to represent cryptographic keys in JSON, typically public keys.
This format contains information about how the key needs to be used so a child
node can validate what a parent node sends (e.g. with JWTs) or encrypt messages
for the parent node using this key (e.g. with JWEs). This crate provides data
structures to interface with this format.

```rust
use jose_jwk::{Jwk, JwkSet, Key};
use jose_jwk::jose_jwa::{Algorithm, Signing};

let keys = serde_json::json!({
    "keys": [
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "use": "enc",
            "kid": "some-ec-kid"
        },
        {
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV\
            T86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5\
            JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMic\
            AtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bF\
            TWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-\
            kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "some-rsa-kid"
        }
    ]
});

let jwkset: JwkSet = serde_json::from_value(keys).unwrap();
let ec_jwk: &Jwk = &jwkset.keys[0];
let rsa_jwk: &Jwk = &jwkset.keys[1];

assert!(matches!(ec_jwk.key, Key::Ec(_)));
assert!(matches!(rsa_jwk.key, Key::Rsa(_)));

assert_eq!(ec_jwk.prm.kid, Some(String::from("some-ec-kid")));
assert_eq!(rsa_jwk.prm.kid, Some(String::from("some-rsa-kid")));

assert_eq!(rsa_jwk.prm.alg, Some(Algorithm::Signing(Signing::Rs256)));
```

[Documentation][docs-link]

## Minimum Supported Rust Version

This crate requires **Rust 1.65** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
version bump.

## License

Licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/jose-jwk
[crate-link]: https://crates.io/crates/jose-jwk
[docs-image]: https://docs.rs/jose-jwk/badge.svg
[docs-link]: https://docs.rs/jose-jwk/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.65+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats
[build-image]: https://github.com/RustCrypto/JOSE/actions/workflows/jose-jwk.yml/badge.svg
[build-link]: https://github.com/RustCrypto/JOSE/actions/workflows/jose-jwk.yml

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto/
[JWK]: https://jose.readthedocs.io/en/latest/#jwk
[JOSE]: https://jose.readthedocs.io/
[RFC7517]: https://www.rfc-editor.org/rfc/rfc7517
