# [RustCrypto]: JOSE JWT

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the JSON Web Token ([JWT]) component of the
Javascript Object Signing and Encryption ([JOSE]) specification as described
in [RFC7519].

A JWT is a way of representing multiple "claims" to be transferred between two
parties, typically for token-based authentication. The RFC specifies some
standard claim names:

```json5
{
    "iss": "https://mywebsite.com",     // Token issuer
    "sub": "ferris1234",                // Subjet, typically username or UID
    "iat": 1516239022,                  // Time token was issued (issued at)
    "exp": 1516299022,                  // Time token is valid until (expiration)
    "nbf": 1516239022,                  // Time token is valid from (not before)
    "aud": "https://someotherwebsite.com", // Who the token should be accepted by
    "jti": "88383475-23b1-4955-9941-45f5447838b1" // UNIQUE token identifier
}
```

All of these claims are optional, and there can be additional claims.

Most commonly, JWTs are formed into a JSON Web Signature (JWS), which is a way
to verify that the token came from the correct sender. IN JWS FORMAT, ANYBODY
CAN READ THE TOKEN DATA so never encode things like passwords. (JSON Web
Encryption (JWE) provides a way to encrypt the data to keep it safe from third
parties, but this isn't needed for web authentication).

In the JWE form, the signature will look like this:

```json5
{
    "header": {
        "alg": "HS256",
        "typ": "JWT"
    },
    "payload": { /* contents from above */ },
    "signature": "YYProLkBExJS9woTrux2lLHvktGZ6iki86VJrBl5tm8"
}
```

`header` defines the algorithms used. To calcaulate the `signature`, the issuing
server will cyptographically hash the header and payload data using a private
secret (`secret!` in this case). When the server receives a token back, it can
use the same secret to verify the signature matches and know that it was indeed
the issuer of the JWT, so can trust its data.

For transmission, each of these three sections is typically minified then base64
encoded, the three sections are joined with a `.`. The result looks like this:

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215d2Vic2l0ZS5jb20iL
CJzdWIiOiJmZXJyaXMxMjM0IiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyOTkwMjIsIm5iZiI6
MTUxNjIzOTAyMiwiYXVkIjoiaHR0cHM6Ly9zb21lb3RoZXJ3ZWJzaXRlLmNvbSIsImp0aSI6Ijg4Mzg
zNDc1LTIzYjEtNDk1NS05OTQxLTQ1ZjU0NDc4MzhiMSJ9.YYProLkBExJS9woTrux2lLHvktGZ6iki8
6VJrBl5tm8
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

[crate-image]: https://buildstats.info/crate/jose-jwt
[crate-link]: https://crates.io/crates/jose-jwt
[docs-image]: https://docs.rs/jose-jwt/badge.svg
[docs-link]: https://docs.rs/jose-jwt/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.65+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats
[build-image]: https://github.com/RustCrypto/JOSE/actions/workflows/jose-jwt.yml/badge.svg
[build-link]: https://github.com/RustCrypto/JOSE/actions/workflows/jose-jwt.yml

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto/
[JWT]: https://jose.readthedocs.io/en/latest/#jwt
[JOSE]: https://jose.readthedocs.io/
[RFC7519]: https://www.rfc-editor.org/rfc/rfc7519
