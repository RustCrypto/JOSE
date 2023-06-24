# RustCrypto: JOSE [![Project Chat][chat-image]][chat-link] [![dependency status][deps-image]][deps-link]

Pure Rust implementation of Javascript Object Signing and Encryption ([JOSE])

## Crates

| Name       | crates.io                                                                                       | Docs                                                                             | Description                             |
|------------|-------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|-----------------------------------------|
| `jose-b64` | [![crates.io](https://img.shields.io/crates/v/jose-b64.svg)](https://crates.io/crates/jose-b64) | [![Documentation](https://docs.rs/jose-b64/badge.svg)](https://docs.rs/jose-b64) | Base64 utilities for use in JOSE crates |
| `jose-jwa` | [![crates.io](https://img.shields.io/crates/v/jose-jwa.svg)](https://crates.io/crates/jose-jwa) | [![Documentation](https://docs.rs/jose-jwa/badge.svg)](https://docs.rs/jose-jwa) | JSON Web Algorithms (JWA)               |
| `jose-jwe` | [![crates.io](https://img.shields.io/crates/v/jose-jwe.svg)](https://crates.io/crates/jose-jwe) | [![Documentation](https://docs.rs/jose-jwe/badge.svg)](https://docs.rs/jose-jwe) | JSON Web Encryption (JWE)               |
| `jose-jwk` | [![crates.io](https://img.shields.io/crates/v/jose-jwk.svg)](https://crates.io/crates/jose-jwk) | [![Documentation](https://docs.rs/jose-jwk/badge.svg)](https://docs.rs/jose-jwk) | JSON Web Keys (JWK)                     |
| `jose-jws` | [![crates.io](https://img.shields.io/crates/v/jose-jws.svg)](https://crates.io/crates/jose-jws) | [![Documentation](https://docs.rs/jose-jws/badge.svg)](https://docs.rs/jose-jws) | JSON Web Signatures (JWS)               |
| `jose-jwt` | [![crates.io](https://img.shields.io/crates/v/jose-jwt.svg)](https://crates.io/crates/jose-jwt) | [![Documentation](https://docs.rs/jose-jwt/badge.svg)](https://docs.rs/jose-jwt) | JSON Web Tokens (JWT)                   |

## Crate Overview

This project provides multiple crates that implement different components of the
JOSE family. An overview of each and information on their relationships is
listed below.

### `jose-b64`

This crate provides relevant utilities for working with Base64. It won't often
be used on its own, but provides helper types for working with json-as-b64 and
cyptographically secure base64, both of which are common cases with JOSE.

### `jose-jwa`

This crate provides representations of different algorithm types as specified in
[RFC7518]. Again, it is not likely that this crate is used on its own; it will
be reexported when required by the other crates.

### `jose-jwk`

This crate provides ways to interact with JWKs, JSON representations of
cryptographic keys specified in [RFC7517]. Typically JWKs hold public keys.

### `jose-jws`

This crate provides a way to interact with JWSs, data sent via JSON that has a
way to validate data authenticity. These are specified in [RFC7515] and provide
authenticity (a way to prove that data comes from the corrct sender) and
integrity (proof that it was not altered along the way), but _not_
confidentiality; that is, anybody can read the data contents. Typically, JWSs
are seen in the forms of JWTs.

### `jose-jwe`

This crate provides ways to interact with JWEs, JSON representations of
encrypted data specified in [RFC7516]. JWEs provide authenticity, integrity and
confidentiality (unlike JWS), and are typically four or five Base64-encoded
fields separated by a `.`. Each field representing a piece of information
an intended recipient needs to decode an encrypted payload.

### `jose-jwt`

This crate interacts with JWTs, which is a specific JSON schema for representing
web tokens specified in [RFC7519]. The JWT specification just defines a set of
specific fields ("claims", `iss`, `exp` and similar) that are usually
represented as a JWT (the usual Base64 `abc123.321DEF.g_hi10` format) but can
also be encrypted as a JWE.

## License

All crates licensed under either of

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # "badges"
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats
[deps-image]: https://deps.rs/repo/github/RustCrypto/jose/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/jose

[//]: # "links"
[JOSE]: https://jose.readthedocs.io/
[RFC7515]: https://www.rfc-editor.org/rfc/rfc7515
[RFC7516]: https://www.rfc-editor.org/rfc/rfc7516
[RFC7517]: https://www.rfc-editor.org/rfc/rfc7517
[RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
[RFC7519]: https://www.rfc-editor.org/rfc/rfc7519
