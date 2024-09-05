# [RustCrypto]: JOSE JWS

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the JSON Web Signature ([JWS]) component of the
Javascript Object Signing and Encryption ([JOSE]) specification as described
in [RFC7515].

JSON Web Signatures are a way of sharing unencrypted data in a way that the
sender can be verified. A JWS has the following contents:

- A verifyable payload
- One or more signatures including:
  - An optional unprotected header (nonverifyable) containing hints about the
    algorithm
  - An optional protected header (verifyable using the signature)
  - A signature

A client can use the information provided in a JWS to verify the integrity of
the data, meaning the client can be sure that the data did come from the
intended sender.

```rust
use jose_jws::{Jws, Signature};

let jws_json = serde_json::json!({
    "payload": "SGVsbG8gd29ybGQh",
    "signatures": [
        {
            "protected": "eyJhbGciOiJSUzI1NiJ9",
            "header": {
                "kid": "2010-12-29"
            },
            "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOi\
            Zj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYN\
            X4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0Gar\
            ZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh\
            6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQ\
            Ge77Rw"
        },
        {
            "protected": "eyJhbGciOiJFUzI1NiJ9",
            "header": {
                "kid": "e9bc097a-ce51-4036-9562-d2ade882db0d"
            },
            "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djx\
            La8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        }
    ]
});

let Jws::General(jws) = serde_json::from_value(jws_json).unwrap() else {
    panic!("couldn't deserialize JWS");
};

assert_eq!(jws.signatures.len(), 2);

let payload = jws.payload.unwrap();
let payload_str = core::str::from_utf8(&payload).unwrap();

assert_eq!(payload_str, "Hello world!")
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

[crate-image]: https://img.shields.io/crates/v/jose-jws
[crate-link]: https://crates.io/crates/jose-jws
[docs-image]: https://docs.rs/jose-jws/badge.svg
[docs-link]: https://docs.rs/jose-jws/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.65+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats
[build-image]: https://github.com/RustCrypto/JOSE/actions/workflows/jose-jws.yml/badge.svg
[build-link]: https://github.com/RustCrypto/JOSE/actions/workflows/jose-jws.yml

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto/
[JWS]: https://jose.readthedocs.io/en/latest/#jws
[JOSE]: https://jose.readthedocs.io/
[RFC7515]: https://www.rfc-editor.org/rfc/rfc7515
