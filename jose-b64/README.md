# [RustCrypto]: JOSE B64

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

This crate provides base64 utilities for use in other JOSE crates. Features
include:

- Base64 streaming encoders and decoders
- `serde` utilities for working nested JSON and base64 with the `serde` or
  `json` feature flags
- Safe handling of cyptographic data with the `secret` feature flag

[Documentation][docs-link]

## Crate features

- `secret`: This feature enables constant time operations (via `subtle`) and
  memory zeroization (via `zeroize`) for secure use of Base64. This feature is
  enabled by default.
- `serde`: Enable wrapper types usable with `serde`
- `json`: Enable a wrapper type for nested b64 serialization within JSON

## Examples

```rust
# #[cfg(all(feature = "json", feature = "secret"))] {
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use jose_b64::{B64Bytes, Json, B64Secret};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Inner {
    name: String,
    value: u64
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Data {
    /// Base64-encoded data
    unsecure: B64Bytes<Vec<u8>>,
    /// JSON embedded as base64
    inner: Json<Inner>,
    /// Base64-encoded data, to be serialized/deserialized securely
    secret: B64Secret<Vec<u8>>
}

let input = r#"{
   "unsecure": "SGVsbG8gd29ybGQh",
   "inner": "eyJuYW1lIjoiYmFyIiwidmFsdWUiOjEyMzQ1Nn0",
   "secret": "dG9wIHNlY3JldA"
}"#;

let decoded: Data = serde_json::from_str(input).unwrap();

let expected = Data {
    unsecure: Vec::from(b"Hello world!".as_slice()).into(),
    inner: Json::new(Inner { name: String::from("bar"), value: 123456 }).unwrap(),
    secret: Vec::from(b"top secret".as_slice()).into()
};

assert_eq!(expected, decoded);
# }
```

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

[crate-image]: https://buildstats.info/crate/jose-b64
[crate-link]: https://crates.io/crates/jose-b64
[docs-image]: https://docs.rs/jose-b64/badge.svg
[docs-link]: https://docs.rs/jose-b64/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.65+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats
[build-image]: https://github.com/RustCrypto/JOSE/actions/workflows/jose-b64.yml/badge.svg
[build-link]: https://github.com/RustCrypto/JOSE/actions/workflows/jose-b64.yml

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto/
[JOSE]: https://jose.readthedocs.io/
[RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
