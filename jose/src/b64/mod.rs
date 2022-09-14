// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Base64 Conversion Utilities

pub use jose_b64::base64ct::{Base64 as StandardPad, Base64UrlUnpadded as UrlSafe};
pub use jose_b64::stream::{Decoder, Encoder, Error, Optional, Update};

#[cfg(any(feature = "jwk", feature = "jws"))]
pub use jose_b64::serde::*;
