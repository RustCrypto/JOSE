// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWS integrations with RustCrypto types

#![cfg(all(
    feature = "sha2",
    any(feature = "hmac", feature = "p256", feature = "p384", feature = "rsa")
))]
#![cfg_attr(
    docsrs,
    doc(cfg(all(
        feature = "sha2",
        any(feature = "hmac", feature = "p256", feature = "p384", feature = "rsa")
    )))
)]

mod hmac;
mod key;
mod p256;
mod p384;
mod rsa;
mod state;

pub use key::{Signing, Verifying};
pub use state::State;
