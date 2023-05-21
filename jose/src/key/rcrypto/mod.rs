// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Integration with RustCrypto types.

#![cfg(any(feature = "hmac", feature = "p256", feature = "p384", feature = "rsa"))]

use core::convert::Infallible;

mod key;
mod oct;
mod p256;
mod p384;
mod rsa;

pub use key::Key;
pub(crate) use key::{Kind, Type};
