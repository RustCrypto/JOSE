// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JOSE: JSON Object Signing & Encryption

#![warn(rust_2018_idioms, unused_lifetimes, unused_qualifications, clippy::all)]
#![forbid(unsafe_code, clippy::expect_used, clippy::panic)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
#![no_std]

extern crate alloc;

pub mod alg;
pub mod b64;
pub mod jwk;
pub mod jws;
pub mod key;
mod x5t;
