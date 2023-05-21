// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JOSE: JSON Object Signing & Encryption

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny()]
#![forbid(unsafe_code)]
#![warn(
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;

pub mod alg;
pub mod b64;
pub mod jwk;
pub mod jws;
pub mod key;
