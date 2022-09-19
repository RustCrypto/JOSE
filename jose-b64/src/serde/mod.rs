// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Utilities for encoding serde types

#![cfg(feature = "serde")]
#![cfg_attr(docsrs, doc(cfg(feature = "serde")))]

mod bytes;
mod json;
mod secret;

pub use bytes::Bytes;

#[cfg(feature = "secret")]
pub use secret::Secret;

#[cfg(feature = "json")]
pub use json::Json;
