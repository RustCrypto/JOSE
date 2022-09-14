// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK RSA key material.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use jose_b64::serde::{Bytes, Secret};

/// An RSA key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rsa {
    /// The RSA modulus.
    pub n: Bytes,

    /// The RSA public exponent.
    pub e: Bytes,

    /// The RSA private key material.
    #[serde(skip_serializing_if = "Option::is_none", default, flatten)]
    pub prv: Option<RsaPrivate>,
}

/// RSA key private material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaPrivate {
    /// The RSA private key exponent.
    pub d: Secret,

    /// Optional RSA private key material.
    #[serde(skip_serializing_if = "Option::is_none", default, flatten)]
    pub opt: Option<RsaOptional>,
}

impl From<Secret> for RsaPrivate {
    #[inline(always)]
    fn from(bytes: Secret) -> Self {
        Self {
            d: bytes,
            opt: None,
        }
    }
}

/// Optional RSA private key material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaOptional {
    /// The private first prime factor.
    pub p: Secret,

    /// The private second prime factor.
    pub q: Secret,

    /// The private first factor CRT exponent.
    pub dp: Secret,

    /// The private second factor CRT exponent.
    pub dq: Secret,

    /// The private first CRT coefficient.
    pub qi: Secret,

    /// Additional RSA private primes.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub oth: Vec<RsaOtherPrimes>,
}

/// Additional RSA private primes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaOtherPrimes {
    /// The private prime factor.
    pub r: Secret,

    /// The private factor CRT exponent.
    pub d: Secret,

    /// The private factor CRT coefficient.
    pub t: Secret,
}
