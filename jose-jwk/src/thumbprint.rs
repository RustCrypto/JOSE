// SPDX-FileCopyrightText: 2025 Phantom Technologies, Inc. <legal@phantom.app>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK Thumbprint implementation as defined in RFC 7638.
//!
//! This module provides methods for computing JWK Thumbprints, which are
//! cryptographic hash values computed over the required members of a JWK.

use alloc::string::String;

use jose_b64::base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

use crate::key::{Ec, Oct, Okp, Rsa};
use crate::{Jwk, Key};

/// Trait for computing JWK thumbprints.
///
/// This trait is implemented for each key type to compute the thumbprint
/// according to RFC 7638 requirements.
pub trait JwkThumbprint {
    /// Compute the JWK thumbprint using SHA-256.
    ///
    /// Returns the base64url-encoded thumbprint string.
    fn jwk_thumbprint(&self) -> Result<String, ThumbprintError>;

    /// Compute the JWK thumbprint using a custom hash function.
    ///
    /// Returns the base64url-encoded thumbprint string.
    fn jwk_thumbprint_with_hash<D>(&self) -> Result<String, ThumbprintError>
    where
        D: Digest;
}

/// Errors that can occur during thumbprint computation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThumbprintError {
    /// Failed to format the JSON representation.
    JsonFormatError,
}

impl core::fmt::Display for ThumbprintError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ThumbprintError::JsonFormatError => write!(f, "failed to format JSON for thumbprint"),
        }
    }
}

impl JwkThumbprint for Ec {
    fn jwk_thumbprint(&self) -> Result<String, ThumbprintError> {
        self.jwk_thumbprint_with_hash::<Sha256>()
    }

    fn jwk_thumbprint_with_hash<D>(&self) -> Result<String, ThumbprintError>
    where
        D: Digest,
    {
        // Required members in lexicographic order: crv, kty, x, y
        let buf = D::new()
            .chain_update(r#"{"crv":""#)
            .chain_update(self.crv.as_str())
            .chain_update(r#"","kty":"EC","x":""#)
            .chain_update(Base64UrlUnpadded::encode_string(&self.x))
            .chain_update(r#"","y":""#)
            .chain_update(Base64UrlUnpadded::encode_string(&self.y))
            .chain_update(r#""}"#)
            .finalize();

        Ok(Base64UrlUnpadded::encode_string(&buf))
    }
}

impl JwkThumbprint for Jwk {
    /// Compute the JWK thumbprint using SHA-256 as defined in RFC 7638.
    ///
    /// This method computes a cryptographic hash over the required members
    /// of the JWK and returns the base64url-encoded result.
    ///
    /// # Examples
    ///
    /// ```
    /// # use jose_jwk::{Jwk, JwkThumbprint, Key, Rsa};
    /// let jwk = Jwk {
    ///     key: Key::Rsa(Rsa {
    ///         e: vec![1, 0, 1].into(),
    ///         n: vec![0xAB, 0xCD, 0xEF].into(),
    ///         prv: None,
    ///     }),
    ///     prm: Default::default(),
    /// };
    ///
    /// let thumbprint = jwk.jwk_thumbprint().unwrap();
    /// assert!(!thumbprint.is_empty());
    /// ```
    fn jwk_thumbprint(&self) -> Result<String, ThumbprintError> {
        self.key.jwk_thumbprint()
    }

    /// Compute the JWK thumbprint using a custom hash function as defined in RFC 7638.
    ///
    /// This method allows using a different hash function than the default SHA-256.
    ///
    /// # Examples
    ///
    /// ```
    /// # use jose_jwk::{Jwk, JwkThumbprint, Key, Rsa};
    /// # use sha2::Sha512;
    /// let jwk = Jwk {
    ///     key: Key::Rsa(Rsa {
    ///         e: vec![1, 0, 1].into(),
    ///         n: vec![0xAB, 0xCD, 0xEF].into(),
    ///         prv: None,
    ///     }),
    ///     prm: Default::default(),
    /// };
    ///
    /// let thumbprint = jwk.jwk_thumbprint_with_hash::<Sha512>().unwrap();
    /// assert!(!thumbprint.is_empty());
    /// ```
    fn jwk_thumbprint_with_hash<D>(&self) -> Result<String, ThumbprintError>
    where
        D: Digest,
    {
        self.key.jwk_thumbprint_with_hash::<D>()
    }
}

impl JwkThumbprint for Rsa {
    fn jwk_thumbprint(&self) -> Result<String, ThumbprintError> {
        self.jwk_thumbprint_with_hash::<Sha256>()
    }

    fn jwk_thumbprint_with_hash<D>(&self) -> Result<String, ThumbprintError>
    where
        D: Digest,
    {
        // Required members in lexicographic order: e, kty, n
        let buf = D::new()
            .chain_update(r#"{"e":""#)
            .chain_update(Base64UrlUnpadded::encode_string(&self.e))
            .chain_update(r#"","kty":"RSA","n":""#)
            .chain_update(Base64UrlUnpadded::encode_string(&self.n))
            .chain_update(r#""}"#)
            .finalize();

        Ok(Base64UrlUnpadded::encode_string(&buf))
    }
}

impl JwkThumbprint for Oct {
    fn jwk_thumbprint(&self) -> Result<String, ThumbprintError> {
        self.jwk_thumbprint_with_hash::<Sha256>()
    }

    fn jwk_thumbprint_with_hash<D>(&self) -> Result<String, ThumbprintError>
    where
        D: Digest,
    {
        // Required members in lexicographic order: k, kty
        let buf = D::new()
            .chain_update(r#"{"k":""#)
            .chain_update(Base64UrlUnpadded::encode_string(&self.k))
            .chain_update(r#"","kty":"oct"}"#)
            .finalize();

        Ok(Base64UrlUnpadded::encode_string(&buf))
    }
}

impl JwkThumbprint for Okp {
    fn jwk_thumbprint(&self) -> Result<String, ThumbprintError> {
        self.jwk_thumbprint_with_hash::<Sha256>()
    }

    fn jwk_thumbprint_with_hash<D>(&self) -> Result<String, ThumbprintError>
    where
        D: Digest,
    {
        // Required members in lexicographic order: crv, kty, x
        let buf = D::new()
            .chain_update(r#"{"crv":""#)
            .chain_update(self.crv.as_str())
            .chain_update(r#"","kty":"OKP","x":""#)
            .chain_update(Base64UrlUnpadded::encode_string(&self.x))
            .chain_update(r#""}"#)
            .finalize();

        Ok(Base64UrlUnpadded::encode_string(&buf))
    }
}

impl JwkThumbprint for Key {
    fn jwk_thumbprint(&self) -> Result<String, ThumbprintError> {
        match self {
            Key::Ec(ec) => ec.jwk_thumbprint(),
            Key::Rsa(rsa) => rsa.jwk_thumbprint(),
            Key::Oct(oct) => oct.jwk_thumbprint(),
            Key::Okp(okp) => okp.jwk_thumbprint(),
        }
    }

    fn jwk_thumbprint_with_hash<D>(&self) -> Result<String, ThumbprintError>
    where
        D: Digest,
    {
        match self {
            Key::Ec(ec) => ec.jwk_thumbprint_with_hash::<D>(),
            Key::Rsa(rsa) => rsa.jwk_thumbprint_with_hash::<D>(),
            Key::Oct(oct) => oct.jwk_thumbprint_with_hash::<D>(),
            Key::Okp(okp) => okp.jwk_thumbprint_with_hash::<D>(),
        }
    }
}
