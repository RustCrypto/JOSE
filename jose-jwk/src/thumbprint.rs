// SPDX-FileCopyrightText: 2025 Phantom Technologies, Inc. <legal@phantom.app>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWK Thumbprint as defined in RFC 7638.
//!
//! This module provides methods for computing JWK Thumbprints, which are
//! cryptographic hash values computed over the required members of a JWK.

#![cfg(feature = "thumbprint")]

extern crate alloc;

use alloc::string::String;

use crate::{Ec, Jwk, Key, Oct, Okp, Rsa};
use jose_b64::base64ct::{Base64UrlUnpadded, Encoding};
use jose_b64::stream::{Encoder, Update};
use sha2::{Digest, Sha256};

/// Trait for computing JWK thumbprints.
pub trait JwkThumbprint {
    /// Compute the JWK thumbprint using SHA-256.
    fn thumbprint(&self) -> String {
        self.thumbprint_with_digest::<Sha256>()
    }

    /// Compute the JWK thumbprint using a custom digest function.
    fn thumbprint_with_digest<D: Digest>(&self) -> String;
}

impl JwkThumbprint for Ec {
    fn thumbprint_with_digest<D: Digest>(&self) -> String {
        let mut digest = D::new();

        // Required members in lexicographic order: crv, kty, x, y
        digest.update(r#"{"crv":""#);
        digest.update(self.crv.as_str());
        digest.update(r#"","kty":"EC","x":""#);
        b64digest(&mut digest, &self.x);
        digest.update(r#"","y":""#);
        b64digest(&mut digest, &self.y);
        digest.update(r#""}"#);

        Base64UrlUnpadded::encode_string(&digest.finalize())
    }
}

impl JwkThumbprint for Rsa {
    fn thumbprint_with_digest<D: Digest>(&self) -> String {
        let mut digest = D::new();

        // Required members in lexicographic order: e, kty, n
        digest.update(r#"{"e":""#);
        b64digest(&mut digest, &self.e);
        digest.update(r#"","kty":"RSA","n":""#);
        b64digest(&mut digest, &self.n);
        digest.update(r#""}"#);

        Base64UrlUnpadded::encode_string(&digest.finalize())
    }
}

impl JwkThumbprint for Oct {
    fn thumbprint_with_digest<D: Digest>(&self) -> String {
        let mut digest = D::new();

        // Required members in lexicographic order: k, kty
        digest.update(r#"{"k":""#);
        b64digest(&mut digest, &*self.k);
        digest.update(r#"","kty":"oct"}"#);

        Base64UrlUnpadded::encode_string(&digest.finalize())
    }
}

impl JwkThumbprint for Okp {
    fn thumbprint_with_digest<D: Digest>(&self) -> String {
        let mut digest = D::new();

        // Required members in lexicographic order: crv, kty, x
        digest.update(r#"{"crv":""#);
        digest.update(self.crv.as_str());
        digest.update(r#"","kty":"OKP","x":""#);
        b64digest(&mut digest, &self.x);
        digest.update(r#""}"#);

        Base64UrlUnpadded::encode_string(&digest.finalize())
    }
}

impl JwkThumbprint for Jwk {
    fn thumbprint_with_digest<D: Digest>(&self) -> String {
        self.key.thumbprint_with_digest::<D>()
    }
}

impl JwkThumbprint for Key {
    fn thumbprint_with_digest<D: Digest>(&self) -> String {
        match self {
            Key::Ec(ec) => ec.thumbprint_with_digest::<D>(),
            Key::Rsa(rsa) => rsa.thumbprint_with_digest::<D>(),
            Key::Oct(oct) => oct.thumbprint_with_digest::<D>(),
            Key::Okp(okp) => okp.thumbprint_with_digest::<D>(),
        }
    }
}

struct DigestUpdater<'a, D>(&'a mut D);

impl<'a, D: Digest> Update for DigestUpdater<'a, D> {
    type Error = ();

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.0.update(chunk);
        Ok(())
    }
}

fn b64digest<D: Digest>(digest: &mut D, chunk: impl AsRef<[u8]>) {
    let mut encoder: Encoder<DigestUpdater<'_, D>> = Encoder::from(DigestUpdater(digest));
    let _ = encoder.update(chunk);
    let _ = encoder.finish();
}
