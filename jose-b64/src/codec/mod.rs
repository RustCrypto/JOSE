// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod dec;
mod enc;

pub use dec::{Decoder, Error};
pub use enc::Encoder;

use alloc::vec::Vec;
use core::{convert::Infallible, fmt::Debug};

use super::Update;

const fn invert(input: &[u8; 64]) -> [u8; 256] {
    let mut output = [0xff; 256];
    let mut i = 0;

    while i < 64u8 {
        output[input[i as usize] as usize] = i;
        i += 1;
    }

    output
}

/// A base64 configuration
pub trait Config: Sized {
    /// Whether or not the base64 encoding is padded.
    const PAD: bool = false;

    /// The base64 encoding alphabet (a decoded-to-encoded map).
    const D2E: [u8; 64];

    /// Performs a single-pass base64 decoding.
    fn decode(value: impl AsRef<[u8]>) -> Result<Vec<u8>, Error<Infallible>> {
        let vec = Vec::with_capacity((value.as_ref().len() + 3) / 4 * 3);
        Decoder::<Vec<u8>, Self>::from(vec).chain(value)?.finish()
    }

    /// Performs a single-pass base64 encoding.
    fn encode(value: impl AsRef<[u8]>) -> Vec<u8> {
        let vec = Vec::with_capacity((value.as_ref().len() + 2) / 3 * 4);
        Encoder::<Vec<u8>, Self>::from(vec)
            .chain(value.as_ref())
            .expect("unreachable")
            .finish()
            .expect("unreachable")
    }
}

pub trait Codec {
    const E2D: [u8; 256];

    /// Decoded block to encoded block.
    fn d2e(block: [u8; 3]) -> [u8; 4];

    /// Encoded block to decoded block.
    fn e2d(block: [u8; 4], offset: usize) -> Result<[u8; 3], usize>;
}

impl<T: Config> Codec for T {
    const E2D: [u8; 256] = invert(&Self::D2E);

    #[inline(always)]
    fn d2e(block: [u8; 3]) -> [u8; 4] {
        let bits = u32::from_be_bytes([0, block[0], block[1], block[2]]) as usize;

        [
            Self::D2E[bits >> 18 & 0b111111],
            Self::D2E[bits >> 12 & 0b111111],
            Self::D2E[bits >> 6 & 0b111111],
            Self::D2E[bits & 0b111111],
        ]
    }

    #[inline(always)]
    fn e2d(block: [u8; 4], offset: usize) -> Result<[u8; 3], usize> {
        #[inline(always)]
        fn val(e2d: &[u8; 256], index: u8, offset: usize, byte: usize) -> Result<u32, usize> {
            match e2d[usize::from(index)] {
                0xff => Err(offset + byte),
                n => Ok(n.into()),
            }
        }

        let bits = val(&Self::E2D, block[0], offset, 0)? << 18
            | val(&Self::E2D, block[1], offset, 1)? << 12
            | val(&Self::E2D, block[2], offset, 2)? << 6
            | val(&Self::E2D, block[3], offset, 3)?;

        Ok([
            (bits >> 16 & 0xff) as u8,
            (bits >> 8 & 0xff) as u8,
            (bits & 0xff) as u8,
        ])
    }
}

/// Standard Base64 WITHOUT padding
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Standard(());

impl Config for Standard {
    const D2E: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
}

/// Standard Base64 WITH padding
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StandardPad(());

impl Config for StandardPad {
    const PAD: bool = true;
    const D2E: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
}

/// URL-Safe Base64 WITHOUT padding
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UrlSafe(());

impl Config for UrlSafe {
    const D2E: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
}

/// URL-Safe Base64 WITH padding
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UrlSafePad(());

impl Config for UrlSafePad {
    const PAD: bool = true;
    const D2E: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode() {
        assert_eq!(Standard::encode(*b"Man"), *b"TWFu");
        assert_eq!(Standard::encode(*b"foo"), *b"Zm9v");
        assert_eq!(Standard::encode(*b"bar"), *b"YmFy");
    }

    #[test]
    fn decode() {
        assert_eq!(Standard::decode(*b"TWFu").unwrap(), *b"Man");
        assert_eq!(Standard::decode(*b"Zm9v").unwrap(), *b"foo");
        assert_eq!(Standard::decode(*b"YmFy").unwrap(), *b"bar");
    }
}
