// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

use alloc::boxed::Box;
use alloc::vec::Vec;

use zeroize::Zeroizing;

use super::key::{Key, Kind, Type};

impl<T: Type<Oct = Zeroizing<Box<[u8]>>>> From<&[u8]> for Key<T> {
    fn from(value: &[u8]) -> Self {
        Self {
            kind: Kind::Oct(Zeroizing::new(value.into())),
            algo: None,
        }
    }
}

impl<T: Type<Oct = Zeroizing<Box<[u8]>>>> From<Vec<u8>> for Key<T> {
    fn from(value: Vec<u8>) -> Self {
        Self {
            kind: Kind::Oct(value.into_boxed_slice().into()),
            algo: None,
        }
    }
}

impl<T: Type<Oct = Zeroizing<Box<[u8]>>>> From<Zeroizing<Vec<u8>>> for Key<T> {
    fn from(value: Zeroizing<Vec<u8>>) -> Self {
        value.into()
    }
}

impl<T: Type<Oct = Zeroizing<Box<[u8]>>>> From<Box<[u8]>> for Key<T> {
    fn from(value: Box<[u8]>) -> Self {
        Self {
            kind: Kind::Oct(value.into()),
            algo: None,
        }
    }
}

impl<T: Type<Oct = Zeroizing<Box<[u8]>>>> From<Zeroizing<Box<[u8]>>> for Key<T> {
    fn from(value: Zeroizing<Box<[u8]>>) -> Self {
        Self {
            kind: Kind::Oct(value),
            algo: None,
        }
    }
}
