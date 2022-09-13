// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

use super::super::super::*;
use crate::key::rcrypto::{Key, Type};

impl<T: Type, E> TryFrom<Oct> for Key<T>
where
    for<'a> &'a Oct: TryInto<Self, Error = E>,
{
    type Error = E;

    fn try_from(value: Oct) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl<T: Type, E> TryFrom<Ec> for Key<T>
where
    for<'a> &'a Ec: TryInto<Self, Error = E>,
{
    type Error = E;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl<T: Type, E> TryFrom<Rsa> for Key<T>
where
    for<'a> &'a Rsa: TryInto<Self, Error = E>,
{
    type Error = E;

    fn try_from(value: Rsa) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl<T: Type, E> TryFrom<Okp> for Key<T>
where
    for<'a> &'a Okp: TryInto<Self, Error = E>,
{
    type Error = E;

    fn try_from(value: Okp) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl<T: Type, E> TryFrom<Jwk> for Key<T>
where
    for<'a> &'a Jwk: TryInto<Self, Error = E>,
{
    type Error = E;

    fn try_from(value: Jwk) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}
