#![cfg(any(feature = "p256", feature = "p384", feature = "p521", feature = "k256"))]
use crate::Signing;

#[cfg(feature = "p256")]
impl From<p256::NistP256> for Signing {
    fn from(_alg: p256::NistP256) -> Self {
        Signing::Es256
    }
}

#[cfg(feature = "k256")]
impl From<k256::Secp256k1> for Signing {
    fn from(_alg: k256::Secp256k1) -> Self {
        Signing::Es256K
    }
}

#[cfg(feature = "p384")]
impl From<p384::NistP384> for Signing {
    fn from(_alg: p384::NistP384) -> Self {
        Signing::Es384
    }
}

#[cfg(feature = "p521")]
impl From<p521::NistP521> for Signing {
    fn from(_alg: p521::NistP521) -> Self {
        Signing::Es512
    }
}
