use crate::cert::g2cert::TachoCurveDomain;
use bp256::BrainpoolP256r1;
use bp384::BrainpoolP384r1;
use ecdsa::VerifyingKey;
use elliptic_curve::{
    PublicKey,
    sec1::{FromEncodedPoint, ToEncodedPoint},
};
use std::fmt::Debug;

use super::{
    affine_point::TachoAffinePoint, encoded_point::TachoEncodedPoint,
    verifying_key::TachoVerifyingKey,
};

/// Public Key point of ECDSA or ECDH
#[derive(Clone, Eq, PartialEq)]
pub enum TachoPublicKey {
    /// Nist
    P256(p256::PublicKey),

    /// Nist
    P384(p384::PublicKey),

    /// Nist
    P521(p521::PublicKey),

    /// Brainpool
    BP256(PublicKey<BrainpoolP256r1>),

    /// Brainpool
    BP384(PublicKey<BrainpoolP384r1>),

    /// Brainpool
    BP512(()),
}

impl Debug for TachoPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P256(_) => f.debug_tuple("P256").finish_non_exhaustive(),
            Self::P384(_) => f.debug_tuple("P384").finish_non_exhaustive(),
            Self::P521(_) => f.debug_tuple("P521").finish_non_exhaustive(),
            Self::BP256(_) => f.debug_tuple("BP256").finish_non_exhaustive(),
            Self::BP384(_) => f.debug_tuple("BP384").finish_non_exhaustive(),
            Self::BP512(_) => f.debug_tuple("BP512").finish_non_exhaustive(),
        }
    }
}

impl TachoPublicKey {
    pub fn from_encoded_point(encoded: &TachoEncodedPoint) -> Option<Self> {
        Some(match encoded {
            TachoEncodedPoint::P256(point) => {
                TachoPublicKey::P256(p256::PublicKey::from_encoded_point(point).into_option()?)
            }
            TachoEncodedPoint::P384(point) => {
                TachoPublicKey::P384(p384::PublicKey::from_encoded_point(point).into_option()?)
            }
            TachoEncodedPoint::P521(point) => {
                TachoPublicKey::P521(p521::PublicKey::from_encoded_point(point).into_option()?)
            }

            TachoEncodedPoint::BP256(point) => {
                TachoPublicKey::BP256(PublicKey::from_encoded_point(point).into_option()?)
            }
            TachoEncodedPoint::BP384(point) => {
                TachoPublicKey::BP384(PublicKey::from_encoded_point(point).into_option()?)
            }
            TachoEncodedPoint::BP512(_) => {
                unimplemented!("TachoEncodedPoint from_encoded_point BP512")
            }
        })
    }

    /// Returns compressed SEC1-encoded compressed point
    ///
    /// can be read with [`TachoEncodedPoint::from_bytes`]
    pub fn compressed_sec1_bytes(&self) -> Box<[u8]> {
        self.to_encoded_point(true).to_bytes()
    }

    /// Convert this [`TachoPublicKey`] into the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section 2.3.3
    /// (page 10).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    ///
    /// Uncompressed form.
    pub fn to_sec1_bytes(&self) -> Box<[u8]> {
        self.to_encoded_point(false).to_bytes()
    }

    /// Returns SEC1-encoded point
    pub fn to_encoded_point(&self, compress: bool) -> TachoEncodedPoint {
        match self {
            TachoPublicKey::P256(public_key) => {
                TachoEncodedPoint::P256(public_key.to_encoded_point(compress))
            }
            TachoPublicKey::P384(public_key) => {
                TachoEncodedPoint::P384(public_key.to_encoded_point(compress))
            }
            TachoPublicKey::P521(public_key) => {
                TachoEncodedPoint::P521(public_key.to_encoded_point(compress))
            }

            TachoPublicKey::BP256(public_key) => {
                TachoEncodedPoint::BP256(public_key.to_encoded_point(compress))
            }
            TachoPublicKey::BP384(public_key) => {
                TachoEncodedPoint::BP384(public_key.to_encoded_point(compress))
            }

            TachoPublicKey::BP512(_) => {
                unimplemented!("to_encoded_point BP512")
            }
        }
    }

    /// The inner AffinePoint from this PublicKey.
    /// In ECC, public keys are elliptic curve points.
    pub fn as_affine(&self) -> TachoAffinePoint<'_> {
        match self {
            TachoPublicKey::P256(public_key) => TachoAffinePoint::P256(public_key.as_affine()),
            TachoPublicKey::P384(public_key) => TachoAffinePoint::P384(public_key.as_affine()),
            TachoPublicKey::P521(public_key) => TachoAffinePoint::P521(public_key.as_affine()),
            TachoPublicKey::BP256(public_key) => TachoAffinePoint::BP256(public_key.as_affine()),
            TachoPublicKey::BP384(public_key) => TachoAffinePoint::BP384(public_key.as_affine()),
            TachoPublicKey::BP512(_public_key) => TachoAffinePoint::BP512(()),
        }
    }

    pub fn from_sec1_bytes(domain: TachoCurveDomain, sec1_encoded: &[u8]) -> eyre::Result<Self> {
        Ok(match domain {
            TachoCurveDomain::NistSecp256r1 => {
                TachoPublicKey::P256(p256::PublicKey::from_sec1_bytes(sec1_encoded)?)
            }
            TachoCurveDomain::NistSecp384r1 => {
                TachoPublicKey::P384(p384::PublicKey::from_sec1_bytes(sec1_encoded)?)
            }
            TachoCurveDomain::NistSecp521r1 => {
                TachoPublicKey::P521(p521::PublicKey::from_sec1_bytes(sec1_encoded)?)
            }
            TachoCurveDomain::BrainpoolP256r1 => {
                TachoPublicKey::BP256(PublicKey::from_sec1_bytes(sec1_encoded)?)
            }
            TachoCurveDomain::BrainpoolP384r1 => {
                TachoPublicKey::BP384(PublicKey::from_sec1_bytes(sec1_encoded)?)
            }
            TachoCurveDomain::BrainpoolP512r1 => {
                todo!("TachoPublicKey from_sec1_bytes BrainpoolP512r1")
            }
        })
    }

    pub fn verifying(&self) -> TachoVerifyingKey {
        match self {
            TachoPublicKey::P256(public_key) => {
                TachoVerifyingKey::P256(VerifyingKey::from(public_key))
            }
            TachoPublicKey::P384(public_key) => {
                TachoVerifyingKey::P384(VerifyingKey::from(public_key))
            }
            TachoPublicKey::P521(public_key) => {
                TachoVerifyingKey::P521(VerifyingKey::from(public_key))
            }

            TachoPublicKey::BP256(public_key) => {
                TachoVerifyingKey::BP256(VerifyingKey::from(public_key))
            }
            TachoPublicKey::BP384(public_key) => {
                TachoVerifyingKey::BP384(VerifyingKey::from(public_key))
            }
            TachoPublicKey::BP512(_public_key) => TachoVerifyingKey::BP512(()),
        }
    }

    pub fn domain(&self) -> TachoCurveDomain {
        match self {
            TachoPublicKey::P256(_) => TachoCurveDomain::NistSecp256r1,
            TachoPublicKey::P384(_) => TachoCurveDomain::NistSecp384r1,
            TachoPublicKey::P521(_) => TachoCurveDomain::NistSecp521r1,
            TachoPublicKey::BP256(_) => TachoCurveDomain::BrainpoolP256r1,
            TachoPublicKey::BP384(_) => TachoCurveDomain::BrainpoolP384r1,
            TachoPublicKey::BP512(_) => TachoCurveDomain::BrainpoolP512r1,
        }
    }
}
