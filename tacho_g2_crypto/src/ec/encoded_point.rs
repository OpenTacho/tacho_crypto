use std::borrow::Cow;

use bp256::BrainpoolP256r1;
use bp384::BrainpoolP384r1;
use ecdsa::EncodedPoint;

use crate::cert::{g2cert::TachoCurveDomain, g2certraw::CertificatePublicKeyRaw};

/// Encoded, used for ECDH or ECDSA
pub enum TachoEncodedPoint {
    /// Nist
    P256(p256::EncodedPoint),

    /// Nist
    P384(p384::EncodedPoint),

    /// Nist
    P521(p521::EncodedPoint),

    /// Brainpool
    BP256(EncodedPoint<BrainpoolP256r1>),

    /// Brainpool
    BP384(EncodedPoint<BrainpoolP384r1>),

    /// Brainpool
    BP512(()),
}

impl TachoEncodedPoint {
    pub fn from_bytes(domain: TachoCurveDomain, sec1_encoded: &[u8]) -> eyre::Result<Self> {
        Ok(match domain {
            TachoCurveDomain::NistSecp256r1 => {
                Self::P256(p256::EncodedPoint::from_bytes(sec1_encoded)?)
            }
            TachoCurveDomain::NistSecp384r1 => {
                Self::P384(p384::EncodedPoint::from_bytes(sec1_encoded)?)
            }
            TachoCurveDomain::NistSecp521r1 => {
                Self::P521(p521::EncodedPoint::from_bytes(sec1_encoded)?)
            }
            TachoCurveDomain::BrainpoolP256r1 => {
                Self::BP256(EncodedPoint::<BrainpoolP256r1>::from_bytes(sec1_encoded)?)
            }
            TachoCurveDomain::BrainpoolP384r1 => {
                Self::BP384(EncodedPoint::<BrainpoolP384r1>::from_bytes(sec1_encoded)?)
            }
            TachoCurveDomain::BrainpoolP512r1 => {
                eyre::bail!("TachoEncodedPoint from_bytes BrainpoolP512r1")
            }
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            TachoEncodedPoint::P256(encoded_point) => encoded_point.as_bytes(),
            TachoEncodedPoint::P384(encoded_point) => encoded_point.as_bytes(),
            TachoEncodedPoint::P521(encoded_point) => encoded_point.as_bytes(),
            TachoEncodedPoint::BP256(encoded_point) => encoded_point.as_bytes(),
            TachoEncodedPoint::BP384(encoded_point) => encoded_point.as_bytes(),
            TachoEncodedPoint::BP512(_) => todo!(),
        }
    }

    pub fn to_bytes(&self) -> Box<[u8]> {
        self.as_bytes().to_vec().into_boxed_slice()
    }

    pub fn domain(&self) -> TachoCurveDomain {
        match self {
            TachoEncodedPoint::P256(_) => TachoCurveDomain::NistSecp256r1,
            TachoEncodedPoint::P384(_) => TachoCurveDomain::NistSecp384r1,
            TachoEncodedPoint::P521(_) => TachoCurveDomain::NistSecp521r1,
            TachoEncodedPoint::BP256(_) => TachoCurveDomain::BrainpoolP256r1,
            TachoEncodedPoint::BP384(_) => TachoCurveDomain::BrainpoolP384r1,
            TachoEncodedPoint::BP512(_) => TachoCurveDomain::BrainpoolP512r1,
        }
    }

    /// Returns `Cow::Borrowed` data, ready to be encoded in raw certificate.
    pub fn to_raw(&self) -> CertificatePublicKeyRaw<'_> {
        CertificatePublicKeyRaw {
            domain_parameters: *self.domain().oid(),
            public_point: Cow::Borrowed(self.as_bytes()),
        }
    }
}

impl AsRef<[u8]> for TachoEncodedPoint {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
