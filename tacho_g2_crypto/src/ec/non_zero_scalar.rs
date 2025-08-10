use der::zeroize::{Zeroize, Zeroizing};

use crate::{
    cert::g2cert::TachoCurveDomain,
    ec::affine_point::TachoAffinePoint,
    ecdh::{diffie_hellman::tacho_diffie_hellman, shared_secret::TachoSharedSecret},
};

/// Private key material
pub enum TachoNonZeroScalar {
    /// Nist
    P256(p256::NonZeroScalar),

    /// Nist
    P384(p384::NonZeroScalar),

    /// Nist
    P521(p521::NonZeroScalar),

    /// Brainpool
    BP256(bp256::r1::NonZeroScalar),

    /// Brainpool
    BP384(bp384::r1::NonZeroScalar),

    /// Brainpool
    BP512(()),
}

impl TachoNonZeroScalar {
    pub fn domain(&self) -> TachoCurveDomain {
        match self {
            TachoNonZeroScalar::P256(_) => TachoCurveDomain::NistSecp256r1,
            TachoNonZeroScalar::P384(_) => TachoCurveDomain::NistSecp384r1,
            TachoNonZeroScalar::P521(_) => TachoCurveDomain::NistSecp521r1,
            TachoNonZeroScalar::BP256(_) => TachoCurveDomain::BrainpoolP256r1,
            TachoNonZeroScalar::BP384(_) => TachoCurveDomain::BrainpoolP384r1,
            TachoNonZeroScalar::BP512(_) => TachoCurveDomain::BrainpoolP512r1,
        }
    }

    /// Returns the SEC1 encoding of this scalar.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(match self {
            TachoNonZeroScalar::P256(non_zero_scalar) => {
                non_zero_scalar.to_bytes().as_slice().into()
            }
            TachoNonZeroScalar::P384(non_zero_scalar) => {
                non_zero_scalar.to_bytes().as_slice().into()
            }
            TachoNonZeroScalar::P521(non_zero_scalar) => {
                non_zero_scalar.to_bytes().as_slice().into()
            }
            TachoNonZeroScalar::BP256(non_zero_scalar) => {
                non_zero_scalar.to_bytes().as_slice().into()
            }
            TachoNonZeroScalar::BP384(non_zero_scalar) => {
                non_zero_scalar.to_bytes().as_slice().into()
            }
            TachoNonZeroScalar::BP512(_) => {
                todo!("TachoNonZeroScalar BP512")
            }
        })
    }

    /// Performs Elliptic Curve Diffie-Hellman (ECDH)
    pub fn diffie_hellman(
        &self,
        public_key: &TachoAffinePoint<'_>,
    ) -> eyre::Result<TachoSharedSecret> {
        tacho_diffie_hellman(self, public_key)
    }
}

impl Zeroize for TachoNonZeroScalar {
    fn zeroize(&mut self) {
        match self {
            TachoNonZeroScalar::P256(non_zero_scalar) => non_zero_scalar.zeroize(),
            TachoNonZeroScalar::P384(non_zero_scalar) => non_zero_scalar.zeroize(),
            TachoNonZeroScalar::P521(non_zero_scalar) => non_zero_scalar.zeroize(),
            TachoNonZeroScalar::BP256(non_zero_scalar) => non_zero_scalar.zeroize(),
            TachoNonZeroScalar::BP384(non_zero_scalar) => non_zero_scalar.zeroize(),
            TachoNonZeroScalar::BP512(_) => todo!(),
        }
    }
}
