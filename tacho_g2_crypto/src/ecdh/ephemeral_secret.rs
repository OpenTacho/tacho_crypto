use p256::{elliptic_curve::ecdh::EphemeralSecret, SecretKey};
use rand_core::CryptoRngCore;

use crate::cert::g2cert::TachoCurveDomain;

use super::{public_key::TachoPublicKey, secret_key::TachoSecretKey};

/// Ephemeral Diffie-Hellman Secret
pub enum TachoEphemeralSecret {
    /// Nist
    P256(p256::ecdh::EphemeralSecret),

    /// Nist
    P384(p384::ecdh::EphemeralSecret),

    /// Nist
    P521(p521::ecdh::EphemeralSecret),

    /// Brainpool
    BP256(()),

    /// Brainpool
    BP384(()),

    /// Brainpool
    BP512(()),
}

impl TachoEphemeralSecret {
    pub fn random(domain: TachoCurveDomain, rng: &mut impl CryptoRngCore) -> Self {
        match domain {
            TachoCurveDomain::NistSecp256r1 => Self::P256(EphemeralSecret::random(rng)),
            TachoCurveDomain::NistSecp384r1 => Self::P384(EphemeralSecret::random(rng)),
            TachoCurveDomain::NistSecp521r1 => Self::P521(EphemeralSecret::random(rng)),
            TachoCurveDomain::BrainpoolP256r1 => unimplemented!(),
            TachoCurveDomain::BrainpoolP384r1 => unimplemented!(),
            TachoCurveDomain::BrainpoolP512r1 => unimplemented!(),
        }
    }

    pub fn public_key(&self) -> TachoPublicKey {
        match self {
            TachoEphemeralSecret::P256(es) => TachoPublicKey::P256(es.public_key()),
            TachoEphemeralSecret::P384(es) => TachoPublicKey::P384(es.public_key()),
            TachoEphemeralSecret::P521(es) => TachoPublicKey::P521(es.public_key()),
            TachoEphemeralSecret::BP256(_) => unimplemented!(),
            TachoEphemeralSecret::BP384(_) => unimplemented!(),
            TachoEphemeralSecret::BP512(_) => unimplemented!(),
        }
    }

}
