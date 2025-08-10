use bp256::BrainpoolP256r1;
use bp384::BrainpoolP384r1;
use ecdsa::VerifyingKey;

use crate::cert::g2cert::TachoCurveDomain;

/// ECDSA verification key (i.e. public key)
#[derive(Clone, Eq, PartialEq)]
pub enum TachoVerifyingKey {
    /// Nist
    P256(p256::ecdsa::VerifyingKey),

    /// Nist
    P384(p384::ecdsa::VerifyingKey),

    /// Nist
    P521(p521::ecdsa::VerifyingKey),

    /// Brainpool
    BP256(VerifyingKey<BrainpoolP256r1>),

    /// Brainpool
    BP384(VerifyingKey<BrainpoolP384r1>),

    /// Brainpool
    BP512(()),
}

impl TachoVerifyingKey {
    pub fn domain(&self) -> TachoCurveDomain {
        match self {
            TachoVerifyingKey::P256(_) => TachoCurveDomain::NistSecp256r1,
            TachoVerifyingKey::P384(_) => TachoCurveDomain::NistSecp384r1,
            TachoVerifyingKey::P521(_) => TachoCurveDomain::NistSecp521r1,
            TachoVerifyingKey::BP256(_) => TachoCurveDomain::BrainpoolP256r1,
            TachoVerifyingKey::BP384(_) => TachoCurveDomain::BrainpoolP384r1,
            TachoVerifyingKey::BP512(_) => TachoCurveDomain::BrainpoolP512r1,
        }
    }

    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> eyre::Result<()> {
        use ecdsa::signature::Verifier;

        match self {
            TachoVerifyingKey::P256(verifying_key) => {
                use p256::ecdsa::Signature;
                let signature = Signature::from_slice(signature)?;

                verifying_key.verify(msg, &signature)?;
            }
            TachoVerifyingKey::P384(verifying_key) => {
                use p384::ecdsa::Signature;
                let signature = Signature::from_slice(signature)?;

                verifying_key.verify(msg, &signature)?;
            }

            TachoVerifyingKey::P521(verifying_key) => {
                use p521::ecdsa::Signature;
                let signature = Signature::from_slice(signature)?;

                verifying_key.verify(msg, &signature)?;
            }

            TachoVerifyingKey::BP256(verifying_key) => {
                use bp256::r1::ecdsa::Signature;
                let signature = Signature::from_slice(signature)?;

                verifying_key.verify(msg, &signature)?;
            }
            TachoVerifyingKey::BP384(verifying_key) => {
                use bp384::r1::ecdsa::Signature;
                let signature = Signature::from_slice(signature)?;

                verifying_key.verify(msg, &signature)?;
            }
            TachoVerifyingKey::BP512(_) => todo!("TachoVerifyingKey BP512"),
        }

        Ok(())
    }
}
