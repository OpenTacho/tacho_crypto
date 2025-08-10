use bp256::BrainpoolP256r1;
use bp384::BrainpoolP384r1;
use ecdsa::SigningKey;

use crate::cert::g2cert::TachoCurveDomain;

use super::{
    secret_key::TachoSecretKey, signature::TachoSignatureBytes, verifying_key::TachoVerifyingKey,
};

/// ECDSA signing key
pub enum TachoSigningKey {
    /// Nist
    P256(p256::ecdsa::SigningKey),

    /// Nist
    P384(p384::ecdsa::SigningKey),

    /// Nist
    P521(p521::ecdsa::SigningKey),

    /// Brainpool
    BP256(SigningKey<BrainpoolP256r1>),

    /// Brainpool
    BP384(SigningKey<BrainpoolP384r1>),

    /// Brainpool
    BP512(()),
}

impl TachoSigningKey {
    /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary format).
    pub fn from_pkcs8_der(bytes: &[u8]) -> eyre::Result<Self> {
        let secret_key = TachoSecretKey::from_pkcs8_der(bytes)?;

        Ok(secret_key.signing())
    }

    pub fn verifying(&self) -> TachoVerifyingKey {
        match self {
            TachoSigningKey::P256(sk) => TachoVerifyingKey::P256(*sk.verifying_key()),
            TachoSigningKey::P384(sk) => TachoVerifyingKey::P384(*sk.verifying_key()),
            TachoSigningKey::P521(sk) => TachoVerifyingKey::P521(*sk.verifying_key()),

            TachoSigningKey::BP256(sk) => TachoVerifyingKey::BP256(*sk.verifying_key()),
            TachoSigningKey::BP384(sk) => TachoVerifyingKey::BP384(*sk.verifying_key()),
            TachoSigningKey::BP512(_) => TachoVerifyingKey::BP512(()),
        }
    }
    pub fn domain(&self) -> TachoCurveDomain {
        match self {
            TachoSigningKey::P256(_) => TachoCurveDomain::NistSecp256r1,
            TachoSigningKey::P384(_) => TachoCurveDomain::NistSecp384r1,
            TachoSigningKey::P521(_) => TachoCurveDomain::NistSecp521r1,
            TachoSigningKey::BP256(_) => TachoCurveDomain::BrainpoolP256r1,
            TachoSigningKey::BP384(_) => TachoCurveDomain::BrainpoolP384r1,
            TachoSigningKey::BP512(_) => TachoCurveDomain::BrainpoolP512r1,
        }
    }

    pub fn try_sign(&self, msg: &[u8]) -> eyre::Result<TachoSignatureBytes> {
        Ok(match self {
            TachoSigningKey::P256(signing_key) => {
                use p256::ecdsa::Signature;
                use p256::ecdsa::signature::Signer;
                let signature: Signature = signing_key.try_sign(msg)?;

                TachoSignatureBytes::P256(signature.to_bytes())
            }
            TachoSigningKey::P384(signing_key) => {
                use p384::ecdsa::Signature;
                use p384::ecdsa::signature::Signer;

                let signature: Signature = signing_key.try_sign(msg)?;

                TachoSignatureBytes::P384(signature.to_bytes())
            }

            TachoSigningKey::P521(_)
            | TachoSigningKey::BP256(_)
            | TachoSigningKey::BP384(_)
            | TachoSigningKey::BP512(_) => unimplemented!("TachoSigningKey try_sign"),
        })
    }
}
