use super::{
    non_zero_scalar::TachoNonZeroScalar, public_key::TachoPublicKey, signing_key::TachoSigningKey,
};
use crate::cert::g2cert::TachoCurveDomain;
use ecdsa::SigningKey;
use elliptic_curve::ScalarPrimitive;
use eyre::{OptionExt, eyre};

use p256::pkcs8::{DecodePrivateKey, PrivateKeyInfoRef, SecretDocument, der::pem::PemLabel};
use rand_core::CryptoRng;

use elliptic_curve::zeroize::Zeroizing;

/// EC Secret (Private) scalar Key
pub enum TachoSecretKey {
    /// Nist
    P256(p256::SecretKey),

    /// Nist
    P384(p384::SecretKey),

    /// Nist
    P521(p521::SecretKey),

    /// Brainpool
    BP256(bp256::r1::SecretKey),

    /// Brainpool
    BP384(bp384::r1::SecretKey),

    /// Brainpool
    BP512(()),
}
impl TachoSecretKey {
    pub fn random(domain: TachoCurveDomain, rng: &mut (impl CryptoRng + ?Sized)) -> Self {
        match domain {
            TachoCurveDomain::NistSecp256r1 => Self::P256(p256::SecretKey::random(rng)),
            TachoCurveDomain::NistSecp384r1 => Self::P384(p384::SecretKey::random(rng)),
            TachoCurveDomain::NistSecp521r1 => Self::P521(p521::SecretKey::random(rng)),

            TachoCurveDomain::BrainpoolP256r1 => Self::BP256(bp256::r1::SecretKey::random(rng)),
            TachoCurveDomain::BrainpoolP384r1 => Self::BP384(bp384::r1::SecretKey::random(rng)),

            TachoCurveDomain::BrainpoolP512r1 => {
                unimplemented!("random BrainpoolP512r1")
            }
        }
    }

    /// Constructs secret key from raw scalar
    //#[cfg(test)]
    pub fn from_raw(domain: TachoCurveDomain, secret_d: &[u8]) -> eyre::Result<Self> {
        Ok(match domain {
            TachoCurveDomain::NistSecp256r1 => {
                let scalar = ScalarPrimitive::from_slice(secret_d)?;
                Self::P256(
                    p256::SecretKey::from_scalar(scalar)
                        .into_option()
                        .ok_or_eyre("expected non-zero secret")?,
                )
            }
            TachoCurveDomain::NistSecp384r1 => {
                let scalar = ScalarPrimitive::from_slice(secret_d)?;
                Self::P384(
                    p384::SecretKey::from_scalar(scalar)
                        .into_option()
                        .ok_or_eyre("expected non-zero secret")?,
                )
            }
            TachoCurveDomain::NistSecp521r1 => {
                let scalar = ScalarPrimitive::from_slice(secret_d)?;
                Self::P521(
                    p521::SecretKey::from_scalar(scalar)
                        .into_option()
                        .ok_or_eyre("expected non-zero secret")?,
                )
            }
            TachoCurveDomain::BrainpoolP256r1 => {
                let scalar = ScalarPrimitive::from_slice(secret_d)?;
                Self::BP256(
                    bp256::r1::SecretKey::from_scalar(scalar)
                        .into_option()
                        .ok_or_eyre("expected non-zero secret")?,
                )
            }
            TachoCurveDomain::BrainpoolP384r1 => {
                let scalar = ScalarPrimitive::from_slice(secret_d)?;
                Self::BP384(
                    bp384::r1::SecretKey::from_scalar(scalar)
                        .into_option()
                        .ok_or_eyre("expected non-zero secret")?,
                )
            }
            TachoCurveDomain::BrainpoolP512r1 => todo!(),
        })
    }

    pub fn to_nonzero_scalar(&self) -> Zeroizing<TachoNonZeroScalar> {
        Zeroizing::new(match self {
            TachoSecretKey::P256(secret_key) => {
                TachoNonZeroScalar::P256(secret_key.to_nonzero_scalar())
            }
            TachoSecretKey::P384(secret_key) => {
                TachoNonZeroScalar::P384(secret_key.to_nonzero_scalar())
            }
            TachoSecretKey::P521(secret_key) => {
                TachoNonZeroScalar::P521(secret_key.to_nonzero_scalar())
            }
            TachoSecretKey::BP256(secret_key) => {
                TachoNonZeroScalar::BP256(secret_key.to_nonzero_scalar())
            }
            TachoSecretKey::BP384(secret_key) => {
                TachoNonZeroScalar::BP384(secret_key.to_nonzero_scalar())
            }
            TachoSecretKey::BP512(_secret_key) => TachoNonZeroScalar::BP512(()),
        })
    }

    pub fn public_key(&self) -> TachoPublicKey {
        match self {
            TachoSecretKey::P256(sk) => TachoPublicKey::P256(sk.public_key()),
            TachoSecretKey::P384(sk) => TachoPublicKey::P384(sk.public_key()),
            TachoSecretKey::P521(sk) => TachoPublicKey::P521(sk.public_key()),

            TachoSecretKey::BP256(sk) => TachoPublicKey::BP256(sk.public_key()),
            TachoSecretKey::BP384(sk) => TachoPublicKey::BP384(sk.public_key()),

            TachoSecretKey::BP512(_) => {
                unimplemented!("public_key BP512")
            }
        }
    }

    pub fn signing(&self) -> TachoSigningKey {
        match self {
            TachoSecretKey::P256(secret_key) => TachoSigningKey::P256(SigningKey::from(secret_key)),
            TachoSecretKey::P384(secret_key) => TachoSigningKey::P384(SigningKey::from(secret_key)),
            TachoSecretKey::P521(secret_key) => TachoSigningKey::P521(SigningKey::from(secret_key)),
            TachoSecretKey::BP256(secret_key) => {
                TachoSigningKey::BP256(SigningKey::from(secret_key))
            }
            TachoSecretKey::BP384(secret_key) => {
                TachoSigningKey::BP384(SigningKey::from(secret_key))
            }
            TachoSecretKey::BP512(_secret_key) => TachoSigningKey::BP512(()),
        }
    }

    pub fn from_pkcs8_pem(pem_str: &str) -> eyre::Result<Self> {
        let (label, doc) = SecretDocument::from_pem(pem_str)?;
        PrivateKeyInfoRef::validate_pem_label(label).map_err(|_| eyre!("invalid pem label"))?;
        Self::from_pkcs8_der(doc.as_bytes())
    }

    /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary format).
    pub fn from_pkcs8_der(bytes: &[u8]) -> eyre::Result<Self> {
        let p256_result = p256::SecretKey::from_pkcs8_der(bytes);
        let p256_err = match p256_result {
            Ok(sk) => return Ok(Self::P256(sk)),
            Err(err) => err,
        };

        if let Ok(sk) = p384::SecretKey::from_pkcs8_der(bytes) {
            return Ok(Self::P384(sk));
        }

        Err(p256_err.into())
    }

    //#[cfg(test)]
    pub fn to_pkcs8_der(&self) -> eyre::Result<Zeroizing<Vec<u8>>> {
        use elliptic_curve::pkcs8::EncodePrivateKey;
        Ok(match self {
            TachoSecretKey::P256(secret_key) => secret_key.to_pkcs8_der()?.to_bytes(),
            TachoSecretKey::P384(secret_key) => secret_key.to_pkcs8_der()?.to_bytes(),
            TachoSecretKey::P521(_ssl_ec_key_private) => todo!(),
            TachoSecretKey::BP256(_ssl_ec_key_private) => todo!(),
            TachoSecretKey::BP384(_ssl_ec_key_private) => todo!(),
            TachoSecretKey::BP512(_ssl_ec_key_private) => todo!(),
        })
    }

    //#[cfg(test)]
    pub fn to_pkcs8_pem(&self) -> eyre::Result<Zeroizing<String>> {
        use elliptic_curve::pkcs8::EncodePrivateKey;
        let lf = p256::pkcs8::LineEnding::LF;
        Ok(match self {
            TachoSecretKey::P256(secret_key) => secret_key.to_pkcs8_pem(lf)?,
            TachoSecretKey::P384(secret_key) => secret_key.to_pkcs8_pem(lf)?,
            TachoSecretKey::P521(_ssl_ec_key_private) => todo!(),
            TachoSecretKey::BP256(_ssl_ec_key_private) => todo!(),
            TachoSecretKey::BP384(_ssl_ec_key_private) => todo!(),
            TachoSecretKey::BP512(_ssl_ec_key_private) => todo!(),
        })
    }

    pub fn domain(&self) -> TachoCurveDomain {
        match self {
            TachoSecretKey::P256(_) => TachoCurveDomain::NistSecp256r1,
            TachoSecretKey::P384(_) => TachoCurveDomain::NistSecp384r1,
            TachoSecretKey::P521(_) => TachoCurveDomain::NistSecp521r1,
            TachoSecretKey::BP256(_) => TachoCurveDomain::BrainpoolP256r1,
            TachoSecretKey::BP384(_) => TachoCurveDomain::BrainpoolP384r1,
            TachoSecretKey::BP512(_) => TachoCurveDomain::BrainpoolP512r1,
        }
    }
}
