use crate::ec::{
    encoded_point::TachoEncodedPoint, public_key::TachoPublicKey, secret_key::TachoSecretKey,
};

use super::{
    anycurvesignature::AnyCurveSignature,
    g2authorization::G2CertificateHolderAuthorisation,
    g2certraw::{CertificatePublicKeyRaw, TachographCertificateBodyRaw, TachographCertificateRaw},
};
use const_oid::{
    ObjectIdentifierRef,
    db::{
        rfc5639::{BRAINPOOL_P_256_R_1, BRAINPOOL_P_384_R_1, BRAINPOOL_P_512_R_1},
        rfc5912::{SECP_256_R_1, SECP_384_R_1, SECP_521_R_1},
    },
};
use der::{Decode, oid::ObjectIdentifier};
use eyre::{Context, bail};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, error::Error, fmt::Debug};
use strum::AsRefStr;
use strum_macros::EnumIter;
use tacho_cert_common::{
    keyidentifier::{KeyIdentifier, authority::AuthorityKID},
    timereal::{TimeReal, TimeRealTooLarge},
};

/// EU Tachograph certificate
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct TachographCertificate {
    /// body
    pub body: TachographCertificateBody,

    /// 64, 96, 128 or 132 bytes
    pub signature: AnyCurveSignature,
}

const TACHO_G2_CERT_VERSION_1: u8 = 0x00;

/// EU Tachograph certificate body
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct TachographCertificateBody {
    /// CAR Certificate Authority Reference
    ///
    /// CSM_138 The Certificate Authority Reference shall be used to identify
    /// the public key to be used to verify the certificate signature.
    /// The Certificate Authority Reference shall therefore be equal
    /// to the Certificate Holder Reference in the certificate of the
    /// corresponding certificate authority.
    ///
    /// CSM_139 An ERCA root certificate shall be self-signed, i.e.,
    /// the Certificate Authority Reference and the Certificate Holder
    /// Reference in the certificate shall be equal.
    ///
    /// CSM_140 For an ERCA link certificate, the Certificate Holder
    /// Reference shall be equal to the CHR of the new ERCA
    /// root certificate. The Certificate Authority Reference for a
    /// link certificate shall be equal to the CHR of the previous
    /// ERCA root certificate.
    pub authority_reference: AuthorityKID,

    /// CHA Certificate Holder Authorisation
    ///
    /// CSM_141 The Certificate Holder Authorisation shall be used to
    /// identify the type of certificate. It consists of the six most
    /// significant bytes of the Tachograph Application ID, concatenated
    /// with the equipment type, which indicates the type of
    /// equipment for which the certificate is intended. In the case
    /// of a VU certificate, a driver card certificate or a workshop
    /// card certificate, the equipment type is also used to differ
    /// entiate between a certificate for Mutual Authentication and a
    /// certificate for creating digital signatures (see section 9.1 and
    /// Appendix 1, data type EquipmentType).
    pub holder_authorisation: G2CertificateHolderAuthorisation,

    /// C.PK Public Key
    ///
    /// The Public Key nests two data elements: the standardized domain
    /// parameters to be used with the public key in the certificate and the
    /// value of the public point.
    pub public_key: CertificatePublicKey,

    /// CHR Certificate Holder Reference
    ///
    /// CSM_144 The Certificate Holder Reference is an identifier for the
    /// public key provided in the certificate. It shall be used to
    /// reference this public key in other certificates.
    ///
    /// CSM_145 For card certificates and external GNSS facility certificates,
    /// the Certificate Holder Reference shall have the
    /// data type specified in Appendix 1.
    ///
    /// CSM_146 For vehicle units, the manufacturer, when requesting a
    /// certificate, may or may not know the manufacturer-specific
    /// serial number of the VU for which that certificate and the
    /// associated private key is intended. In the first case, the
    /// Certificate Holder Reference shall have the
    /// data type specified in Appendix 1.
    ///
    /// In the latter case, the Certificate Holder
    /// Reference shall have the
    /// data type specified in Appendix 1.
    pub holder_reference: KeyIdentifier,

    /// EfD Certificate Effective Date
    /// CSM_148 The Certificate Effective Date shall indicate the starting date
    /// and time of the validity period of the certificate.
    pub effective_date: TimeReal,

    /// ExD Certificate Expiration Date
    /// CSM_149 The Certificate Expiration Date shall indicate the end date
    /// and time of the validity period of the certificate.
    pub expiration_date: TimeReal,
}

/// EU Tachograph G2 certificate public key
///
/// The Public Key nests two data elements: the standardized domain
/// parameters to be used with the public key in the certificate and the
/// value of the public point.
///
/// CSM_142 The data element Domain Parameters shall contain one of
/// the object identifiers specified in Table 1 to reference a set
/// of standardized domain parameters.
///
/// CSM_143 The data element Public Point shall contain the public point.
/// Elliptic curve public points shall be converted to octet
/// strings as specified in [TR-03111]. The uncompressed
/// encoding format shall be used. When recovering an
/// elliptic curve point from its encoded format, the validations
/// described in [TR-03111] shall always be carried out.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CertificatePublicKey {
    pub public_point: TachoPublicKey,
}

impl From<TachoPublicKey> for CertificatePublicKey {
    fn from(public_point: TachoPublicKey) -> Self {
        Self { public_point }
    }
}

impl CertificatePublicKey {
    pub fn from_raw(raw: &CertificatePublicKeyRaw) -> eyre::Result<Self> {
        let domain = raw.domain()?;
        //println!("CertificatePublicKey::from_raw {domain:?}");
        let public_point = TachoPublicKey::from_sec1_bytes(domain, &raw.public_point)
            .wrap_err("TachoVerifyingKey::from_sec1_bytes")?;
        Ok(Self { public_point })
    }

    pub fn to_encoded_point(&self, compress: bool) -> TachoEncodedPoint {
        self.public_point.to_encoded_point(compress)
    }

    #[deprecated = "use to_encoded_point"]
    pub fn to_raw(&self) -> CertificatePublicKeyRaw<'static> {
        self.to_encoded_point(false).to_raw().owned()
    }
}

impl TryFrom<&CertificatePublicKeyRaw<'_>> for CertificatePublicKey {
    type Error = eyre::Report;

    fn try_from(raw: &CertificatePublicKeyRaw) -> Result<Self, Self::Error> {
        CertificatePublicKey::from_raw(raw)
    }
}

impl TachographCertificate {
    pub fn from_raw(raw: &TachographCertificateRaw) -> eyre::Result<Self> {
        let cert = Self {
            body: TachographCertificateBody::from_raw(&raw.body)?,
            signature: AnyCurveSignature::from(raw.signature.as_ref()),
        };
        Ok(cert)
    }
    pub fn parse(cert_bytes: &[u8]) -> eyre::Result<Self> {
        let raw = TachographCertificateRaw::from_der(cert_bytes)?;
        Self::from_raw(&raw)
    }

    pub fn verify_with(&self, ca: &TachographCertificate) -> eyre::Result<()> {
        self.verify_with_ca_body(&ca.body)
            .wrap_err("verify_with_ca_body")
    }

    pub fn verify_with_ca_body(&self, ca: &TachographCertificateBody) -> eyre::Result<()> {
        self.verify_with_key(&ca.public_key.public_point)
            .wrap_err("verify_with_key")
    }

    /// Verifies self signature with given public key
    pub fn verify_with_key(&self, ca_key: &TachoPublicKey) -> eyre::Result<()> {
        let builder = self.body.raw_builder();
        let raw_body = builder.to_raw()?;
        raw_body
            .verify_raw_with_key(ca_key, &self.signature)
            .wrap_err("verify_raw_with_key")
    }

    /// Signs self with given private key
    pub fn sign_with_key(&mut self, ca_key: &TachoSecretKey) -> eyre::Result<()> {
        let builder = self.body.raw_builder();
        let raw_body = builder.to_raw()?;
        // let signature = raw_body
        //     .sign_raw_with_key(ca_key)
        //     .wrap_err("sign_raw_with_key")?;
        todo!();
        Ok(())
    }

    /// Creates an intermediate object used for encoding raw cert
    pub fn raw_builder(&self) -> TachoCertRawBuilder<'_> {
        TachoCertRawBuilder {
            body_builder: self.body.raw_builder(),
            signature: &self.signature,
        }
    }
}
pub struct TachoCertRawBuilder<'a> {
    signature: &'a [u8],
    body_builder: TachoCertBodyRawBuilder<'a>,
}

impl TachoCertRawBuilder<'_> {
    /// Creates raw cert using borrowed bytes (without allocations)
    pub fn to_raw(&self) -> Result<TachographCertificateRaw<'_>, TimeRealTooLarge> {
        Ok(TachographCertificateRaw {
            body: self.body_builder.to_raw()?,
            signature: Cow::Borrowed(self.signature),
        })
    }
}

impl TachographCertificateBody {
    pub fn from_bytes(cert_bytes: &[u8]) -> eyre::Result<Self> {
        let raw_cert = TachographCertificateBodyRaw::from_der(cert_bytes)?;

        Self::from_raw(&raw_cert)
    }

    pub fn from_raw(raw: &TachographCertificateBodyRaw) -> eyre::Result<Self> {
        if raw.profile_identifier[0] != TACHO_G2_CERT_VERSION_1 {
            bail!("only Tachograph G2 cert version 1 (0x00) is supported")
        }

        let holder_authorisation =
            G2CertificateHolderAuthorisation::parse(raw.holder_authorisation)?;

        let is_equipment = holder_authorisation.equipment_type.is_equipment();

        let body = Self {
            authority_reference: AuthorityKID::from_bytes(raw.authority_reference)?,
            holder_authorisation,
            public_key: CertificatePublicKey::from_raw(&raw.public_key)?,
            holder_reference: KeyIdentifier::from_bytes(raw.holder_reference, is_equipment)?,
            effective_date: TimeReal::from_bytes(raw.effective_date),
            expiration_date: TimeReal::from_bytes(raw.expiration_date),
        };

        Ok(body)
    }

    /// Creates an intermediate object used for encoding raw cert
    pub fn raw_builder(&self) -> TachoCertBodyRawBuilder<'_> {
        TachoCertBodyRawBuilder {
            encoded_point: self.public_key.public_point.to_encoded_point(false),
            body: self,
        }
    }
}

pub struct TachoCertBodyRawBuilder<'a> {
    body: &'a TachographCertificateBody,
    encoded_point: TachoEncodedPoint,
}
impl TachoCertBodyRawBuilder<'_> {
    /// Creates raw body using borrowed encoded public point data
    pub fn to_raw(&self) -> Result<TachographCertificateBodyRaw<'_>, TimeRealTooLarge> {
        Ok(TachographCertificateBodyRaw {
            profile_identifier: [TACHO_G2_CERT_VERSION_1],
            authority_reference: self.body.authority_reference.to_bytes(),
            holder_authorisation: self.body.holder_authorisation.to_bytes(),
            public_key: self.encoded_point.to_raw(),
            holder_reference: self.body.holder_reference.to_bytes(),
            effective_date: self.body.effective_date.to_bytes()?,
            expiration_date: self.body.expiration_date.to_bytes()?,
        })
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, AsRefStr, EnumIter)]
pub enum TachoCurveDomain {
    NistSecp256r1,
    NistSecp384r1,
    NistSecp521r1,

    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
}

#[derive(Debug)]
pub struct UnknownDomainParameters;

impl Error for UnknownDomainParameters {}
impl std::fmt::Display for UnknownDomainParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnknownDomainParameters")
    }
}

impl TryFrom<ObjectIdentifier> for TachoCurveDomain {
    type Error = UnknownDomainParameters;

    fn try_from(value: ObjectIdentifier) -> Result<Self, Self::Error> {
        if value == SECP_256_R_1 {
            Ok(TachoCurveDomain::NistSecp256r1)
        } else if value == SECP_384_R_1 {
            Ok(TachoCurveDomain::NistSecp384r1)
        } else if value == SECP_521_R_1 {
            Ok(TachoCurveDomain::NistSecp521r1)
        } else if value == BRAINPOOL_P_256_R_1 {
            Ok(TachoCurveDomain::BrainpoolP256r1)
        } else if value == BRAINPOOL_P_384_R_1 {
            Ok(TachoCurveDomain::BrainpoolP384r1)
        } else if value == BRAINPOOL_P_512_R_1 {
            Ok(TachoCurveDomain::BrainpoolP512r1)
        } else {
            Err(UnknownDomainParameters)
        }
    }
}

impl TachoCurveDomain {
    pub const fn oid(&self) -> &ObjectIdentifier {
        match self {
            TachoCurveDomain::NistSecp256r1 => &SECP_256_R_1,
            TachoCurveDomain::NistSecp384r1 => &SECP_384_R_1,
            TachoCurveDomain::NistSecp521r1 => &SECP_521_R_1,
            TachoCurveDomain::BrainpoolP256r1 => &BRAINPOOL_P_256_R_1,
            TachoCurveDomain::BrainpoolP384r1 => &BRAINPOOL_P_384_R_1,
            TachoCurveDomain::BrainpoolP512r1 => &BRAINPOOL_P_512_R_1,
        }
    }
    pub const fn oid_ref(&self) -> &ObjectIdentifierRef {
        self.oid().as_oid_ref()
    }

    /// scalar length in bits
    pub const fn bit_size(&self) -> u16 {
        match self {
            TachoCurveDomain::NistSecp256r1 => 256,
            TachoCurveDomain::NistSecp384r1 => 384,
            TachoCurveDomain::NistSecp521r1 => 521,
            TachoCurveDomain::BrainpoolP256r1 => 256,
            TachoCurveDomain::BrainpoolP384r1 => 384,
            TachoCurveDomain::BrainpoolP512r1 => 512,
        }
    }

    /// scalar length in bytes
    pub const fn scalar_len(&self) -> u16 {
        (self.bit_size() + 7) / 8
    }

    /// point length in bytes
    pub const fn signature_len(&self) -> u16 {
        self.scalar_len() * 2
    }

    /// Complementary domain parameters.
    ///
    /// Gives another domain, that is different in every way (length and algorithm) from self.
    pub const fn different_len_domain(&self) -> TachoCurveDomain {
        match self {
            TachoCurveDomain::NistSecp256r1 => TachoCurveDomain::BrainpoolP512r1,
            TachoCurveDomain::NistSecp384r1 => TachoCurveDomain::BrainpoolP256r1,
            TachoCurveDomain::NistSecp521r1 => TachoCurveDomain::BrainpoolP384r1,
            TachoCurveDomain::BrainpoolP256r1 => TachoCurveDomain::NistSecp384r1,
            TachoCurveDomain::BrainpoolP384r1 => TachoCurveDomain::NistSecp521r1,
            TachoCurveDomain::BrainpoolP512r1 => TachoCurveDomain::NistSecp256r1,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::cert::g2cert::{CertificatePublicKey, TachoCurveDomain};
    use der::Encode;
    use rand_core::TryRngCore;

    #[test]
    fn oid_lengths() {
        use strum::IntoEnumIterator;
        for domain in TachoCurveDomain::iter() {
            println!(
                "{domain:?} oid encoded_len: {}",
                domain.oid().encoded_len().unwrap()
            );
        }

        for domain in TachoCurveDomain::iter() {
            println!("{domain:?} oid len: {}", domain.oid().as_bytes().len());
        }
    }
    #[test]
    fn public_key_lengths() {
        use crate::ec::secret_key::TachoSecretKey;
        use rand_core::OsRng;
        use strum::IntoEnumIterator;

        let mut min_len: u32 = 1000;
        let mut max_len: u32 = 0;
        for domain in TachoCurveDomain::iter() {
            let sk = TachoSecretKey::random(domain, &mut OsRng.unwrap_mut());

            let pk = sk.public_key();
            let pk: CertificatePublicKey = pk.into();

            let pk = pk.to_encoded_point(false);
            let pk = pk.to_raw();
            let encoded_len = pk.encoded_len().unwrap();
            min_len = min_len.min(u32::from(encoded_len));
            max_len = max_len.max(u32::from(encoded_len));
            println!("{domain:?} public key encoded_len: {}", encoded_len);
        }
        println!("range: {:?}", min_len..=max_len);
    }
}
