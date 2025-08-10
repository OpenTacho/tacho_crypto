use std::borrow::Cow;

use const_oid::ObjectIdentifier;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Sequence, SliceWriter, Tag, TagNumber,
};

use crate::ec::public_key::TachoPublicKey;

use super::g2cert::{TachoCurveDomain, UnknownDomainParameters};

/// EU Tachograph G2 certificate
///
/// '7F 21' tagged
///
/// | Field                            | Field ID | Tag     | Length (bytes) | ASN.1 data type                   |
/// |----------------------------------|----------|---------|----------------|-----------------------------------|
/// | ECC Certificate                  | C        | `7F 21` | var            | custom SEQUENCE                   |
/// | ECC Certificate Body             | B        | `7F 4E` | var            | custom SEQUENCE                   |
/// | Certificate Profile Identifier   | CPI      | `5F 29` | 1              | `INTEGER(0..255)`                 |
/// | Certificate Authority Reference  | CAR      | `42`    | 8              | `KeyIdentifier`                   |
/// | Certificate Holder Authorisation | CHA      | `5F 4C` | 7              | `CertificateHolderAuthorisation`  |
/// | Public Key                       | PK       | `7F 49` | var            | custom SEQUENCE                   |
/// | Domain Parameters                | DP       | `06`    | var            | `OBJECT IDENTIFIER`               |
/// | Public Point                     | PP       | `86`    | var            | `OCTET STRING`                    |
/// | Certificate Holder Reference     | CHR      | `5F 20` | 8              | `KeyIdentifier`                   |
/// | Certificate Effective Date       | CEfD     | `5F 25` | 4              | `TimeReal`                        |
/// | Certificate Expiration Date      | CExD     | `5F 24` | 4              | `TimeReal`                        |
/// | ECC Certificate Signature        | S        | `5F 37` | var            | `OCTET STRING`                    |

#[derive(EncodeValue, DecodeValue, Debug, Clone, Eq, PartialEq)]
#[asn1(tag_mode = "IMPLICIT")]
pub struct TachographCertificateRaw<'a> {
    /// constructed
    pub body: TachographCertificateBodyRaw<'a>,

    /// S '5F 37' primitive
    #[asn1(application = "55", type = "OCTET STRING", deref = "true")]
    pub signature: Cow<'a, [u8]>,
}
impl FixedTag for TachographCertificateRaw<'_> {
    const TAG: Tag = Tag::Application {
        number: TagNumber(33),
        constructed: true,
    };
}
impl<'a> TachographCertificateRaw<'a> {
    /// Parses raw tacho G2 certificate into slices
    pub fn from_bytes(der_bytes: &'a [u8]) -> der::Result<Self> {
        let (cert, _) = Self::from_der_partial(der_bytes)?;
        Ok(cert)
    }

    pub fn owned(&self) -> TachographCertificateRaw<'static> {
        TachographCertificateRaw {
            body: self.body.owned(),
            signature: Cow::Owned(self.signature.to_vec()),
        }
    }
}

/// EU Tachograph G2 certificate body
///
/// '7F 4E' tagged
#[derive(EncodeValue, DecodeValue, Debug, Clone, Eq, PartialEq)]
#[asn1(tag_mode = "IMPLICIT")]
pub struct TachographCertificateBodyRaw<'a> {
    /// CPI '5F 29' primitive, 1 byte
    #[asn1(application = "41", type = "OCTET STRING", deref = "true")]
    pub profile_identifier: [u8; 1],

    /// CAR '42' primitive, 8 bytes
    #[asn1(application = "2", type = "OCTET STRING", deref = "true")]
    pub authority_reference: [u8; 8],

    /// CHA '5F 4C' primitive, 7 bytes
    #[asn1(application = "76", type = "OCTET STRING", deref = "true")]
    pub holder_authorisation: [u8; 7],

    /// PK '7F 49' constructed
    #[asn1(application = "73")]
    pub public_key: CertificatePublicKeyRaw<'a>,

    /// CHR '5F 20' primitive, 8 bytes
    #[asn1(application = "32", type = "OCTET STRING", deref = "true")]
    pub holder_reference: [u8; 8],

    /// CEfD '5F 25' primitive, 4 bytes
    #[asn1(application = "37", type = "OCTET STRING", deref = "true")]
    pub effective_date: [u8; 4],

    /// CExD '5F 24' primitive, 4 bytes
    #[asn1(application = "36", type = "OCTET STRING", deref = "true")]
    pub expiration_date: [u8; 4],
}
impl FixedTag for TachographCertificateBodyRaw<'_> {
    const TAG: Tag = Tag::Application {
        number: TagNumber(78),
        constructed: true,
    };
}

impl TachographCertificateBodyRaw<'_> {
    pub fn verify_raw_with_key(
        &self,
        ca_key: &TachoPublicKey,
        signature: &[u8],
    ) -> eyre::Result<()> {
        let mut buf = [0u8; 341];

        let encoded_body = {
            let mut writer = SliceWriter::new(&mut buf);
            self.encode(&mut writer)?;
            writer.finish()?
        };
        ca_key.verifying().verify(encoded_body, signature)
    }

    pub fn owned(&self) -> TachographCertificateBodyRaw<'static> {
        TachographCertificateBodyRaw {
            profile_identifier: self.profile_identifier,
            authority_reference: self.authority_reference,
            holder_authorisation: self.holder_authorisation,
            public_key: self.public_key.owned(),
            holder_reference: self.holder_reference,
            effective_date: self.effective_date,
            expiration_date: self.expiration_date,
        }
    }
}

/// EU Tachograph G2 certificate public key
///
/// '7F 49' tagged
#[derive(Sequence, Debug, Clone, Eq, PartialEq)]
#[asn1(tag_mode = "IMPLICIT")]
pub struct CertificatePublicKeyRaw<'a> {
    /// DP tag '06'
    // TODO: use `ObjectIdentifier<10>` or `ObjectIdentifierRef`
    pub domain_parameters: ObjectIdentifier,

    /// PP tag '86'
    #[asn1(context_specific = "6", type = "OCTET STRING", deref = "true")]
    pub public_point: Cow<'a, [u8]>,
}

impl CertificatePublicKeyRaw<'_> {
    pub fn domain(&self) -> Result<TachoCurveDomain, UnknownDomainParameters> {
        TachoCurveDomain::try_from(self.domain_parameters)
    }

    pub fn owned(&self) -> CertificatePublicKeyRaw<'static> {
        CertificatePublicKeyRaw {
            domain_parameters: self.domain_parameters,
            public_point: Cow::Owned(self.public_point.to_vec()),
        }
    }
}

#[cfg(test)]
pub mod test {

    use super::TachographCertificateRaw;
    use der::{Decode, Encode, oid::ObjectIdentifier};
    use hex_literal::hex;

    const GREECE_MSCA_CERT_DER: &[u8] = &hex!(
    "7F 21  81 C8" // Application 33

        "7F 4E  81 81" // Appliction 78

            "5F 29" // Application 41
                "01 00"
            "42 08" // Application 2
                "FD 45 43 20 01 FF FF 01"
            "5F 4C  07" // Application 76
                "FF 53 4D 52 44 54 0E"
            "7F 49  4D" // Application 73
                "06 08 2A 86 48  CE 3D 03 01 07 86 41 04
                30 E8 EE D8 05 1D FB 8F  05 BF 4E 34 90 B8 A0 1C
                83 21 37 4E 99 41 67 70  64 28 23 A2 C9 E1 21 16
                D9 27 46 45 94 DD CB CC  79 42 B5 F3 EE 1A A3 AB
                A2 5C E1 6B 20 92 00 F0  09 70 D9 CF 83 0A 33 4B"


            "5F 20 08" // Application 32
                "17 47 52 20 02  FF FF 01"
            "5F 25 04" // Application 37
                "62 A3 B0 D0"
            "5F 24 04" // Application 36
                "6F F6 49 50"
        "5F 37 40" // Application 55
            "6D 3E FD 97
                BE 83 EC 65 5F 51 4D 8C  47 60 DB FD 9B A2 D1 5D
                3C 1A 21 93 CE D7 EA F2  A2 0D 89 CC 4A 4F 0C 4B
                E5 3F A3 F9 0F 20 B5 74  67 26 DB 19 9E FF DE 0B
                D0 B9 2C B9 D1 5A E2 18  08 6C F0 E2"
    );

    const BULGARIA_MSCA_CERT_DER: &[u8] = &hex!(
    "7F 21 81 C9" // tag: APPLICATION [33] (constructed) len: 201
            "7F 4E 81 82" // tag: APPLICATION [78] (constructed) len: 130
                    "5F 29 01" // tag: APPLICATION [41] (primitive)
                            "00"
                    "42 08" // tag: APPLICATION [2] (primitive)
                            "FD 45 43 20 01 FF FF 01"
                    "5F 4C 07" // tag: APPLICATION [76] (primitive)
                            "FF 53 4D 52 44 54 0E"
                    "7F 49 4E" // tag: APPLICATION [73] (constructed) len: 78
                            "06 09" // tag: OBJECT IDENTIFIER
                                    "2B 24 03 03 02 08 01 01 07"
                            "86 41" // tag: CONTEXT-SPECIFIC [6] (primitive) len: 65
                                    "04 18 7E 47 93 EE E5 AA 0D 82 34 A7 19 40 BB D8
                                 A1 DF 58 99 53 AA 5F 0C C2 2D 91 6D D0 03 E9 EB 
                                 64 83 6F DB FA F9 96 02 6F 1B 06 6F 05 FC D2 9D 
                                 71 A9 BA 79 F9 B8 6A 01 AB B8 CD 28 7A A6 35 DC 
                                 F1"
                    "5F 20 08" // tag: APPLICATION [32] (primitive)
                            "07 42 47 20 22 FF FF 01"
                    "5F 25 04" // tag: APPLICATION [37] (primitive)
                            "5F CE C2 00"
                    "5F 24 04" // tag: APPLICATION [36] (primitive)
                            "6D 21 5A 80"
            "5F 37 40" // tag: APPLICATION [55] (primitive) len: 64
                    "89 4E 5A 34 D1 AA 61 67 DE C9 FE 5C 23 1A 80 53
                 F4 C2 D9 8F 29 1E 34 27 AC 6B AB AA 0F C6 02 8A 
                 40 A0 37 91 A1 F6 FA 7B 51 78 3B 0F 3F 32 28 E1 
                 8E AE 82 57 86 07 97 53 EE FA 86 29 64 51 48 0B"
    );
    #[test]
    fn decode_tacho_application_tags() {
        let tacho_cert = TachographCertificateRaw::from_der(GREECE_MSCA_CERT_DER).unwrap();

        let sig = &tacho_cert.signature;
        assert_eq!(&sig[..2], hex!("6D 3E"));
        assert_eq!(tacho_cert.body.profile_identifier, [0x00]);
        assert_eq!(
            tacho_cert.body.authority_reference,
            hex!("FD 45 43 20 01 FF FF 01")
        );
        assert_eq!(
            tacho_cert.body.holder_authorisation,
            hex!("FF 53 4D 52 44 54 0E")
        );
        assert_eq!(
            tacho_cert.body.public_key.domain_parameters,
            ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7")
        );
        assert_eq!(
            &tacho_cert.body.public_key.public_point[..4],
            hex!("04 30 E8 EE")
        );
        const GREECE: &[u8] = b"GR ";
        assert_eq!(&tacho_cert.body.holder_reference[1..4], GREECE);

        // Re-encode
        let mut buf = [0u8; 256];
        let encoded = tacho_cert.encode_to_slice(&mut buf).unwrap();
        assert_eq!(encoded, GREECE_MSCA_CERT_DER);
    }

    #[test]
    fn decode_bulgaria_cert() {
        TachographCertificateRaw::from_der(GREECE_MSCA_CERT_DER).unwrap();
    }
}
