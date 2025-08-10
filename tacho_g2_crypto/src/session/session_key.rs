use crate::{
    auth::{auth_token::TachoAuthenticationToken, cmac::TachoCmac},
    ec::public_key::TachoPublicKey,
};

use super::aes::{TachoAes, TachoAesCbcDec, TachoAesCbcEnc};

/// AES Key
///
/// k_enc or k_mac
///
/// Result of KDF
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TachoSessionKey {
    /// CS#1
    ///
    /// ECC key size (bits): 256
    ///
    /// AES key length (bits): 128 = 16 bytes
    ///
    /// Hashing algorithm: SHA-256
    ///
    /// MAC length (bytes): 8
    ///
    /// Mac8
    CS1(Cs1SessionKey),

    /// CS#2
    ///
    /// ECC key size (bits): 384
    ///
    /// AES key length (bits): 192 = 24 bytes
    ///
    /// Hashing algorithm: SHA-384
    ///
    /// MAC length (bytes): 12
    ///
    /// Mac12
    CS2(Cs2SessionKey),

    /// CS#3
    ///
    /// ECC key size (bits): 512/521
    ///
    /// AES key length (bits): 256 = 32 bytes
    ///
    /// Hashing algorithm: SHA-512
    ///
    /// MAC length (bytes): 16
    ///
    /// Mac16
    CS3(Cs3SessionKey),
}

// 16 bytes
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub struct Cs1SessionKey(pub [u8; 16]);

// 24 bytes
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub struct Cs2SessionKey(pub [u8; 24]);

// 32 bytes
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub struct Cs3SessionKey(pub [u8; 32]);

impl From<Cs1SessionKey> for TachoSessionKey {
    fn from(value: Cs1SessionKey) -> Self {
        value.to_enum()
    }
}
impl From<Cs2SessionKey> for TachoSessionKey {
    fn from(value: Cs2SessionKey) -> Self {
        value.to_enum()
    }
}
impl From<Cs3SessionKey> for TachoSessionKey {
    fn from(value: Cs3SessionKey) -> Self {
        value.to_enum()
    }
}

impl From<[u8; 16]> for Cs1SessionKey {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

impl From<[u8; 24]> for Cs2SessionKey {
    fn from(value: [u8; 24]) -> Self {
        Self(value)
    }
}
impl From<[u8; 32]> for Cs3SessionKey {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

pub trait SessionKeyFromDigest {
    fn cut_from_digest(t_picc_material: &[u8]) -> Option<Self>
    where
        Self: Sized;

    fn to_enum(self) -> TachoSessionKey;
}

impl SessionKeyFromDigest for Cs1SessionKey {
    /// Cuts digest to 16 bytes length
    ///
    /// Returns None if digest is smaller than target key size
    fn cut_from_digest(digest: &[u8]) -> Option<Self> {
        let mut key = Self::default();
        let len = key.0.len();
        key.0.copy_from_slice(digest.get(..len)?);
        Some(key)
    }

    fn to_enum(self) -> TachoSessionKey {
        TachoSessionKey::CS1(self)
    }
}

impl SessionKeyFromDigest for Cs2SessionKey {
    /// Cuts digest to 24 bytes length
    ///
    /// Returns None if digest is smaller than target key size
    fn cut_from_digest(digest: &[u8]) -> Option<Self> {
        let mut key = Self::default();
        let len = key.0.len();
        key.0.copy_from_slice(digest.get(..len)?);
        Some(key)
    }
    fn to_enum(self) -> TachoSessionKey {
        TachoSessionKey::CS2(self)
    }
}

impl SessionKeyFromDigest for Cs3SessionKey {
    /// Cuts digest to 32 bytes length
    ///
    /// Returns None if digest is smaller than target key size
    fn cut_from_digest(digest: &[u8]) -> Option<Self> {
        let mut key = Self::default();
        let len = key.0.len();
        key.0.copy_from_slice(digest.get(..len)?);
        Some(key)
    }
    fn to_enum(self) -> TachoSessionKey {
        TachoSessionKey::CS3(self)
    }
}

impl TachoSessionKey {
    /// Key material
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            TachoSessionKey::CS1(key) => key.0.as_slice(),
            TachoSessionKey::CS2(key) => key.0.as_slice(),
            TachoSessionKey::CS3(key) => key.0.as_slice(),
        }
    }

    /// Returns T_PICC = CMAC(K_MAC , VU.PK_eph )
    ///
    /// 8, 12 or 16 bytes
    pub fn cmac(&self, vu_pk_eph: &TachoPublicKey) -> TachoAuthenticationToken {
        let sec1_encoded = vu_pk_eph.to_encoded_point(false);
        self.cmac_bytes(sec1_encoded.as_ref())
    }

    /// Internal.
    ///
    /// Returns CMAC(K_MAC , message )
    ///
    /// 8, 12 or 16 bytes
    pub fn cmac_bytes(&self, message: &[u8]) -> TachoAuthenticationToken {
        let mut cmac = self.new_cmac();

        cmac.update(message);
        cmac.finalize()
    }

    /// Internal.
    ///
    /// Returns CMAC(K_MAC , ... )
    ///
    /// 8, 12 or 16 bytes
    pub fn new_cmac(&self) -> TachoCmac {
        TachoCmac::from_key(self)
    }

    /// Create new AES from K_enc
    pub fn new_aes(&self) -> TachoAes {
        TachoAes::new(self)
    }

    /// Create new AES CBC Encryptor from K_enc
    pub fn new_aes_cbc_enc(&self, iv: [u8; 16]) -> TachoAesCbcEnc {
        TachoAesCbcEnc::new(self, iv)
    }

    /// Create new AES CBC Decryptor from K_enc
    pub fn new_aes_cbc_dec(&self, iv: [u8; 16]) -> TachoAesCbcDec {
        TachoAesCbcDec::new(self, iv)
    }
}

#[cfg(test)]
pub mod test {
    use super::TachoSessionKey;
    use crate::{
        auth::auth_token::TachoAuthenticationToken,
        cert::{g2cert::TachoCurveDomain, hexslice::HexDisplay},
        ec::public_key::TachoPublicKey,
    };
    use hex_literal::hex;

    #[test]
    pub fn test_cmac_raw_bytes_cs1() {
        let k_mac =
            TachoSessionKey::CS1([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15].into());

        let t_picc = k_mac.cmac_bytes(&[0, 1, 2, 3]);

        println!("t_picc: {}", HexDisplay(t_picc.as_ref()));

        assert_eq!(
            t_picc,
            TachoAuthenticationToken::CS1(hex!("1B F1 FA A0 E4 AA 23 92").into())
        );
    }

    #[test]
    pub fn test_cmac_raw_bytes_cs2() {
        let k_mac = TachoSessionKey::CS2(
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, //
                12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            ]
            .into(),
        );

        let t_picc = k_mac.cmac_bytes(&[0, 1, 2, 3]);

        println!("t_picc: {}", HexDisplay(t_picc.as_ref()));

        assert_eq!(
            t_picc,
            TachoAuthenticationToken::CS2(hex!("B0 5F E3 81 B6 CF FB 0B F1 A6 AB C5").into())
        );
    }

    #[test]
    pub fn test_cmac_raw_bytes_cs3() {
        let k_mac = TachoSessionKey::CS3(
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ]
            .into(),
        );

        let t_picc = k_mac.cmac_bytes(&[0, 1, 2, 3]);

        println!("t_picc: {}", HexDisplay(t_picc.as_ref()));

        assert_eq!(
            t_picc,
            TachoAuthenticationToken::CS3(
                hex!("AA B3 1C 17 81 5A 86 1E 50 B4 3E 4D FC 56 B0 AA").into()
            )
        );
    }

    #[test]
    pub fn test_cmac_cs1() {
        let domain = TachoCurveDomain::NistSecp256r1;

        // if false {
        //     use rand::thread_rng;

        //     let vu_pk_eph = TachoSecretKey::random(domain, &mut thread_rng());

        //     println!(
        //         "generated vu_pk_eph: {}",
        //         HexDisplay(&vu_pk_eph.public_key().to_sec1_bytes())
        //     );
        // }

        let k_mac =
            TachoSessionKey::CS1([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15].into());

        let sec1_vu_pk_eph = hex!("
            04
            88 C6 9C 8E 35 34 F4 40 03 1B F7 3A E0 75 07 08 22 32 48 5C 0A 20 3A 56 21 1B 77 61 9B 4F B4 C0 
            94 C5 C6 B7 59 AE 38 B5 32 75 AE 9C 65 7A 78 84 CA FE C6 DD 6D FE 0B F5 38 C3 21 14 30 0E 26 EC
        ");

        let vu_pk_eph =
            TachoPublicKey::from_sec1_bytes(domain, &sec1_vu_pk_eph).expect("public key to parse");
        let t_picc = k_mac.cmac(&vu_pk_eph);

        println!("t_picc: {}", HexDisplay(t_picc.as_ref()));

        assert_eq!(
            t_picc,
            TachoAuthenticationToken::CS1(hex!("45 3F 0E 10 B7 DE 6C 67").into())
        );
    }

    #[test]
    pub fn test_cmac_cs2() {
        let domain = TachoCurveDomain::NistSecp384r1;

        // if false {
        //     use rand::thread_rng;

        //     let vu_pk_eph = TachoSecretKey::random(domain, &mut thread_rng());

        //     println!(
        //         "generated vu_pk_eph: {}",
        //         HexDisplay(&vu_pk_eph.public_key().to_sec1_bytes())
        //     );
        // }

        let k_mac = TachoSessionKey::CS2(
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, //
                12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            ]
            .into(),
        );

        let sec1_vu_pk_eph = hex!("
            04
            70 E5 71 44 99 54 41 7B 71 F4 80 2E AD 31 81 C0 0E 2E C5 F4 AC 73 BA A4 38 D1 A1 F4 F5 C2 5F E8 7C 1A 50 D5 68 3E 54 B5 88 52 F6 11 01 38 77 79
            1A 36 85 09 BF 21 F7 B9 8C 71 7E 3A C5 E2 36 7D CF C6 17 C1 DA C3 8F C4 3B AF 47 E4 96 BE BE 39 DD 24 67 86 EC F5 9D A1 2C A5 11 7B 7C E9 47 55
        ");

        let vu_pk_eph =
            TachoPublicKey::from_sec1_bytes(domain, &sec1_vu_pk_eph).expect("public key to parse");
        let t_picc = k_mac.cmac(&vu_pk_eph);

        println!("t_picc: {}", HexDisplay(t_picc.as_ref()));

        assert_eq!(
            t_picc,
            TachoAuthenticationToken::CS2(hex!("DA 5A 28 1C 1F A7 E2 C4 D9 38 62 68").into())
        );
    }

    #[test]
    pub fn test_cmac_cs3() {
        let domain = TachoCurveDomain::NistSecp521r1;

        // if true {
        //     use rand::thread_rng;

        //     let vu_pk_eph = TachoSecretKey::random(domain, &mut thread_rng());

        //     println!(
        //         "generated vu_pk_eph: {}",
        //         HexDisplay(&vu_pk_eph.public_key().to_sec1_bytes())
        //     );
        // }

        let k_mac = TachoSessionKey::CS3(
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ]
            .into(),
        );

        let sec1_vu_pk_eph = hex!("
            04
            00 84 7A B5 E8 45 A7 FC AF BA 30 97 23 5E 42 02 6E 75 5F E5 EF 5A 6F DA 32 70 54 2C BB 5E ED D6 F2 96 92 EF 48 4D A1 33 D0 B7 F4 76 B2 59 40 66 1C 5D BD 80 D4 8B 8E 7D B6 CB 35 6D 0B 4A 77 F1 0F 5D 
            00 1E C3 31 8E FE 81 38 3E DC E8 B4 71 D9 A0 1E 16 22 8A 00 C2 2A 95 CF FB 21 83 7C 35 55 11 71 FE 5F C5 F5 44 88 0F 28 7F 80 3F A8 79 AA 9B 83 2C 0C 6C E1 9B 79 83 73 7E 9B 24 54 62 B6 1A E0 E9 F5
        ");

        let vu_pk_eph =
            TachoPublicKey::from_sec1_bytes(domain, &sec1_vu_pk_eph).expect("public key to parse");
        let t_picc = k_mac.cmac(&vu_pk_eph);

        println!("t_picc: {}", HexDisplay(t_picc.as_ref()));

        assert_eq!(
            t_picc,
            TachoAuthenticationToken::CS3(
                hex!("23 2C B3 25 24 F4 B8 15 F4 0F 12 4C E4 7C 84 8B").into()
            )
        );
    }
}
