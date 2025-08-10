use std::{error::Error, fmt::Display};

/// Auth token
///
/// T_PICC
///
/// Result of CMAC(K MAC , VU.PK eph )
///
/// 8, 12 or 16 bytes
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TachoAuthenticationToken {
    /// CS#1
    ///
    /// ECC key size (bits): 256
    ///
    /// AES key length (bits): 128 = 16 bytes
    ///
    /// Hashing algorithm: SHA-256
    ///
    /// MAC length (bytes): 8
    CS1(Cs1AuthToken),

    /// CS#2
    ///
    /// ECC key size (bits): 384
    ///
    /// AES key length (bits): 192 = 24 bytes
    ///
    /// Hashing algorithm: SHA-384
    ///
    /// MAC length (bytes): 12
    CS2(Cs2AuthToken),

    /// CS#3
    ///
    /// ECC key size (bits): 512/521
    ///
    /// AES key length (bits): 256 = 32 bytes
    ///
    /// Hashing algorithm: SHA-512
    ///
    /// MAC length (bytes): 16
    CS3(Cs3AuthToken),
}

/// 8 bytes
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cs1AuthToken(pub [u8; 8]);

/// 12 bytes
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cs2AuthToken(pub [u8; 12]);

/// 16 bytes
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cs3AuthToken(pub [u8; 16]);

impl From<Cs1AuthToken> for TachoAuthenticationToken {
    fn from(value: Cs1AuthToken) -> Self {
        TachoAuthenticationToken::CS1(value)
    }
}
impl From<Cs2AuthToken> for TachoAuthenticationToken {
    fn from(value: Cs2AuthToken) -> Self {
        TachoAuthenticationToken::CS2(value)
    }
}
impl From<Cs3AuthToken> for TachoAuthenticationToken {
    fn from(value: Cs3AuthToken) -> Self {
        TachoAuthenticationToken::CS3(value)
    }
}

impl From<[u8; 8]> for Cs1AuthToken {
    fn from(value: [u8; 8]) -> Self {
        Self(value)
    }
}

impl From<[u8; 12]> for Cs2AuthToken {
    fn from(value: [u8; 12]) -> Self {
        Self(value)
    }
}
impl From<[u8; 16]> for Cs3AuthToken {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for TachoAuthenticationToken {
    fn as_ref(&self) -> &[u8] {
        match self {
            TachoAuthenticationToken::CS1(t_picc) => t_picc.0.as_slice(),
            TachoAuthenticationToken::CS2(t_picc) => t_picc.0.as_slice(),
            TachoAuthenticationToken::CS3(t_picc) => t_picc.0.as_slice(),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct InvalidLengthOfAuthTokenError(pub u32);

impl Display for InvalidLengthOfAuthTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InvalidLengthOfAuthTokenError: {}", self.0)
    }
}

impl Error for InvalidLengthOfAuthTokenError {}

impl TryFrom<&[u8]> for TachoAuthenticationToken {
    type Error = InvalidLengthOfAuthTokenError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.len() {
            8 => Ok(Self::CS1(Cs1AuthToken(value.try_into().unwrap()))),
            12 => Ok(Self::CS2(Cs2AuthToken(value.try_into().unwrap()))),
            16 => Ok(Self::CS3(Cs3AuthToken(value.try_into().unwrap()))),
            invalid_len => Err(InvalidLengthOfAuthTokenError(invalid_len as u32)),
        }
    }
}

pub trait AuthTokenFromCmac {
    fn cut_from_cmac(t_picc_material: &[u8]) -> Option<Self>
    where
        Self: Sized;

    fn to_enum(self) -> TachoAuthenticationToken;
}

impl AuthTokenFromCmac for Cs1AuthToken {
    /// Cuts CMAC to 8 bytes length
    ///
    /// Returns None if CMAC is smaller than target key size
    fn cut_from_cmac(t_picc_material: &[u8]) -> Option<Self> {
        let mut key = Self::default();
        let len = key.0.len();
        key.0.copy_from_slice(t_picc_material.get(..len)?);
        Some(key)
    }

    fn to_enum(self) -> TachoAuthenticationToken {
        TachoAuthenticationToken::CS1(self)
    }
}

impl AuthTokenFromCmac for Cs2AuthToken {
    /// Cuts CMAC to 12 bytes length
    ///
    /// Returns None if CMAC is smaller than target key size
    fn cut_from_cmac(t_picc_material: &[u8]) -> Option<Self> {
        let mut key = Self::default();
        let len = key.0.len();
        key.0.copy_from_slice(t_picc_material.get(..len)?);
        Some(key)
    }

    fn to_enum(self) -> TachoAuthenticationToken {
        TachoAuthenticationToken::CS2(self)
    }
}

impl AuthTokenFromCmac for Cs3AuthToken {
    /// Cuts CMAC to 16 bytes length
    ///
    /// Returns None if CMAC is smaller than target key size
    fn cut_from_cmac(t_picc_material: &[u8]) -> Option<Self> {
        let mut key = Self::default();
        let len = key.0.len();
        key.0.copy_from_slice(t_picc_material.get(..len)?);
        Some(key)
    }

    fn to_enum(self) -> TachoAuthenticationToken {
        TachoAuthenticationToken::CS3(self)
    }
}

#[cfg(test)]
pub mod test {
    use crate::auth::auth_token::{AuthTokenFromCmac, Cs2AuthToken};

    use hex_literal::hex;

    #[test]
    fn test_cutting_cs2() {
        let t_picc_material = &[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, //
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let t_picc = Cs2AuthToken::cut_from_cmac(t_picc_material).unwrap();

        assert_eq!(
            t_picc,
            Cs2AuthToken(hex!("00 01 02 03 04 05 06 07 08 09 0A 0B"))
        );
    }
}
