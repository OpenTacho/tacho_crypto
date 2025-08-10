use std::error::Error;

use crate::cert::g2cert::TachoCurveDomain;

/// ECDSA signature bytes (point)
///
/// use `.as_ref()` to get bytes
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TachoSignatureBytes {
    /// Nist
    P256(ecdsa::SignatureBytes<p256::NistP256>),

    /// Nist
    P384(ecdsa::SignatureBytes<p384::NistP384>),

    /// Nist
    P521([u8; 132]),

    /// Brainpool
    BP256([u8; 64]),

    /// Brainpool
    BP384([u8; 96]),

    /// Brainpool
    BP512([u8; 128]),
}

impl TachoSignatureBytes {
    pub fn from_slice(
        domain: TachoCurveDomain,
        slice: &[u8],
    ) -> Result<Self, SignatureLengthError> {
        match domain {
            TachoCurveDomain::NistSecp256r1 => {
                let sig_array: [u8; 64] = slice
                    .try_into()
                    .map_err(|_| SignatureLengthError::P256(slice.len()))?;

                Ok(Self::P256(sig_array.into()))
            }
            TachoCurveDomain::NistSecp384r1 => {
                let sig_array: [u8; 96] = slice
                    .try_into()
                    .map_err(|_| SignatureLengthError::P384(slice.len()))?;

                //let sig_bytes = ecdsa::SignatureBytes::<p384::NistP384>::try_from(sig_array);
                Ok(Self::P384(sig_array.into()))
            }
            TachoCurveDomain::NistSecp521r1 => {
                let sig_array = slice
                    .try_into()
                    .map_err(|_| SignatureLengthError::P521(slice.len()))?;
                Ok(Self::P521(sig_array))
            }
            TachoCurveDomain::BrainpoolP256r1 => {
                let sig_array = slice
                    .try_into()
                    .map_err(|_| SignatureLengthError::BP256(slice.len()))?;
                Ok(Self::BP256(sig_array))
            }
            TachoCurveDomain::BrainpoolP384r1 => {
                let sig_array = slice
                    .try_into()
                    .map_err(|_| SignatureLengthError::BP384(slice.len()))?;
                Ok(Self::BP384(sig_array))
            }
            TachoCurveDomain::BrainpoolP512r1 => {
                let sig_array = slice
                    .try_into()
                    .map_err(|_| SignatureLengthError::BP512(slice.len()))?;
                Ok(Self::BP512(sig_array))
            }
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            Self::P256(sig) => sig.len(),
            Self::P384(sig) => sig.len(),
            Self::P521(sig) => sig.len(),
            Self::BP256(sig) => sig.len(),
            Self::BP384(sig) => sig.len(),
            Self::BP512(sig) => sig.len(),
        }
    }
}

impl AsRef<[u8]> for TachoSignatureBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::P256(sig) => sig,
            Self::P384(sig) => sig,
            Self::P521(sig) => sig,
            Self::BP256(sig) => sig,
            Self::BP384(sig) => sig,
            Self::BP512(sig) => sig,
        }
    }
}

#[derive(Debug)]
pub enum SignatureLengthError {
    P256(usize),
    P384(usize),
    P521(usize),
    BP256(usize),
    BP384(usize),
    BP512(usize),
}
impl Error for SignatureLengthError {}

impl std::fmt::Display for SignatureLengthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (msg, invalid_len) = match self {
            SignatureLengthError::P256(invalid_len) => (
                "SignatureLengthError::P256: expected 64 bytes, but was: ",
                invalid_len,
            ),
            SignatureLengthError::P384(invalid_len) => (
                "SignatureLengthError::P384: expected 96 bytes, but was: ",
                invalid_len,
            ),
            SignatureLengthError::P521(invalid_len) => (
                "SignatureLengthError::P521: expected 132 bytes, but was: ",
                invalid_len,
            ),
            SignatureLengthError::BP256(invalid_len) => (
                "SignatureLengthError::P256: expected 64 bytes, but was: ",
                invalid_len,
            ),
            SignatureLengthError::BP384(invalid_len) => (
                "SignatureLengthError::P256: expected 96 bytes, but was: ",
                invalid_len,
            ),
            SignatureLengthError::BP512(invalid_len) => (
                "SignatureLengthError::P256: expected 128 bytes, but was: ",
                invalid_len,
            ),
        };
        write!(f, "{msg}{invalid_len}")
    }
}
