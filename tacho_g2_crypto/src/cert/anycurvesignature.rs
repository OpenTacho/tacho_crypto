use std::{
    fmt::{Debug, Display},
    ops::Deref,
};

use crate::ec::signature::{SignatureLengthError, TachoSignatureBytes};

use super::{g2cert::TachoCurveDomain, hexslice::HexDisplay};

/// Signature, without known C.DP (Domain Parameters)
///
/// Certificate can be signed by another certificate,
/// therefore we don't know which curve was used.
#[derive(Clone, Eq, PartialEq)]
pub struct AnyCurveSignature {
    /// 64, 96, 128 or 132 bytes
    pub signature: heapless::Vec<u8, 132>,
}
impl AnyCurveSignature {
    /// Checks if signature length is valid for given curve domain parameters
    pub fn with_domain(
        &self,
        domain: TachoCurveDomain,
    ) -> Result<TachoSignatureBytes, SignatureLengthError> {
        TachoSignatureBytes::from_slice(domain, &self.signature)
    }
}

impl Debug for AnyCurveSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&HexDisplay(&self.signature), f)
    }
}

impl From<&[u8]> for AnyCurveSignature {
    fn from(signature: &[u8]) -> Self {
        Self {
            signature: heapless::Vec::from_slice(signature)
                .expect("signature slice to be max 132 bytes"),
        }
    }
}

impl From<heapless::Vec<u8, 132>> for AnyCurveSignature {
    fn from(signature: heapless::Vec<u8, 132>) -> Self {
        Self { signature }
    }
}

impl Deref for AnyCurveSignature {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.signature
    }
}
