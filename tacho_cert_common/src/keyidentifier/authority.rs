use eyre::ensure;
use iso9796_rsa::hexslice::HexDisplay;
use std::fmt::Debug;

pub use super::authority_id::AuthorityIdentification;

/// 5.2 Certification Authority
#[derive(Eq, PartialEq, Clone)]
pub struct AuthorityKID {
    /// Authority Identification
    pub identification: AuthorityIdentification,

    /// Key serial number
    pub serial: u8,

    /// additional coding (CA specific)
    /// 'FF FF' if not used
    pub additional_info: [u8; 2],
}

impl Default for AuthorityKID {
    fn default() -> Self {
        Self {
            identification: Default::default(),
            serial: Default::default(),
            additional_info: Default::default(),
        }
    }
}

impl AuthorityKID {
    /// Returns error only if identifier is not 0x01
    pub fn from_bytes(b: [u8; 8]) -> eyre::Result<Self> {
        let identifier = b[7];
        ensure!(identifier == 0x01);

        let identification = [b[0], b[1], b[2], b[3]];
        Ok(Self {
            identification: AuthorityIdentification::from_bytes(identification),
            serial: b[4],
            additional_info: [b[5], b[6]],
        })
    }
    pub const fn to_bytes(&self) -> [u8; 8] {
        let identification = self.identification.to_bytes();
        let mut kid = [0; 8];
        kid[0] = identification[0];
        kid[1] = identification[1];
        kid[2] = identification[2];
        kid[3] = identification[3];
        kid[4] = self.serial;
        kid[5] = self.additional_info[0];
        kid[6] = self.additional_info[1];
        kid[7] = 0x01;
        kid
    }
}

impl Debug for AuthorityKID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorityKID")
            .field("identification", &self.identification)
            .field("serial", &HexDisplay(&[self.serial]))
            .field("additional_info", &HexDisplay(&self.additional_info))
            .finish()
    }
}
