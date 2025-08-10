use crate::ensure_eq;

use super::equipmenttype::G2EquipmentType;
use eyre::ensure;
use eyre::eyre;
use std::fmt::Debug;

/// Length 7
///
/// Contains EquipmentType enum
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct G2CertificateHolderAuthorisation {
    pub equipment_type: G2EquipmentType,
}

/// tachographApplicationID  OCTET STRING(SIZE(6))
pub const TACHO_G2_APP_ID: [u8; 6] = [0xFF, 0x53, 0x4D, 0x52, 0x44, 0x54];

impl G2CertificateHolderAuthorisation {
    /// Parses:
    /// - 6 bytes of `tachographApplicationID`
    /// - 1 byte of `equipmentType`
    pub fn parse(cha: [u8; 7]) -> eyre::Result<Self> {
        ensure_eq!(cha.len(), 7);
        ensure!(cha[0..6] == TACHO_G2_APP_ID);

        let raw_eq_type = cha[6] as usize;
        Ok(Self {
            equipment_type: G2EquipmentType::from_repr(raw_eq_type)
                .ok_or_else(|| eyre!("unknown G2EquipmentType: {raw_eq_type}"))?,
        })
    }

    /// Returns:
    /// - 6 bytes of `tachographApplicationID`
    /// - 1 byte of `equipmentType`
    pub fn to_bytes(&self) -> [u8; 7] {
        let mut cha = [0; 7];
        cha[0..6].copy_from_slice(&TACHO_G2_APP_ID);
        cha[6] = self.equipment_type as u8;
        cha
    }
}
