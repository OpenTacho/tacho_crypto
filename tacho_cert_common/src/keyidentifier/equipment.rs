use crate::bcddate::{BCDDate, BCDMonth, BCDYear};
use iso9796_rsa::hexslice::HexDisplay;
use std::fmt::Debug;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ManufacturerSpecific(pub u8);

impl Default for ManufacturerSpecific {
    fn default() -> Self {
        Self(Default::default())
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ManufacturerCode(pub u8);

impl Default for ManufacturerCode {
    fn default() -> Self {
        Self(Default::default())
    }
}

/// 5.1 Equipment (VU or Card)
///
/// ExtendedSerialNumber
#[derive(Eq, PartialEq, Clone, Default)]
pub struct ExtendedSerialNumber {
    /// serialNumber
    pub serial: [u8; 4],

    /// monthYear
    pub date: BCDDate,

    // type
    pub typ: ManufacturerSpecific,

    /// manufacturerCode
    pub manufacturer: ManufacturerCode,
}
impl Debug for ExtendedSerialNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedSerialNumber")
            .field("serial", &HexDisplay(&self.serial))
            .field("date", &self.date)
            .field("typ", &HexDisplay(&[self.typ.0]))
            .field("manufacturer", &HexDisplay(&[self.manufacturer.0]))
            .finish()
    }
}
impl ExtendedSerialNumber {
    pub const fn from_bytes(b: [u8; 8]) -> Self {
        Self {
            serial: [b[0], b[1], b[2], b[3]],
            date: BCDDate {
                month: BCDMonth(b[4]),
                year: BCDYear(b[5]),
            },
            typ: ManufacturerSpecific(b[6]),
            manufacturer: ManufacturerCode(b[7]),
        }
    }
    pub const fn to_bytes(&self) -> [u8; 8] {
        let mut kid = [0; 8];
        kid[0] = self.serial[0];
        kid[1] = self.serial[1];
        kid[2] = self.serial[2];
        kid[3] = self.serial[3];
        kid[4] = self.date.month.0;
        kid[5] = self.date.year.0;
        kid[6] = self.typ.0;
        kid[7] = self.manufacturer.0;
        kid
    }
}
