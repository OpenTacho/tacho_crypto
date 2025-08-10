use strum::{AsRefStr, EnumIter, EnumString, FromRepr, VariantNames};

#[derive(
    Copy, Debug, Clone, FromRepr, Eq, PartialEq, AsRefStr, EnumString, VariantNames, EnumIter,
)]
pub enum G2EquipmentType {
    Reserved = 0x00,
    DriverCard = 0x01,
    WorkshopCard = 0x02,
    ControlCard = 0x03,
    CompanyCard = 0x04,
    ManufacturingCard = 0x05,
    VehicleUnit = 0x06,
    MotionSensor = 0x07,
    GnssFacility = 0x08,
    RemoteCommunicationMode = 0x09,
    ITSInterfaceMode = 0x0A,
    Plaque = 0x0B,
    M1N1Adapter = 0x0C,

    /// ERCA
    EuropeanRootCA = 0x0D,

    // MSCA
    MemberStateCA = 0x0E,
    ExternalGNSSConnection = 0x0F,
    UnusedSealDataVu = 0x10,

    /// Only to be used in the CHA field of signing cert
    DriverCardSign = 0x11,
    /// Only to be used in the CHA field of signing cert
    WorkshopCardSign = 0x12,
    /// Only to be used in the CHA field of signing cert
    VehicleUnitSign = 0x13,
    // RFU
}

impl G2EquipmentType {
    /// EquipmentType::Reserved is not equipment but a CA
    ///
    /// this function determines if CHR is an Authority or an EquipmentKID
    pub fn is_equipment(&self) -> bool {
        !matches!(
            self,
            G2EquipmentType::Reserved
                | G2EquipmentType::EuropeanRootCA
                | G2EquipmentType::MemberStateCA
        )
    }
}
