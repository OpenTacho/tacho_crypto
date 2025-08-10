use enum_kinds::EnumKind;
use strum::{AsRefStr, EnumIter, EnumString, VariantNames};

pub mod ids;

#[derive(Debug, Clone, Eq, PartialEq, Default, EnumKind)]
#[enum_kind(
    AuthorityIdentificationKind,
    derive(AsRefStr, EnumString, VariantNames, EnumIter)
)]
pub enum AuthorityIdentification {
    #[default]
    NoInfo,
    EuropeanCommunity,
    RestofEurope,
    RestoftheWorld,

    Utopia,
    Arcadia,

    Albania,
    Andorra,
    Armenia,
    Austria,
    Azerbaijan,
    Belarus,
    Belgium,
    BosniaHerzegovina,
    Bulgaria,
    Croatia,
    Cyprus,
    CzechRepublic,
    Denmark,
    Estonia,
    FaroeIslands,
    Finland,
    France,
    Georgia,
    Germany,
    Greece,
    Hungary,
    Iceland,
    Ireland,
    Italy,
    Kazakhstan,
    KyrgyzRepublic,
    Latvia,
    Liechtenstein,
    Lithuania,
    Luxembourg,
    Malta,
    Moldova,
    Monaco,
    Montenegro,
    Netherlands,
    NorthMacedonia,
    Norway,
    Poland,
    Portugal,
    Romania,
    Russia,
    SanMarino,
    Serbia,
    Slovakia,
    Slovenia,
    Spain,
    Sweden,
    Switzerland,
    Tajikistan,
    Turkiye,
    Turkmenistan,
    Ukraine,
    UnitedKingdom,
    Uzbekistan,
    VaticanCity,
    Yugoslavia,

    Unknown([u8; 4]),
}

impl From<[u8; 4]> for AuthorityIdentification {
    fn from(value: [u8; 4]) -> Self {
        Self::from_bytes(value)
    }
}
impl AuthorityIdentification {
    pub const fn from_bytes(value: [u8; 4]) -> Self {
        match value {
            ids::EUROPEAN_COMMUNITY_ID => Self::EuropeanCommunity,

            ids::NO_INFO_ID => Self::NoInfo,

            ids::COUNTRY_UTOPIA_ID => Self::Utopia,
            ids::COUNTRY_ARCADIA_ID => Self::Arcadia,

            ids::ALBANIA_ID => Self::Albania,
            ids::ANDORRA_ID => Self::Andorra,
            ids::ARMENIA_ID => Self::Armenia,
            ids::AUSTRIA_ID => Self::Austria,
            ids::AZERBAIJAN_ID => Self::Azerbaijan,
            ids::BELARUS_ID => Self::Belarus,
            ids::BELGIUM_ID => Self::Belgium,
            ids::BOSNIA_HERZEGOVINA_ID => Self::BosniaHerzegovina,
            ids::BULGARIA_ID => Self::Bulgaria,
            ids::CROATIA_ID => Self::Croatia,
            ids::CYPRUS_ID => Self::Cyprus,
            ids::CZECH_REPUBLIC_ID => Self::CzechRepublic,
            ids::DENMARK_ID => Self::Denmark,
            ids::ESTONIA_ID => Self::Estonia,
            ids::FAROE_ISLANDS_ID => Self::FaroeIslands,
            ids::FINLAND_ID => Self::Finland,
            ids::FRANCE_ID => Self::France,
            ids::GEORGIA_ID => Self::Georgia,
            ids::GERMANY_ID => Self::Germany,
            ids::GREECE_ID => Self::Greece,
            ids::HUNGARY_ID => Self::Hungary,
            ids::ICELAND_ID => Self::Iceland,
            ids::IRELAND_ID => Self::Ireland,
            ids::ITALY_ID => Self::Italy,
            ids::KAZAKHSTAN_ID => Self::Kazakhstan,
            ids::KYRGYZ_REPUBLIC_ID => Self::KyrgyzRepublic,
            ids::LATVIA_ID => Self::Latvia,
            ids::LIECHTENSTEIN_ID => Self::Liechtenstein,
            ids::LITHUANIA_ID => Self::Lithuania,
            ids::LUXEMBOURG_ID => Self::Luxembourg,
            ids::MALTA_ID => Self::Malta,
            ids::MOLDOVA_ID => Self::Moldova,
            ids::MONACO_ID => Self::Monaco,
            ids::MONTENEGRO_ID => Self::Montenegro,
            ids::NETHERLANDS_ID => Self::Netherlands,
            ids::NORTH_MACEDONIA_ID => Self::NorthMacedonia,
            ids::NORWAY_ID => Self::Norway,
            ids::POLAND_ID => Self::Poland,
            ids::PORTUGAL_ID => Self::Portugal,
            ids::ROMANIA_ID => Self::Romania,
            ids::RUSSIA_ID => Self::Russia,
            ids::SAN_MARINO_ID => Self::SanMarino,
            ids::SERBIA_ID => Self::Serbia,
            ids::SLOVAKIA_ID => Self::Slovakia,
            ids::SLOVENIA_ID => Self::Slovenia,
            ids::SPAIN_ID => Self::Spain,
            ids::SWEDEN_ID => Self::Sweden,
            ids::SWITZERLAND_ID => Self::Switzerland,
            ids::TAJIKISTAN_ID => Self::Tajikistan,
            ids::TURKIYE_ID => Self::Turkiye,
            ids::TURKMENISTAN_ID => Self::Turkmenistan,
            ids::UKRAINE_ID => Self::Ukraine,
            ids::UNITED_KINGDOM_ID => Self::UnitedKingdom,
            ids::UZBEKISTAN_ID => Self::Uzbekistan,
            ids::VATICAN_CITY_ID => Self::VaticanCity,
            ids::YUGOSLAVIA_ID => Self::Yugoslavia,
            ids::REST_OF_EUROPE_ID => Self::RestofEurope,
            ids::REST_OF_THE_WORLD_ID => Self::RestoftheWorld,

            other => Self::Unknown(other),
        }
    }
    pub const fn to_bytes(&self) -> [u8; 4] {
        match self {
            Self::EuropeanCommunity => ids::EUROPEAN_COMMUNITY_ID,

            Self::NoInfo => ids::NO_INFO_ID,

            Self::Arcadia => ids::COUNTRY_ARCADIA_ID,
            Self::Utopia => ids::COUNTRY_UTOPIA_ID,

            Self::Albania => ids::ALBANIA_ID,
            Self::Andorra => ids::ANDORRA_ID,
            Self::Armenia => ids::ARMENIA_ID,
            Self::Austria => ids::AUSTRIA_ID,
            Self::Azerbaijan => ids::AZERBAIJAN_ID,
            Self::Belarus => ids::BELARUS_ID,
            Self::Belgium => ids::BELGIUM_ID,
            Self::BosniaHerzegovina => ids::BOSNIA_HERZEGOVINA_ID,
            Self::Bulgaria => ids::BULGARIA_ID,
            Self::Croatia => ids::CROATIA_ID,
            Self::Cyprus => ids::CYPRUS_ID,
            Self::CzechRepublic => ids::CZECH_REPUBLIC_ID,
            Self::Denmark => ids::DENMARK_ID,
            Self::Estonia => ids::ESTONIA_ID,
            Self::FaroeIslands => ids::FAROE_ISLANDS_ID,
            Self::Finland => ids::FINLAND_ID,
            Self::France => ids::FRANCE_ID,
            Self::Georgia => ids::GEORGIA_ID,
            Self::Germany => ids::GERMANY_ID,
            Self::Greece => ids::GREECE_ID,
            Self::Hungary => ids::HUNGARY_ID,
            Self::Iceland => ids::ICELAND_ID,
            Self::Ireland => ids::IRELAND_ID,
            Self::Italy => ids::ITALY_ID,
            Self::Kazakhstan => ids::KAZAKHSTAN_ID,
            Self::KyrgyzRepublic => ids::KYRGYZ_REPUBLIC_ID,
            Self::Latvia => ids::LATVIA_ID,
            Self::Liechtenstein => ids::LIECHTENSTEIN_ID,
            Self::Lithuania => ids::LITHUANIA_ID,
            Self::Luxembourg => ids::LUXEMBOURG_ID,
            Self::Malta => ids::MALTA_ID,
            Self::Moldova => ids::MOLDOVA_ID,
            Self::Monaco => ids::MONACO_ID,
            Self::Montenegro => ids::MONTENEGRO_ID,
            Self::Netherlands => ids::NETHERLANDS_ID,
            Self::NorthMacedonia => ids::NORTH_MACEDONIA_ID,
            Self::Norway => ids::NORWAY_ID,
            Self::Poland => ids::POLAND_ID,
            Self::Portugal => ids::PORTUGAL_ID,
            Self::Romania => ids::ROMANIA_ID,
            Self::Russia => ids::RUSSIA_ID,
            Self::SanMarino => ids::SAN_MARINO_ID,
            Self::Serbia => ids::SERBIA_ID,
            Self::Slovakia => ids::SLOVAKIA_ID,
            Self::Slovenia => ids::SLOVENIA_ID,
            Self::Spain => ids::SPAIN_ID,
            Self::Sweden => ids::SWEDEN_ID,
            Self::Switzerland => ids::SWITZERLAND_ID,
            Self::Tajikistan => ids::TAJIKISTAN_ID,
            Self::Turkiye => ids::TURKIYE_ID,
            Self::Turkmenistan => ids::TURKMENISTAN_ID,
            Self::Ukraine => ids::UKRAINE_ID,
            Self::UnitedKingdom => ids::UNITED_KINGDOM_ID,
            Self::Uzbekistan => ids::UZBEKISTAN_ID,
            Self::VaticanCity => ids::VATICAN_CITY_ID,
            Self::Yugoslavia => ids::YUGOSLAVIA_ID,
            Self::RestofEurope => ids::REST_OF_EUROPE_ID,
            Self::RestoftheWorld => ids::REST_OF_THE_WORLD_ID,
            Self::Unknown(other) => *other,
        }
    }
}

impl From<&AuthorityIdentification> for [u8; 4] {
    fn from(value: &AuthorityIdentification) -> Self {
        value.to_bytes()
    }
}

impl From<AuthorityIdentificationKind> for AuthorityIdentification {
    fn from(kind: AuthorityIdentificationKind) -> Self {
        match kind {
            AuthorityIdentificationKind::NoInfo => AuthorityIdentification::NoInfo,

            AuthorityIdentificationKind::Utopia => AuthorityIdentification::Utopia,
            AuthorityIdentificationKind::Arcadia => AuthorityIdentification::Arcadia,

            AuthorityIdentificationKind::Albania => AuthorityIdentification::Albania,
            AuthorityIdentificationKind::Andorra => AuthorityIdentification::Andorra,
            AuthorityIdentificationKind::Armenia => AuthorityIdentification::Armenia,
            AuthorityIdentificationKind::Austria => AuthorityIdentification::Austria,
            AuthorityIdentificationKind::Azerbaijan => AuthorityIdentification::Azerbaijan,
            AuthorityIdentificationKind::Belarus => AuthorityIdentification::Belarus,
            AuthorityIdentificationKind::Belgium => AuthorityIdentification::Belgium,
            AuthorityIdentificationKind::BosniaHerzegovina => {
                AuthorityIdentification::BosniaHerzegovina
            }
            AuthorityIdentificationKind::Bulgaria => AuthorityIdentification::Bulgaria,
            AuthorityIdentificationKind::Croatia => AuthorityIdentification::Croatia,
            AuthorityIdentificationKind::Cyprus => AuthorityIdentification::Cyprus,
            AuthorityIdentificationKind::CzechRepublic => AuthorityIdentification::CzechRepublic,
            AuthorityIdentificationKind::Denmark => AuthorityIdentification::Denmark,
            AuthorityIdentificationKind::Estonia => AuthorityIdentification::Estonia,
            AuthorityIdentificationKind::FaroeIslands => AuthorityIdentification::FaroeIslands,
            AuthorityIdentificationKind::Finland => AuthorityIdentification::Finland,
            AuthorityIdentificationKind::France => AuthorityIdentification::France,
            AuthorityIdentificationKind::Georgia => AuthorityIdentification::Georgia,
            AuthorityIdentificationKind::Germany => AuthorityIdentification::Germany,
            AuthorityIdentificationKind::Greece => AuthorityIdentification::Greece,
            AuthorityIdentificationKind::Hungary => AuthorityIdentification::Hungary,
            AuthorityIdentificationKind::Iceland => AuthorityIdentification::Iceland,
            AuthorityIdentificationKind::Ireland => AuthorityIdentification::Ireland,
            AuthorityIdentificationKind::Italy => AuthorityIdentification::Italy,
            AuthorityIdentificationKind::Kazakhstan => AuthorityIdentification::Kazakhstan,
            AuthorityIdentificationKind::KyrgyzRepublic => AuthorityIdentification::KyrgyzRepublic,
            AuthorityIdentificationKind::Latvia => AuthorityIdentification::Latvia,
            AuthorityIdentificationKind::Liechtenstein => AuthorityIdentification::Liechtenstein,
            AuthorityIdentificationKind::Lithuania => AuthorityIdentification::Lithuania,
            AuthorityIdentificationKind::Luxembourg => AuthorityIdentification::Luxembourg,
            AuthorityIdentificationKind::Malta => AuthorityIdentification::Malta,
            AuthorityIdentificationKind::Moldova => AuthorityIdentification::Moldova,
            AuthorityIdentificationKind::Monaco => AuthorityIdentification::Monaco,
            AuthorityIdentificationKind::Montenegro => AuthorityIdentification::Montenegro,
            AuthorityIdentificationKind::Netherlands => AuthorityIdentification::Netherlands,
            AuthorityIdentificationKind::NorthMacedonia => AuthorityIdentification::NorthMacedonia,
            AuthorityIdentificationKind::Norway => AuthorityIdentification::Norway,
            AuthorityIdentificationKind::Poland => AuthorityIdentification::Poland,
            AuthorityIdentificationKind::Portugal => AuthorityIdentification::Portugal,
            AuthorityIdentificationKind::Romania => AuthorityIdentification::Romania,
            AuthorityIdentificationKind::Russia => AuthorityIdentification::Russia,
            AuthorityIdentificationKind::SanMarino => AuthorityIdentification::SanMarino,
            AuthorityIdentificationKind::Serbia => AuthorityIdentification::Serbia,
            AuthorityIdentificationKind::Slovakia => AuthorityIdentification::Slovakia,
            AuthorityIdentificationKind::Slovenia => AuthorityIdentification::Slovenia,
            AuthorityIdentificationKind::Spain => AuthorityIdentification::Spain,
            AuthorityIdentificationKind::Sweden => AuthorityIdentification::Sweden,
            AuthorityIdentificationKind::Switzerland => AuthorityIdentification::Switzerland,
            AuthorityIdentificationKind::Tajikistan => AuthorityIdentification::Tajikistan,
            AuthorityIdentificationKind::Turkiye => AuthorityIdentification::Turkiye,
            AuthorityIdentificationKind::Turkmenistan => AuthorityIdentification::Turkmenistan,
            AuthorityIdentificationKind::Ukraine => AuthorityIdentification::Ukraine,
            AuthorityIdentificationKind::UnitedKingdom => AuthorityIdentification::UnitedKingdom,
            AuthorityIdentificationKind::Uzbekistan => AuthorityIdentification::Uzbekistan,
            AuthorityIdentificationKind::VaticanCity => AuthorityIdentification::VaticanCity,
            AuthorityIdentificationKind::Yugoslavia => AuthorityIdentification::Yugoslavia,
            AuthorityIdentificationKind::EuropeanCommunity => {
                AuthorityIdentification::EuropeanCommunity
            }
            AuthorityIdentificationKind::RestofEurope => AuthorityIdentification::RestofEurope,
            AuthorityIdentificationKind::RestoftheWorld => AuthorityIdentification::RestoftheWorld,
            AuthorityIdentificationKind::Unknown => {
                AuthorityIdentification::Unknown([0x20, 0x20, 0x20, 0x20])
            }
        }
    }
}
