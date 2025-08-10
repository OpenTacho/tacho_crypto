pub mod authority;
pub mod authority_id;
pub mod equipment;

use authority::AuthorityKID;
use enum_kinds::EnumKind;
use equipment::ExtendedSerialNumber;
use strum::{AsRefStr, EnumIter, EnumString, VariantNames};

use std::fmt::Debug;

/// Key Identifiers uniquely identify certificate holder or certification
/// authorities.
#[derive(Eq, PartialEq, Clone, Debug, EnumKind)]
#[enum_kind(
    KeyIdentifierKind,
    derive(AsRefStr, EnumString, VariantNames, EnumIter)
)]
pub enum KeyIdentifier {
    /// 5.1 Equipment (VU or Card)
    ///
    /// ExtendedSerialNumber
    Equipment(ExtendedSerialNumber),

    /// 5.2 Certification Authority
    Authority(AuthorityKID),
}

impl KeyIdentifier {
    pub fn from_bytes(b: [u8; 8], is_equipment: bool) -> eyre::Result<Self> {
        if is_equipment {
            Ok(Self::Equipment(ExtendedSerialNumber::from_bytes(b)))
        } else {
            Ok(Self::Authority(AuthorityKID::from_bytes(b)?))
        }
    }
    pub fn to_bytes(&self) -> [u8; 8] {
        match self {
            KeyIdentifier::Equipment(kid) => kid.to_bytes(),
            KeyIdentifier::Authority(car) => car.to_bytes(),
        }
    }

    pub fn as_authority(&self) -> Option<&AuthorityKID> {
        match self {
            KeyIdentifier::Equipment(_) => None,
            KeyIdentifier::Authority(authority_kid) => Some(authority_kid),
        }
    }
}
