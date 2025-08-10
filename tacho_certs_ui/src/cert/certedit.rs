use crate::{
    edit_widget_kind,
    editctx::TachoEditCtx,
    editwidget::{EditWidget, EditWidgetEdited},
};
use std::fmt::Write;

use der::Encode;
use egui::{CollapsingHeader, DragValue, Id, TextEdit, Ui};
use enum_kinds::EnumKind;
use strum::{AsRefStr, EnumIter, EnumString, VariantNames};
use tacho_cert_common::{
    bcddate::{BCDDate, BCDMonth, BCDYear},
    keyidentifier::{
        KeyIdentifier, KeyIdentifierKind,
        authority::{AuthorityIdentification, AuthorityKID},
        authority_id::AuthorityIdentificationKind,
        equipment::{ExtendedSerialNumber, ManufacturerCode, ManufacturerSpecific},
    },
    timereal::TimeReal,
};
use tacho_g2_crypto::{
    cert::{
        anycurvesignature::AnyCurveSignature,
        equipmenttype::G2EquipmentType,
        g2authorization::G2CertificateHolderAuthorisation,
        g2cert::{CertificatePublicKey, TachographCertificate, TachographCertificateBody},
        g2certraw::{
            CertificatePublicKeyRaw, TachographCertificateBodyRaw, TachographCertificateRaw,
        },
    },
    ec::public_key::TachoPublicKey,
};

#[derive(Clone, Debug, Eq, PartialEq, EnumKind)]
#[enum_kind(
    RawOrParsedCertKind,
    derive(AsRefStr, EnumString, VariantNames, EnumIter)
)]
pub enum RawOrParsedCert {
    Raw(TachographCertificateRaw<'static>),
    Parsed(TachographCertificate),
}

impl From<TachographCertificateRaw<'static>> for RawOrParsedCert {
    fn from(value: TachographCertificateRaw<'static>) -> Self {
        Self::Raw(value)
    }
}
impl From<TachographCertificate> for RawOrParsedCert {
    fn from(value: TachographCertificate) -> Self {
        Self::Parsed(value)
    }
}

// impl From<RawOrParsedCertKind> for RawOrParsedCert {
//     fn from(kind: RawOrParsedCertKind) -> Self {
//         match kind {
//             RawOrParsedCertKind::Raw => RawOrParsedCert::Raw(Default::default()),
//             RawOrParsedCertKind::Parsed => RawOrParsedCert::Parsed(Default::default()),
//         }
//     }
// }

impl EditWidget for RawOrParsedCert {
    fn edit_ui(&mut self, ui: &mut Ui, id: Id, tctx: &mut TachoEditCtx) {
        RawOrParsedCertKind::from(&*self)
            .edited(ui, id, tctx)
            .map(|_new_kind| {
                self.transmute();
            });

        match self {
            RawOrParsedCert::Raw(raw) => raw.edit_ui(ui, id, tctx),
            RawOrParsedCert::Parsed(parsed) => parsed.edit_ui(ui, id, tctx),
        }
    }
}

impl RawOrParsedCert {
    pub fn transmute(&mut self) {
        match self {
            RawOrParsedCert::Raw(raw) => {
                let parsed = TachographCertificate::from_raw(raw);

                if let Ok(parsed) = parsed {
                    *self = RawOrParsedCert::Parsed(parsed);
                }
            }
            RawOrParsedCert::Parsed(parsed) => {
                let builder = parsed.raw_builder();
                let raw = builder.to_raw();

                if let Ok(raw) = raw {
                    *self = RawOrParsedCert::Raw(raw.owned());
                }
            }
        }
    }
}

edit_widget_kind!(RawOrParsedCertKind);
edit_widget_kind!(KeyIdentifierKind);
edit_widget_kind!(AuthorityIdentificationKind);

impl<'a> EditWidget for TachographCertificateRaw<'a> {
    fn edit_ui(&mut self, ui: &mut Ui, id: Id, tctx: &mut TachoEditCtx) {
        CollapsingHeader::new("Body")
            .id_salt(id.with("collapsing"))
            .default_open(true)
            .show(ui, |ui| {
                self.body.edit_ui(ui, id.with("body"), tctx);
            });

        CollapsingHeader::new("Signature")
            .id_salt(id.with("collapsingsig"))
            .default_open(true)
            .show(ui, |ui| {
                self.signature.edit_ui(ui, id.with("signature"), tctx);
            });
    }
}

impl EditWidget for TachographCertificate {
    fn edit_ui(&mut self, ui: &mut Ui, id: Id, tctx: &mut TachoEditCtx) {
        CollapsingHeader::new("Body")
            .id_salt(id.with("collapsingbody"))
            .default_open(true)
            .show(ui, |ui| {
                self.body.edit_ui(ui, id.with("body"), tctx);
            });
        CollapsingHeader::new("Signature")
            .id_salt(id.with("collapsingsig"))
            .default_open(true)
            .show(ui, |ui| {
                self.signature.edit_ui(ui, id.with("signature"), tctx);
            });
    }
}

impl EditWidget for AnyCurveSignature {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        self.signature.as_mut_slice().edit_ui(ui, id, tctx);
    }
}

impl EditWidget for TachographCertificateBody {
    fn edit_ui(&mut self, ui: &mut Ui, id: Id, tctx: &mut TachoEditCtx) {
        ui.horizontal(|ui| {
            ui.label("CPI");
            ui.label("v1");
        });

        ui.horizontal(|ui| {
            ui.label("CAR");
            self.authority_reference.edit_ui(ui, id.with("CAR"), tctx);
        });

        ui.horizontal(|ui| {
            ui.label("CHA");
            self.holder_authorisation.edit_ui(ui, id.with("CHA"), tctx);
        });
        ui.horizontal(|ui| {
            ui.label("PK");
            self.public_key.edit_ui(ui, id.with("PK"), tctx);
        });
        ui.horizontal(|ui| {
            ui.label("CHR");
            self.holder_reference.edit_ui(ui, id.with("CHR"), tctx);
        });

        ui.horizontal(|ui| {
            ui.label("EfD");
            self.effective_date.edit_ui(ui, id.with("EfD"), tctx);
        });

        ui.horizontal(|ui| {
            ui.label("ExD");
            self.expiration_date.edit_ui(ui, id.with("ExD"), tctx);
        });
    }
}

impl EditWidget for AuthorityIdentification {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        ui.horizontal(|ui| {
            ui.label("nation")
                .on_hover_text("nationNumeric + nationAlpha");
            AuthorityIdentificationKind::from(&*self)
                .edited(ui, id, tctx)
                .map(|new_kind| {
                    *self = AuthorityIdentification::from(new_kind);
                });
        });
    }
}

impl EditWidget for AuthorityKID {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        ui.group(|ui| {
            ui.vertical(|ui| {
                ui.label("AuthorityKID");
                self.identification.edit_ui(ui, id, tctx);
                ui.horizontal(|ui| {
                    ui.label("keySerialNumber");
                    self.serial.edit_ui(ui, id, tctx);
                });
                ui.horizontal(|ui| {
                    ui.label("additionalInfo:");
                    self.additional_info.as_mut_slice().edit_ui(ui, id, tctx);
                });
                ui.label("caIdentifier: 01");
            });
        });
    }
}

impl EditWidget for ExtendedSerialNumber {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        ui.group(|ui| {
            ui.vertical(|ui| {
                ui.label("ExtendedSerialNumber");

                self.serial.as_mut_slice().edit_ui(ui, id, tctx);
                self.date.edit_ui(ui, id, tctx);
                self.typ.edit_ui(ui, id, tctx);
                self.manufacturer.edit_ui(ui, id, tctx);
            });
        });
    }
}
impl EditWidget for BCDDate {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        self.month.edit_ui(ui, id, tctx);
        self.year.edit_ui(ui, id, tctx);
    }
}

impl EditWidget for BCDMonth {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        ui.horizontal(|ui| {
            let buf = tctx.string_buf();
            let _ = write!(buf, "BCDMonth: {:02X}", self.0);
            ui.label(buf.as_str());
        });
    }
}
impl EditWidget for BCDYear {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        ui.horizontal(|ui| {
            let buf = tctx.string_buf();
            let _ = write!(buf, "BCDYear: {:02X}", self.0);
            ui.label(buf.as_str());
        });
    }
}

impl EditWidget for ManufacturerCode {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        ui.horizontal(|ui| {
            let buf = tctx.string_buf();
            let _ = write!(buf, "ManufacturerCode: {:02X}", self.0);
            ui.label(buf.as_str());
        });
    }
}
impl EditWidget for ManufacturerSpecific {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        ui.horizontal(|ui| {
            let buf = tctx.string_buf();
            let _ = write!(buf, "ManufacturerSpecific: {:02X}", self.0);
            ui.label(buf.as_str());
        });
    }
}

impl EditWidget for KeyIdentifier {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        ui.group(|ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label("KeyIdentifier: ");
                    KeyIdentifierKind::from(&*self)
                        .edited(ui, id, tctx)
                        .map(|new_kind| match new_kind {
                            KeyIdentifierKind::Equipment => {
                                *self = KeyIdentifier::Equipment(ExtendedSerialNumber::default())
                            }
                            KeyIdentifierKind::Authority => {
                                *self = KeyIdentifier::Authority(AuthorityKID::default())
                            }
                        });
                });

                match self {
                    KeyIdentifier::Equipment(serial) => serial.edit_ui(ui, id, tctx),
                    KeyIdentifier::Authority(authority) => authority.edit_ui(ui, id, tctx),
                }
            });
        });
    }
}

impl EditWidget for G2CertificateHolderAuthorisation {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        self.equipment_type.edit_ui(ui, id, tctx)
    }
}

impl EditWidget for CertificatePublicKey {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        CollapsingHeader::new("PublicKey")
            .id_salt(id.with("collpk"))
            .default_open(true)
            .show(ui, |ui| {
                self.public_point.edit_ui(ui, id, tctx);
            });
    }
}

edit_widget_kind!(G2EquipmentType);

impl EditWidget for TimeReal {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        let buf = tctx.string_buf();
        let _ = write!(buf, "TimeReal: {}", self.timestamp);
        ui.label(buf.as_str());
    }
}

impl EditWidget for TachoPublicKey {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        let buf = tctx.string_buf();
        let _ = write!(buf, "TachoPublicKey: {:?}", self.domain());
        ui.label(buf.as_str());
        let encoded = self.to_encoded_point(false);

        encoded.as_bytes().edit_ui(ui, id, tctx);
    }
}

impl<'a> EditWidget for TachographCertificateBodyRaw<'a> {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        ui.horizontal(|ui| {
            ui.label("CPI");
            self.profile_identifier
                .as_mut_slice()
                .edit_ui(ui, id.with("profile_identifier"), tctx);
        });

        ui.horizontal(|ui| {
            ui.label("CAR");
            self.authority_reference
                .as_mut_slice()
                .edit_ui(ui, id.with("CAR"), tctx);
        });

        ui.horizontal(|ui| {
            ui.label("CHA");
            self.holder_authorisation
                .as_mut_slice()
                .edit_ui(ui, id.with("CHA"), tctx);
        });
        ui.horizontal(|ui| {
            ui.label("PK");
            self.public_key.edit_ui(ui, id.with("PK"), tctx);
        });
        ui.horizontal(|ui| {
            ui.label("CHR");
            self.holder_reference
                .as_mut_slice()
                .edit_ui(ui, id.with("CHR"), tctx);
        });
        ui.horizontal(|ui| {
            ui.label("EfD");
            self.effective_date
                .as_mut_slice()
                .edit_ui(ui, id.with("EfD"), tctx);
        });

        ui.horizontal(|ui| {
            ui.label("ExD");
            self.expiration_date
                .as_mut_slice()
                .edit_ui(ui, id.with("ExD"), tctx);
        });
    }
}

impl<'a> EditWidget for CertificatePublicKeyRaw<'a> {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        CollapsingHeader::new("PublicKey")
            .id_salt(id.with("collpk"))
            .default_open(true)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("DP").on_hover_text({
                        let buf = tctx.string_buf();
                        let _ = write!(buf, "{}", self.domain_parameters);
                        buf.as_str()
                    });
                    let mut domain_bytes = self.domain_parameters.as_bytes();
                    domain_bytes.edit_ui(ui, id, tctx);
                });
                ui.horizontal(|ui| {
                    ui.label("PP")
                        .on_hover_text("byte '04' prefix means it's uncompressed point");

                    let mut public_point: &[u8] = self.public_point.as_ref();
                    public_point.edit_ui(ui, id, tctx);
                });
            });
    }
}
