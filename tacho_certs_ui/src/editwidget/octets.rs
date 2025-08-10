use der::asn1::{self, OctetString};
use egui::Ui;

use crate::{editctx::TachoEditCtx, editwidget::{hex::HexEditState, EditWidget}};


#[derive(Clone)]
pub enum OctetsEditState {
    Hex(HexEditState),
    Utf8String(String),
}

// impl FieldEditor for OctetsEditState {
//     fn is_valid(&self) -> bool {
//         match self {
//             OctetsEditState::Hex(hex) => hex.is_valid(),
//             OctetsEditState::Utf8String(_) => true,
//         }
//     }
//     fn as_any(&self) -> &(dyn std::any::Any) {
//         self
//     }
//     fn as_any_mut(&mut self) -> &mut (dyn std::any::Any) {
//         self
//     }
//     fn clone_box_editor(&self) -> Box<dyn FieldEditor> {
//         Box::new(self.clone())
//     }
// }

pub enum OctetsEditResp {
    None,
    Update(asn1::OctetString),
    SwitchMode,
}

impl OctetsEditState {
    fn new(oct: &asn1::OctetString) -> Self {
        let oct_bytes = oct.as_bytes();
        if oct_bytes.len() <= 2 || oct_bytes.contains(&0x00) {
            return Self::Hex(HexEditState::new(oct));
        }
        let oct_str = std::str::from_utf8(oct_bytes).ok();

        if let Some(oct_str) = oct_str {
            Self::Utf8String(oct_str.to_owned())
        } else {
            Self::Hex(HexEditState::new(oct))
        }
    }

    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, multiline: bool) -> OctetsEditResp {
        let resp = match self {
            OctetsEditState::Hex(hex) => hex.edit_button_ui(ui, id, multiline),
            OctetsEditState::Utf8String(text) => Self::edit_str(text, ui, id, multiline),
        };
        if let OctetsEditResp::SwitchMode = resp {
            self.switch_mode();

            OctetsEditResp::None
        } else {
            resp
        }
    }

    fn switch_mode(&mut self) {
        match self {
            OctetsEditState::Hex(hex) => {
                // TODO move to hex.rs
                // make private: last_convert_err_str
                if hex.is_valid() {
                    if let Ok(oct) = OctetString::asn1_octets_from_hex(&hex.text) {
                        match std::str::from_utf8(oct.as_bytes()) {
                            Ok(s) => {
                                *self = OctetsEditState::Utf8String(s.to_owned());
                            }
                            Err(err) => {
                                hex.last_convert_err_str =
                                    Some(format!("Can't convert to UTF-8\n{}", err))
                            }
                        }
                    }
                } else {
                    // error message already exists
                }
            }
            OctetsEditState::Utf8String(s) => {
                if let Ok(oct) = asn1::OctetString::new(s.as_bytes()) {
                    *self = OctetsEditState::Hex(HexEditState::new(&oct))
                }
            }
        }
    }

    fn edit_str(text: &mut String, ui: &mut Ui, _id: egui::Id, multiline: bool) -> OctetsEditResp {
        let button_resp = ui.button("utf8");
        let switch_mode = button_resp.clicked();

        button_resp.on_hover_ui(|ui| {
            ui.label("Click: switch to OctetString hex editor");
        });

        let resp = if multiline {
            ui.text_edit_multiline(text)
        } else {
            ui.text_edit_singleline(text)
        };

        if resp.changed() {
            match asn1::OctetString::new(text.as_bytes()) {
                Ok(ok) => OctetsEditResp::Update(ok),
                Err(_) => OctetsEditResp::None,
            }
        } else {
            if switch_mode {
                OctetsEditResp::SwitchMode
            } else {
                OctetsEditResp::None
            }
        }
    }
}

impl EditWidget for OctetString {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        if tctx.now_octetstring_only_hex {
            edit_octet_string_only_hex(self, ui, id, false);
        } else {
            edit_octet_string(self, ui, id, false);
        }
    }
}

pub fn edit_octet_string(oct: &mut OctetString, ui: &mut Ui, id: egui::Id, multiline: bool) {
    ui.horizontal(|ui| {
        let hex_edit = oct
            .editor
            .0
            .get_or_insert_with(|| Box::new(OctetsEditState::new(&oct.bytes)));
        let hex_edit = hex_edit.as_any_mut().downcast_mut::<OctetsEditState>();
        if let Some(hex_edit) = hex_edit {
            if let OctetsEditResp::Update(new) = hex_edit.edit_ui(ui, id, multiline) {
                oct.bytes = new;
            }
        }
    });
}

pub fn edit_octet_string_only_hex(
    oct: &mut OctetString,
    ui: &mut Ui,
    id: egui::Id,
    multiline: bool,
) {
    ui.horizontal(|ui| {
        let hex_edit = oct
            .editor
            .0
            .get_or_insert_with(|| Box::new(HexEditState::new(&oct.bytes)));
        let hex_edit = hex_edit.as_any_mut().downcast_mut::<HexEditState>();
        if let Some(hex_edit) = hex_edit {
            if let OctetsEditResp::Update(new) = hex_edit.edit_label_ui(ui, id, multiline) {
                oct.bytes = new;
            }
        }
    });
}
