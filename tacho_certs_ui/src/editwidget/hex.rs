use der::asn1::{self, OctetString};
use egui::{Color32, Separator, TextEdit, Ui, Widget};
use tacho_g2_crypto::cert::hexslice::HexDisplay;

use crate::{editwidget::octets::OctetsEditResp, util::asciislice::AsciiEscapeDisplay};

#[derive(Clone)]
pub struct HexEditState {
    /// e.g. "01 FF"
    pub text: String,
    last_error_str: Option<String>,
    pub last_convert_err_str: Option<String>,
}
// impl FieldEditor for HexEditState {
//     fn is_valid(&self) -> bool {
//         self.last_error_str.is_none()
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

impl HexEditState {
    pub fn new(oct: &asn1::OctetString) -> Self {
        Self {
            text: format!("{}", HexDisplay(&oct.as_bytes())),
            last_error_str: None,
            last_convert_err_str: None,
        }
    }

    fn button_label(&mut self, ui: &mut Ui, clickable: bool) {
        if let Some(err_str) = self.last_error_str.as_deref() {
            ui.label(err_str);
        } else {
            if clickable {
                ui.label("Click: edit this OctetString as UTF-8 text");
            } else {
                ui.label("✔️ hex valid");
            }
            if let Some(err_str) = &self.last_convert_err_str {
                let sep = Separator::default();
                ui.add(sep);
                let mut rich_text = egui::RichText::new(err_str);

                rich_text = rich_text.color(egui::Color32::from_rgb(255, 100, 100));
                ui.label(rich_text);
            }
            ui.label("");
            if let Ok(oct) = OctetString::from_hex(&self.text) {
                let oct = oct.bytes.as_bytes();

                let text = format!(r#""{}""#, AsciiEscapeDisplay(&oct));
                let rich_text = egui::RichText::new(text);
                let rich_text = rich_text.family(egui::FontFamily::Monospace);
                ui.label(rich_text);
            }
        }
    }

    fn get_info_text(&self) -> egui::RichText {
        let mut rich_text = egui::RichText::new("hex");
        let valid = true;//self.is_valid();
        if !valid {
            rich_text = rich_text.color(egui::Color32::from_rgb(255, 100, 100));
        }
        rich_text
    }

    /// With label
    pub fn edit_label_ui(&mut self, ui: &mut Ui, id: egui::Id, multiline: bool) -> OctetsEditResp {
        let label_resp = ui.label(self.get_info_text());
        let switch_mode = label_resp.clicked();
        label_resp.on_hover_ui(|ui| self.button_label(ui, false));

        let resp = self.edit_text_ui(ui, id, multiline);
        if switch_mode {
            return OctetsEditResp::SwitchMode;
        }
        resp
    }

    /// With button
    pub fn edit_button_ui(&mut self, ui: &mut Ui, id: egui::Id, multiline: bool) -> OctetsEditResp {
        let button_resp = ui.button(self.get_info_text());
        let switch_mode = button_resp.clicked();
        button_resp.on_hover_ui(|ui| self.button_label(ui, true));

        let resp = self.edit_text_ui(ui, id, multiline);
        if switch_mode {
            return OctetsEditResp::SwitchMode;
        }
        resp
    }

    pub fn edit_text_ui(&mut self, ui: &mut Ui, id: egui::Id, multiline: bool) -> OctetsEditResp {
        let valid = true;//self.is_valid();
        let mut text_edit = if multiline {
            TextEdit::multiline(&mut self.text)
        } else {
            TextEdit::singleline(&mut self.text)
        };

        text_edit = text_edit
            .hint_text("empty OctetString")
            .id(id.with("text"))
            .desired_width(300.0);

        if !valid {
            text_edit = text_edit.text_color(Color32::from_rgb(255, 100, 100));
        }
        if text_edit.ui(ui).changed() {
            self.last_convert_err_str = None;

            self.text = self.text.to_uppercase();
            let result = OctetString::from_hex(&self.text);
            match result {
                Ok(new) => {
                    self.last_error_str = None;
                    return OctetsEditResp::Update(new.bytes);
                }
                Err(err) => {
                    self.last_error_str = Some(err.to_string());
                }
            }
        }
        OctetsEditResp::None
    }
}
