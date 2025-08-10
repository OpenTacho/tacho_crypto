use std::borrow::Cow;

use crate::editctx::TachoEditCtx;
use egui::{DragValue, Widget};
use egui::{TextEdit, Ui};
use tacho_g2_crypto::cert::hexslice::HexDisplay;

//pub mod octets;
//pub mod hex;

pub trait EditWidget {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx);
}

pub trait EditWidgetEdited: EditWidget + Eq + Clone
where
    Self: Sized,
{
    fn edited(mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) -> Option<Self> {
        let old = self.clone();
        self.edit_ui(ui, id, tctx);
        if old != self { Some(self) } else { None }
    }
}

impl<E> EditWidgetEdited for E where E: EditWidget + Eq + Clone {}

impl EditWidget for String {
    fn edit_ui(&mut self, ui: &mut Ui, _id: egui::Id, _tctx: &mut TachoEditCtx) {
        TextEdit::singleline(self)
            .hint_text("empty UTF8String")
            .desired_width(300.0)
            .ui(ui);
    }
}

impl EditWidget for bool {
    fn edit_ui(&mut self, ui: &mut Ui, _id: egui::Id, _tctx: &mut TachoEditCtx) {
        ui.checkbox(self, "bool");
    }
}

impl EditWidget for () {
    fn edit_ui(&mut self, _ui: &mut Ui, _id: egui::Id, _tctx: &mut TachoEditCtx) {}
}

impl EditWidget for der::asn1::Null {
    fn edit_ui(&mut self, ui: &mut Ui, _id: egui::Id, _tctx: &mut TachoEditCtx) {
        ui.label(format!("NULL"));
    }
}

impl EditWidget for &mut [u8] {
    fn edit_ui(&mut self, ui: &mut Ui, _id: egui::Id, tctx: &mut TachoEditCtx) {
        let hex_text = {
            let buf = tctx.string_buf();
            use std::fmt::Write;
            write!(buf, "{}", HexDisplay(self)).unwrap();
            buf
        };

        TextEdit::singleline(hex_text)
            .hint_text("empty OctetString")
            .desired_width(300.0)
            .ui(ui);
    }
}

impl EditWidget for &[u8] {
    fn edit_ui(&mut self, ui: &mut Ui, _id: egui::Id, tctx: &mut TachoEditCtx) {
        let hex_text = {
            let buf = tctx.string_buf();
            use std::fmt::Write;
            write!(buf, "{}", HexDisplay(self)).unwrap();
            buf
        };

        TextEdit::singleline(hex_text)
            .hint_text("empty OctetString")
            .desired_width(300.0)
            .ui(ui);
    }
}

impl<'a> EditWidget for Cow<'a, [u8]> {
    fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, tctx: &mut TachoEditCtx) {
        let mut value = self.to_vec();
        value.as_mut_slice().edit_ui(ui, id, tctx);
        *self = Cow::Owned(value);
    }
}

impl EditWidget for u8 {
    fn edit_ui(&mut self, ui: &mut Ui, _id: egui::Id, _tctx: &mut TachoEditCtx) {
        ui.add(DragValue::new(self).range(0..=255));
    }
}
