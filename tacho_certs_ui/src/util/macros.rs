#[macro_export]
macro_rules! edit_widget_kind {
    ($structure:ty) => {
        impl EditWidget for $structure {
            fn edit_ui(&mut self, ui: &mut Ui, id: egui::Id, _tctx: &mut TachoEditCtx) {
                egui::ComboBox::from_id_salt(id.with(stringify!($structure)))
                    .width(170.0)
                    .selected_text(self.as_ref())
                    .show_ui(ui, |ui| {
                        use strum::IntoEnumIterator;
                        for kind in <$structure>::iter() {
                            ui.selectable_value(self, kind, kind.as_ref());
                        }
                    });
            }
        }
    };
}
