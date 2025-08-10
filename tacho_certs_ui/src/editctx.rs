#[derive(Clone, Default)]
pub struct TachoEditCtx {
    pub now_octetstring_only_hex: bool,
    buf: String,
}

impl TachoEditCtx {
    pub fn string_buf(&mut self) -> &mut String {
        self.buf.clear();
        &mut self.buf
    }
}
