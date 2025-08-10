use core::fmt;
use std::fmt::Write;

pub struct AsciiEscapeDisplay<'a>(pub &'a [u8]);

impl fmt::Display for AsciiEscapeDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            if (32..127).contains(byte) {
                f.write_char(*byte as char)?;
            } else {
                f.write_char('.')?;
            }
        }
        Ok(())
    }
}
