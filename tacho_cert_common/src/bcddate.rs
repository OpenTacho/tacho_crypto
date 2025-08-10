use std::fmt::Debug;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct BCDMonth(pub u8);

impl Default for BCDMonth {
    fn default() -> Self {
        Self(1)
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct BCDYear(pub u8);

impl Default for BCDYear {
    fn default() -> Self {
        Self(1)
    }
}

/// BCD coding
#[derive(Eq, PartialEq, Clone, Default)]
pub struct BCDDate {
    pub month: BCDMonth,
    pub year: BCDYear,
}

impl Debug for BCDDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BCDDate {{ month:{:02X} year:{:02X} }}",
            self.month.0, self.year.0
        )
    }
}
