use core::fmt;
use std::{error::Error, fmt::Display};

use chrono::{DateTime, Utc};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct TimeReal {
    /// Seconds past 00h 00m 00s on 1 January 1970 UTC
    pub timestamp: chrono::DateTime<Utc>,
}

#[derive(Debug)]
pub struct TimeRealTooLarge;

impl Error for TimeRealTooLarge {}

impl Display for TimeRealTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TimeRealTooLarge")
    }
}
impl TimeReal {
    pub const fn from_bytes(unix_epoch: [u8; 4]) -> TimeReal {
        let unix_ts = u32::from_be_bytes(unix_epoch);
        TimeReal {
            timestamp: DateTime::from_timestamp(unix_ts as i64, 0).expect("to never fail with u32"),
        }
    }

    pub fn to_bytes(&self) -> Result<[u8; 4], TimeRealTooLarge> {
        let ts = self.timestamp.timestamp();
        let ts32: u32 = ts.try_into().map_err(|_| TimeRealTooLarge)?;
        Ok(ts32.to_be_bytes())
    }
}
