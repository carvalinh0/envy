//! Current time.
//!
//! Time comes from the operating system, so commands read it through [`Clock`] and tests
//! can pin it.

use chrono::{DateTime, Utc};

pub trait Clock {
    fn now(&self) -> DateTime<Utc>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}
