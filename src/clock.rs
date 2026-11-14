//! Current time and the durations written in the manifest (`"every": "90d"`) and in flags
//! (`envy export --ttl 7d`).
//!
//! Time comes from the operating system, so commands read it through [`Clock`] and tests
//! can pin it.

use anyhow::{Result, bail};
use chrono::{DateTime, Duration, Utc};

pub trait Clock {
    fn now(&self) -> DateTime<Utc>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// `<number><unit>` with the unit `h` (hours), `d` (days) or `w` (weeks), e.g. `90d`.
pub fn parse_duration(text: &str) -> Result<Duration> {
    let Some(unit) = text.chars().last() else {
        bail!("The duration is empty. Use a number followed by h, d or w (e.g. 90d).");
    };
    let amount: i64 = match text[..text.len() - unit.len_utf8()].parse() {
        Ok(amount) if amount > 0 => amount,
        _ => bail!("'{text}' is not a duration. Use a number followed by h, d or w (e.g. 90d)."),
    };
    let duration = match unit {
        'h' => Duration::try_hours(amount),
        'd' => Duration::try_days(amount),
        'w' => Duration::try_weeks(amount),
        _ => bail!("'{text}' has an unknown unit. Use h, d or w (e.g. 90d)."),
    };
    match duration {
        Some(duration) => Ok(duration),
        None => bail!("'{text}' is too long."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_accept_hours_days_and_weeks() {
        assert_eq!(parse_duration("12h").unwrap(), Duration::hours(12));
        assert_eq!(parse_duration("90d").unwrap(), Duration::days(90));
        assert_eq!(parse_duration("2w").unwrap(), Duration::weeks(2));
    }

    #[test]
    fn invalid_durations_are_rejected() {
        for text in [
            "",
            "d",
            "0d",
            "-1d",
            "10",
            "10m",
            "1.5d",
            "ninetyd",
            "9999999999999999w",
        ] {
            assert!(parse_duration(text).is_err(), "{text:?} should be rejected");
        }
    }
}
