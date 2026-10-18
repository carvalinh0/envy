use std::{fmt, str::FromStr};

use anyhow::{Context, Result, bail};

/// A `MAJOR.MINOR.PATCH` version. A leading `v` and any `-pre`/`+build` suffix are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    pub fn parse(text: &str) -> Result<Self> {
        let trimmed = text.trim().trim_start_matches('v');
        let core = trimmed.split(['-', '+']).next().unwrap_or_default();

        let parts: Vec<&str> = core.split('.').collect();
        if parts.len() != 3 {
            bail!("'{text}' is not a MAJOR.MINOR.PATCH version.");
        }
        let number = |part: &str| {
            part.parse::<u64>()
                .with_context(|| format!("'{text}' is not a MAJOR.MINOR.PATCH version."))
        };
        Ok(Self {
            major: number(parts[0])?,
            minor: number(parts[1])?,
            patch: number(parts[2])?,
        })
    }

    /// The version this binary was built as.
    pub fn current() -> Result<Self> {
        Self::parse(env!("CARGO_PKG_VERSION"))
    }
}

impl FromStr for Version {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tags_and_plain_versions() {
        assert_eq!(Version::parse("v1.2.3").unwrap().to_string(), "1.2.3");
        assert_eq!(Version::parse("0.10.0").unwrap().to_string(), "0.10.0");
        assert_eq!(Version::parse(" v2.0.1 ").unwrap().to_string(), "2.0.1");
    }

    #[test]
    fn ignores_pre_release_and_build_suffixes() {
        assert_eq!(
            Version::parse("v1.2.3-rc.1").unwrap(),
            Version::parse("1.2.3").unwrap()
        );
        assert_eq!(
            Version::parse("1.2.3+abc").unwrap(),
            Version::parse("1.2.3").unwrap()
        );
    }

    #[test]
    fn rejects_malformed_versions() {
        for bad in ["", "v1", "1.2", "1.2.3.4", "a.b.c", "v1.2.x", "latest"] {
            assert!(Version::parse(bad).is_err(), "'{bad}' was accepted");
        }
    }

    #[test]
    fn compares_numerically_not_alphabetically() {
        assert!(Version::parse("1.10.0").unwrap() > Version::parse("1.9.9").unwrap());
        assert!(Version::parse("2.0.0").unwrap() > Version::parse("1.99.99").unwrap());
        assert!(Version::parse("0.0.2").unwrap() > Version::parse("0.0.1").unwrap());
        assert_eq!(
            Version::parse("1.0.0").unwrap(),
            Version::parse("v1.0.0").unwrap()
        );
    }

    #[test]
    fn current_version_is_valid() {
        Version::current().unwrap();
    }
}
