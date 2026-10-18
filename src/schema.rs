//! Variable types supported by Envy and the parsing of values against them.

use std::{fmt, net::IpAddr, str::FromStr};

use anyhow::{Result, bail};
use base64::Engine;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

/// A value that must never leak through `Display`/`Debug`. The memory is wiped on drop.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "********")
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(<REDACTED>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentTypes {
    I8,
    I16,
    I32,
    I64,
    I128,
    U8,
    U16,
    U32,
    U64,
    U128,
    F32,
    F64,
    Ip,
    Url,
    Port,
    Uuid,
    Base64,
    String,
    Boolean,
    Iso,
    Secret,
    Cron,
}

#[derive(Debug)]
pub enum ParsedValue {
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    F32(f32),
    F64(f64),
    Ip(IpAddr),
    Url(Url),
    Port(u16),
    Uuid(Uuid),
    Base64(Vec<u8>),
    String(String),
    Boolean(bool),
    Iso(chrono::DateTime<chrono::Utc>),
    Secret(Secret),
    Cron(cron::Schedule),
}

const TYPE_NAMES: &[(&str, EnvironmentTypes)] = &[
    ("i8", EnvironmentTypes::I8),
    ("i16", EnvironmentTypes::I16),
    ("i32", EnvironmentTypes::I32),
    ("i64", EnvironmentTypes::I64),
    ("i128", EnvironmentTypes::I128),
    ("u8", EnvironmentTypes::U8),
    ("u16", EnvironmentTypes::U16),
    ("u32", EnvironmentTypes::U32),
    ("u64", EnvironmentTypes::U64),
    ("u128", EnvironmentTypes::U128),
    ("f32", EnvironmentTypes::F32),
    ("f64", EnvironmentTypes::F64),
    ("ip", EnvironmentTypes::Ip),
    ("url", EnvironmentTypes::Url),
    ("port", EnvironmentTypes::Port),
    ("uuid", EnvironmentTypes::Uuid),
    ("base64", EnvironmentTypes::Base64),
    ("string", EnvironmentTypes::String),
    ("boolean", EnvironmentTypes::Boolean),
    ("iso", EnvironmentTypes::Iso),
    ("cron", EnvironmentTypes::Cron),
    ("secret", EnvironmentTypes::Secret),
];

impl EnvironmentTypes {
    pub fn parse_type(value: &str) -> Result<EnvironmentTypes> {
        match TYPE_NAMES.iter().find(|(name, _)| *name == value) {
            Some((_, kind)) => Ok(*kind),
            None => bail!("'{value}' is not a valid type."),
        }
    }

    pub fn as_str(&self) -> &'static str {
        TYPE_NAMES
            .iter()
            .find(|(_, kind)| kind == self)
            .map(|(name, _)| *name)
            .expect("every type has a name")
    }

    /// Parse a value from a defined type.
    pub fn parse_value(value: &str, kind: EnvironmentTypes) -> Result<ParsedValue> {
        match kind {
            EnvironmentTypes::I8 => Ok(ParsedValue::I8(value.parse()?)),
            EnvironmentTypes::I16 => Ok(ParsedValue::I16(value.parse()?)),
            EnvironmentTypes::I32 => Ok(ParsedValue::I32(value.parse()?)),
            EnvironmentTypes::I64 => Ok(ParsedValue::I64(value.parse()?)),
            EnvironmentTypes::I128 => Ok(ParsedValue::I128(value.parse()?)),
            EnvironmentTypes::U8 => Ok(ParsedValue::U8(value.parse()?)),
            EnvironmentTypes::U16 => Ok(ParsedValue::U16(value.parse()?)),
            EnvironmentTypes::U32 => Ok(ParsedValue::U32(value.parse()?)),
            EnvironmentTypes::U64 => Ok(ParsedValue::U64(value.parse()?)),
            EnvironmentTypes::U128 => Ok(ParsedValue::U128(value.parse()?)),
            EnvironmentTypes::F32 => Ok(ParsedValue::F32(value.parse()?)),
            EnvironmentTypes::F64 => Ok(ParsedValue::F64(value.parse()?)),
            EnvironmentTypes::Ip => Ok(ParsedValue::Ip(value.parse()?)),
            EnvironmentTypes::Url => Ok(ParsedValue::Url(value.parse()?)),
            EnvironmentTypes::Port => Ok(ParsedValue::Port(value.parse()?)),
            EnvironmentTypes::Uuid => Ok(ParsedValue::Uuid(value.parse()?)),
            EnvironmentTypes::Base64 => Ok(ParsedValue::Base64(
                base64::engine::general_purpose::STANDARD.decode(value)?,
            )),
            EnvironmentTypes::String => Ok(ParsedValue::String(value.to_string())),
            EnvironmentTypes::Boolean => Ok(ParsedValue::Boolean(value.parse()?)),
            EnvironmentTypes::Iso => Ok(ParsedValue::Iso(
                value.parse::<chrono::DateTime<chrono::Utc>>()?,
            )),
            EnvironmentTypes::Cron => Ok(ParsedValue::Cron(cron::Schedule::from_str(value)?)),
            EnvironmentTypes::Secret => Ok(ParsedValue::Secret(Secret::new(value))),
        }
    }

    /// Checks that `value` is valid for `kind` without keeping the parsed result.
    pub fn validate(value: &str, kind: EnvironmentTypes) -> Result<()> {
        Self::parse_value(value, kind).map(|_| ())
    }
}

impl FromStr for EnvironmentTypes {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse_type(s)
    }
}

impl fmt::Display for EnvironmentTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_unknown_type() {
        assert!(EnvironmentTypes::parse_type("wrong type").is_err());
    }

    #[test]
    fn every_type_name_round_trips() {
        for (name, kind) in TYPE_NAMES {
            assert_eq!(EnvironmentTypes::parse_type(name).unwrap(), *kind);
            assert_eq!(kind.as_str(), *name);
        }
    }

    #[test]
    fn matches_the_json_schema_enum() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/v1.json")).unwrap();
        let mut expected: Vec<String> =
            schema["$defs"]["envVarConfig"]["properties"]["type"]["enum"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
        let mut actual: Vec<String> = TYPE_NAMES.iter().map(|(n, _)| n.to_string()).collect();
        expected.sort();
        actual.sort();
        assert_eq!(expected, actual);
    }

    #[test]
    fn check_wrong_values() {
        use EnvironmentTypes::*;
        for kind in [
            Base64, I8, I16, I32, I64, I128, U8, U16, U32, U64, U128, F32, F64, Ip, Url, Port,
            Uuid, Boolean, Iso, Cron,
        ] {
            assert!(
                EnvironmentTypes::parse_value("wrong", kind).is_err(),
                "{kind} accepted an invalid value"
            );
        }
    }

    #[test]
    fn check_valid_values() {
        use EnvironmentTypes::*;
        let cases = [
            ("-8", I8),
            ("-16", I16),
            ("-32", I32),
            ("-64", I64),
            ("-128", I128),
            ("8", U8),
            ("16", U16),
            ("32", U32),
            ("64", U64),
            ("128", U128),
            ("1.5", F32),
            ("2.5", F64),
            ("127.0.0.1", Ip),
            ("::1", Ip),
            ("https://example.com/path", Url),
            ("8080", Port),
            ("67e55044-10b1-426f-9247-bb680e5fe0c8", Uuid),
            ("aGVsbG8=", Base64),
            ("anything", String),
            ("true", Boolean),
            ("2026-10-17T12:00:00Z", Iso),
            ("0 0 * * * * *", Cron),
            ("s3cr3t", Secret),
        ];
        for (value, kind) in cases {
            assert!(
                EnvironmentTypes::parse_value(value, kind).is_ok(),
                "{kind} rejected '{value}'"
            );
        }
    }

    #[test]
    fn integer_bounds_are_enforced() {
        assert!(EnvironmentTypes::validate("256", EnvironmentTypes::U8).is_err());
        assert!(EnvironmentTypes::validate("-1", EnvironmentTypes::U8).is_err());
        assert!(EnvironmentTypes::validate("65536", EnvironmentTypes::Port).is_err());
    }

    #[test]
    fn secret_never_exposes_its_value() {
        let secret = Secret::new("my secret");
        assert_ne!(secret.to_string(), "my secret");
        assert!(!format!("{secret:?}").contains("my secret"));
        assert_eq!(secret.expose_secret(), "my secret");
    }

    #[test]
    fn parsed_secret_is_redacted_in_debug() {
        let parsed = EnvironmentTypes::parse_value("hunter2", EnvironmentTypes::Secret).unwrap();
        assert!(!format!("{parsed:?}").contains("hunter2"));
    }
}
