//! Guesses the type of a variable found in an existing `.env` file.

use std::net::IpAddr;

use url::Url;
use uuid::Uuid;

use crate::schema::EnvironmentTypes;

pub trait TypeInferrer {
    fn infer(&self, key: &str, value: &str) -> EnvironmentTypes;
}

/// Name- and value-based heuristics. Anything unrecognised becomes `string`.
#[derive(Debug, Default)]
pub struct HeuristicInferrer;

const SECRET_HINTS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PRIVATE_KEY",
    "API_KEY",
    "APIKEY",
];

impl TypeInferrer for HeuristicInferrer {
    fn infer(&self, key: &str, value: &str) -> EnvironmentTypes {
        let upper = key.to_ascii_uppercase();
        if SECRET_HINTS.iter().any(|hint| upper.contains(hint)) {
            return EnvironmentTypes::Secret;
        }
        if (upper == "PORT" || upper.ends_with("_PORT")) && value.parse::<u16>().is_ok() {
            return EnvironmentTypes::Port;
        }
        if value.parse::<bool>().is_ok() {
            return EnvironmentTypes::Boolean;
        }
        if value.parse::<i64>().is_ok() {
            return EnvironmentTypes::I64;
        }
        if value.parse::<f64>().is_ok() {
            return EnvironmentTypes::F64;
        }
        if Uuid::parse_str(value).is_ok() {
            return EnvironmentTypes::Uuid;
        }
        if value.parse::<IpAddr>().is_ok() {
            return EnvironmentTypes::Ip;
        }
        if Url::parse(value).is_ok_and(|url| url.has_host()) {
            return EnvironmentTypes::Url;
        }
        EnvironmentTypes::String
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn infer(key: &str, value: &str) -> EnvironmentTypes {
        HeuristicInferrer.infer(key, value)
    }

    #[test]
    fn names_that_look_like_secrets_win_over_values() {
        assert_eq!(infer("API_TOKEN", "123"), EnvironmentTypes::Secret);
        assert_eq!(
            infer("db_password", "https://x.y"),
            EnvironmentTypes::Secret
        );
    }

    #[test]
    fn infers_from_values() {
        assert_eq!(infer("PORT", "3000"), EnvironmentTypes::Port);
        assert_eq!(infer("DEBUG", "true"), EnvironmentTypes::Boolean);
        assert_eq!(infer("RETRIES", "3"), EnvironmentTypes::I64);
        assert_eq!(infer("RATIO", "0.5"), EnvironmentTypes::F64);
        assert_eq!(
            infer("ID", "67e55044-10b1-426f-9247-bb680e5fe0c8"),
            EnvironmentTypes::Uuid
        );
        assert_eq!(infer("HOST", "127.0.0.1"), EnvironmentTypes::Ip);
        assert_eq!(
            infer("DATABASE_URL", "postgres://u@h/db"),
            EnvironmentTypes::Url
        );
        assert_eq!(infer("NAME", "hello"), EnvironmentTypes::String);
    }

    #[test]
    fn invalid_port_values_fall_back() {
        assert_eq!(infer("PORT", "99999"), EnvironmentTypes::I64);
    }
}
