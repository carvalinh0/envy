//! How requests reach a server: over HTTPS ([`HttpTransport`]) or, in tests, straight into
//! an in-process [`ServerCore`] ([`LocalTransport`]) through the same JSON.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use ureq::tls::{RootCerts, TlsConfig};

use super::protocol::{ApiError, MAX_BODY, RPC_PATH, Request};
use crate::server::ServerCore;

pub trait Transport {
    /// Sends one request; a refusal of the server is an [`ApiError`] inside the error.
    fn call(&self, token: Option<&str>, request: &Request) -> Result<Value>;
}

/// The server URL without a trailing `/`. Plain `http://` is only accepted for this machine:
/// anywhere else the session token and the ciphertexts would cross the network in clear.
pub fn check_url(url: &str) -> Result<String> {
    let parsed = url::Url::parse(url).with_context(|| format!("'{url}' is not a URL"))?;
    let local = matches!(
        parsed.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    match parsed.scheme() {
        "https" => {}
        "http" if local => {}
        "http" => {
            bail!("The server must use https:// (plain http:// is only allowed for localhost).")
        }
        other => bail!("'{other}://' is not supported; use https://."),
    }
    Ok(url.trim_end_matches('/').to_string())
}

fn parse_reply(status: u16, body: &[u8]) -> Result<Value> {
    if status == 200 {
        return serde_json::from_slice(body).context("The server sent an invalid answer");
    }
    match serde_json::from_slice::<ApiError>(body) {
        Ok(error) => Err(anyhow::Error::new(error)),
        Err(_) => Err(anyhow!("The server answered with status {status}.")),
    }
}

pub struct HttpTransport {
    base: String,
    agent: ureq::Agent,
}

impl HttpTransport {
    pub fn new(url: &str) -> Result<Self> {
        let agent = ureq::Agent::config_builder()
            .tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .build()
            .into();
        Ok(Self {
            base: check_url(url)?,
            agent,
        })
    }
}

impl Transport for HttpTransport {
    fn call(&self, token: Option<&str>, request: &Request) -> Result<Value> {
        let body = serde_json::to_vec(request)?;
        let mut call = self
            .agent
            .post(format!("{}{RPC_PATH}", self.base))
            .header("User-Agent", concat!("envy/", env!("CARGO_PKG_VERSION")))
            .header("Content-Type", "application/json");
        if let Some(token) = token {
            call = call.header("Authorization", format!("Bearer {token}"));
        }
        let mut response = call
            .send(&body[..])
            .with_context(|| format!("Could not reach the Envy server at {}", self.base))?;
        let status = response.status().as_u16();
        let reply = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY as u64)
            .read_to_vec()
            .with_context(|| format!("Could not read the answer of {}", self.base))?;
        parse_reply(status, &reply)
    }
}

/// Calls a [`ServerCore`] in this process, through the same JSON as HTTP.
pub struct LocalTransport {
    core: Arc<ServerCore>,
    client: String,
}

impl LocalTransport {
    pub fn new(core: Arc<ServerCore>, client: &str) -> Self {
        Self {
            core,
            client: client.to_string(),
        }
    }
}

impl Transport for LocalTransport {
    fn call(&self, token: Option<&str>, request: &Request) -> Result<Value> {
        let body = serde_json::to_vec(request)?;
        let (status, reply) = self.core.handle_json(&self.client, token, &body);
        parse_reply(status, &reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_is_only_for_this_machine() {
        assert_eq!(
            check_url("https://envy.example/").unwrap(),
            "https://envy.example"
        );
        assert!(check_url("http://localhost:8080").is_ok());
        assert!(check_url("http://127.0.0.1:8080").is_ok());
        assert!(check_url("http://[::1]:8080").is_ok());
        let err = check_url("http://envy.example").unwrap_err().to_string();
        assert!(err.contains("must use https://"), "{err}");
        assert!(check_url("ftp://envy.example").is_err());
        assert!(check_url("not a url").is_err());
    }
}
