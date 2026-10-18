//! Where releases come from and how their files are named.
//!
//! The asset names must match the ones produced by `.github/workflows/bump_version.yml`:
//! `envy-<tag>-<target>.tar.gz` (or `.zip` on Windows).

use std::time::Duration;

use anyhow::{Context, Result, bail};
use ureq::{
    ResponseExt,
    tls::{RootCerts, TlsConfig},
};

pub trait ReleaseSource {
    /// Tag of the latest release, e.g. `v1.2.3`.
    fn latest_tag(&self) -> Result<String>;
    /// Content of one file attached to the release `tag`.
    fn download(&self, tag: &str, asset: &str) -> Result<Vec<u8>>;
}

/// `owner/repo` out of a GitHub URL such as `https://github.com/owner/repo`.
pub fn repository_slug(url: &str) -> Option<String> {
    let path = url
        .trim_end_matches('/')
        .strip_prefix("https://github.com/")?;
    let path = path.strip_suffix(".git").unwrap_or(path);
    let mut parts = path.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(owner), Some(repo), None) if !owner.is_empty() && !repo.is_empty() => {
            Some(format!("{owner}/{repo}"))
        }
        _ => None,
    }
}

/// The tag at the end of the URL that `/releases/latest` redirects to. When the repository has
/// no release GitHub redirects to `/releases` instead.
pub fn tag_from_url(url: &str) -> Result<String> {
    let last = url
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('/')
        .next();
    match last {
        Some(tag) if tag.starts_with('v') && tag[1..].starts_with(|c: char| c.is_ascii_digit()) => {
            Ok(tag.to_string())
        }
        _ => bail!("No release has been published yet."),
    }
}

/// Target triple of the running binary, when a prebuilt release exists for it.
pub fn current_target() -> Result<&'static str> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Ok("x86_64-unknown-linux-gnu")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Ok("aarch64-apple-darwin")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Ok("x86_64-apple-darwin")
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Ok("x86_64-pc-windows-msvc")
    } else {
        bail!("There is no prebuilt binary for this platform.")
    }
}

pub fn asset_name(tag: &str, target: &str) -> String {
    let extension = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    format!("envy-{tag}-{target}.{extension}")
}

pub fn binary_name(target: &str) -> &'static str {
    if target.contains("windows") {
        "envy.exe"
    } else {
        "envy"
    }
}

/// Reads releases from GitHub.
pub struct GithubReleases {
    repo: String,
    base_url: String,
    quick: ureq::Agent,
    slow: ureq::Agent,
}

impl GithubReleases {
    pub fn new(repo: &str) -> Self {
        let agent = |seconds| -> ureq::Agent {
            ureq::Agent::config_builder()
                // Trust the operating system's certificate store (corporate proxies, custom CAs).
                .tls_config(
                    TlsConfig::builder()
                        .root_certs(RootCerts::PlatformVerifier)
                        .build(),
                )
                .timeout_global(Some(Duration::from_secs(seconds)))
                .build()
                .into()
        };
        Self {
            repo: repo.to_string(),
            base_url: "https://github.com".to_string(),
            quick: agent(3),
            slow: agent(120),
        }
    }

    /// The repository declared in `Cargo.toml`.
    pub fn from_package() -> Result<Self> {
        let repo = repository_slug(env!("CARGO_PKG_REPOSITORY"))
            .context("The package repository is not a GitHub URL.")?;
        Ok(Self::new(&repo))
    }

    /// `/releases/latest` redirects to `/releases/tag/<tag>`. Unlike the REST API this has no
    /// anonymous rate limit.
    fn latest_url(&self) -> String {
        format!("{}/{}/releases/latest", self.base_url, self.repo)
    }

    fn asset_url(&self, tag: &str, asset: &str) -> String {
        format!(
            "{}/{}/releases/download/{tag}/{asset}",
            self.base_url, self.repo
        )
    }
}

impl ReleaseSource for GithubReleases {
    fn latest_tag(&self) -> Result<String> {
        let response = self
            .quick
            .get(&self.latest_url())
            .header("User-Agent", concat!("envy/", env!("CARGO_PKG_VERSION")))
            .call()
            .map_err(|err| match err {
                ureq::Error::StatusCode(404) => {
                    anyhow::anyhow!("No release has been published yet.")
                }
                other => anyhow::Error::new(other).context("Could not reach GitHub"),
            })?;
        tag_from_url(&response.get_uri().to_string())
    }

    fn download(&self, tag: &str, asset: &str) -> Result<Vec<u8>> {
        let url = self.asset_url(tag, asset);
        let mut response = self
            .slow
            .get(&url)
            .header("User-Agent", concat!("envy/", env!("CARGO_PKG_VERSION")))
            .call()
            .with_context(|| format!("Could not download {url}"))?;
        Ok(response
            .body_mut()
            .with_config()
            .limit(200 * 1024 * 1024)
            .read_to_vec()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_repository_slug() {
        assert_eq!(
            repository_slug("https://github.com/carvalinh0/envy").as_deref(),
            Some("carvalinh0/envy")
        );
        assert_eq!(
            repository_slug("https://github.com/carvalinh0/envy/").as_deref(),
            Some("carvalinh0/envy")
        );
        assert_eq!(
            repository_slug("https://github.com/carvalinh0/envy.git").as_deref(),
            Some("carvalinh0/envy")
        );
        assert_eq!(repository_slug("https://gitlab.com/a/b"), None);
        assert_eq!(repository_slug("https://github.com/only-owner"), None);
        assert_eq!(repository_slug("https://github.com/a/b/c"), None);
    }

    #[test]
    fn reads_the_tag_from_the_redirect_target() {
        assert_eq!(
            tag_from_url("https://github.com/me/envy/releases/tag/v1.2.3").unwrap(),
            "v1.2.3"
        );
        assert_eq!(
            tag_from_url("https://github.com/me/envy/releases/tag/v10.0.1?x=1").unwrap(),
            "v10.0.1"
        );
    }

    #[test]
    fn a_repository_without_releases_is_reported() {
        for url in [
            "https://github.com/me/envy/releases",
            "https://github.com/me/envy/releases/latest",
            "https://github.com/me/envy/releases/tag/nightly",
            "",
        ] {
            let err = tag_from_url(url).unwrap_err();
            assert!(err.to_string().contains("No release"), "{url}: {err}");
        }
    }

    #[test]
    fn the_package_repository_is_usable() {
        GithubReleases::from_package().unwrap();
    }

    #[test]
    fn asset_names_match_the_release_workflow() {
        assert_eq!(
            asset_name("v1.2.3", "x86_64-unknown-linux-gnu"),
            "envy-v1.2.3-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert_eq!(
            asset_name("v1.2.3", "aarch64-apple-darwin"),
            "envy-v1.2.3-aarch64-apple-darwin.tar.gz"
        );
        assert_eq!(
            asset_name("v1.2.3", "x86_64-pc-windows-msvc"),
            "envy-v1.2.3-x86_64-pc-windows-msvc.zip"
        );
    }

    #[test]
    fn binary_names_by_platform() {
        assert_eq!(binary_name("x86_64-unknown-linux-gnu"), "envy");
        assert_eq!(binary_name("x86_64-pc-windows-msvc"), "envy.exe");
    }

    #[test]
    fn urls_point_to_the_repository() {
        let releases = GithubReleases::new("me/envy");
        assert_eq!(
            releases.latest_url(),
            "https://github.com/me/envy/releases/latest"
        );
        assert_eq!(
            releases.asset_url("v1.0.0", "envy-v1.0.0-x.tar.gz"),
            "https://github.com/me/envy/releases/download/v1.0.0/envy-v1.0.0-x.tar.gz"
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_has_a_prebuilt_target() {
        assert_eq!(current_target().unwrap(), "x86_64-unknown-linux-gnu");
    }
}
