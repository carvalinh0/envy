//! Self-update: finding the latest release, comparing versions and installing it.

pub mod archive;
pub mod installer;
pub mod release;
pub mod version;

pub use installer::{SelfUpdater, SystemUpdater, UpdateMethod};
pub use release::{GithubReleases, ReleaseSource};
pub use version::Version;
