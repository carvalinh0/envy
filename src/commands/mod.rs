//! One module per CLI command. Each exposes `run` and depends only on [`crate::context::Context`].

pub mod check;
pub mod diff;
pub mod export;
pub mod fill;
pub mod import;
pub mod init;
pub mod list;
pub mod remove;
pub mod rename;
pub mod run;
pub mod schema;
pub mod set;
pub mod switch;
pub mod up;
pub mod update;
pub mod version;
