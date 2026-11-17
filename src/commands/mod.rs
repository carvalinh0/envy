//! One module per CLI command. Each exposes `run` and depends only on [`crate::context::Context`].

pub mod audit;
pub mod check;
pub mod diff;
pub mod export;
pub mod fill;
pub mod history;
pub mod import;
pub mod init;
pub mod list;
pub mod login;
pub mod migrate;
pub mod protect;
pub mod remove;
pub mod rename;
pub mod rollback;
pub mod run;
pub mod schema;
pub mod serve;
pub mod set;
pub mod switch;
pub mod unprotect;
pub mod up;
pub mod update;
pub mod user;
pub mod vault;
pub mod version;
