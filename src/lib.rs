//! Envy: validate, edit and securely share environment variables.
//!
//! The binary in `src/main.rs` only wires the concrete implementations together; every
//! command depends on the traits defined here, which keeps them easy to test.

pub mod app;
pub mod bundle;
pub mod cli;
pub mod commands;
pub mod config;
pub mod context;
pub mod dotenv;
pub mod envy;
pub mod inference;
pub mod prompt;
pub mod resolver;
pub mod runner;
pub mod schema;
pub mod state;
pub mod update;
pub mod vault;
pub mod workspace;
