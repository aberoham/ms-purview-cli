//! The library behind the `purview` binary. It exists for the binary and its
//! tests and is not a stable API. `cli::execute_with` and `env::Env` are the
//! in-process test harness.

pub mod auth;
pub mod cli;
pub mod config;
pub mod env;
pub mod error;
pub mod graph;
pub mod origin;
pub mod output;
pub mod redact;
pub mod routes;
pub mod secrets;
pub mod token;
pub mod trace;
