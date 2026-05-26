//! Ory Self-Hosted Console — backend library crate.
//!
//! The binary (`main.rs`) is a thin bootstrap over this library; integration
//! tests under `tests/` import these modules (`ory_console_backend::*`) to
//! exercise the real router/handlers with Salvo `TestClient`.

pub mod activity;
pub mod audit;
pub mod auth;
pub mod branding;
pub mod config;
pub mod config_edit;
pub mod db;
pub mod error;
pub mod overview;
pub mod ory;
pub mod routes;
pub mod webhooks;
