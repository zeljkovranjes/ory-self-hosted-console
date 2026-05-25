//! Ory Admin client layer (BACK-02) — the backend's first privileged outbound
//! channel to the self-hosted Ory services (Kratos/Hydra/Keto/Oathkeeper).
//!
//! This module is the SINGLE place that speaks to the Ory Admin APIs; the
//! frontend never reaches them (BACK-01 invariant). The base URLs are fixed
//! backend env (not user input) and resolve only on the internal Docker network
//! (INFRA-05) — there is no SSRF surface here.
//!
//! Layout (this plan establishes the foundation only):
//! - [`clients`] — `OryClients`: one OpenAPI-generated `Configuration` per
//!   service, built once from `Config` at startup and injected into the Salvo
//!   `Depot`. Each `Configuration` owns its OWN default reqwest 0.12 client
//!   (RESEARCH Pitfall 1 — the backend's reqwest 0.13 client is a DIFFERENT
//!   type and cannot be injected).
//! - [`error`] — per-crate `map_*_err` functions mapping each crate's distinct
//!   `apis::Error<T>` to `AppError::Upstream` (HTTP 502), never leaking the raw
//!   upstream body or the admin base URL to the client (BACK-07).
//!
//! Arriving in Plan 02 (do NOT add here): the thin proof handler submodules
//! (`kratos`/`hydra`/`keto`/`oathkeeper`) mounted on the Phase-2 protected
//! subtree, and the isolated `fallback` module (reqwest 0.13 + hand-mirrored
//! serde) for endpoints no crate covers.

pub mod clients;
pub mod error;
