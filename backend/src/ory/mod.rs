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
//! Added in Plan 02: the thin proof handler submodules
//! (`kratos`/`hydra`/`keto`/`oathkeeper`) — one authenticated GET wrapper per
//! service mounted on the Phase-2 protected subtree — and the isolated
//! [`fallback`] module (reqwest 0.13 + hand-mirrored serde) for endpoints no
//! crate covers. `fallback` is deliberately ISOLATED from the typed-client path:
//! it never imports the Ory crates' `apis`, and the typed handlers never import
//! it (auditability + containment of the reqwest 0.12/0.13 split, RESEARCH).

pub mod clients;
pub mod error;
pub mod fallback;
pub mod hydra;
pub mod keto;
pub mod kratos;
pub mod oathkeeper;

/// WR-02: the default page size every proof-read list wrapper requests from its
/// upstream Ory service. These wrappers return ONLY the first page and do not
/// yet surface the upstream pagination cursor (`Link` header / `next_page_token`)
/// — full cursor pagination is deferred to the feature phases (P6 identities,
/// P8 OAuth2 clients, P9 Keto/Oathkeeper). Naming the cap here removes the magic
/// `50` from each handler and documents the proof-slice limit in ONE place.
///
/// TODO(P6/P8/P9): expose the upstream pagination cursor (page_token/offset) and
/// stop truncating silently at `DEFAULT_LIST_PAGE_SIZE`.
pub const DEFAULT_LIST_PAGE_SIZE: i64 = 50;
