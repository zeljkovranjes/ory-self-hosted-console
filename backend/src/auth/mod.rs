//! Console auth subsystem (CAUTH-01..06).
//!
//! - `password` — Argon2id password hash/verify + SHA-256 bootstrap-token
//!   hashing with constant-time compare (Pitfall 5: Argon2 only for passwords,
//!   SHA-256 for the high-entropy token).
//! - `session` — DB-backed opaque sessions: mint/validate, the hardened
//!   `__Host-console_session` cookie, sliding idle + absolute expiry, and the
//!   per-session CSRF token (CAUTH-05).
//! - `setup` — first-run bootstrap-token generation + the token-gated,
//!   single-use (404-after-init) `POST /setup` handler (CAUTH-01..03).
//! - `login` — `POST /login` + `POST /logout` (the session half of CAUTH-05).
//! - `middleware` — the single `auth_guard` chokepoint (401 JSON) + the
//!   per-session `csrf_guard` (403 on state-changing methods) (CAUTH-06, BACK-01).

pub mod github;
pub mod login;
pub mod middleware;
pub mod password;
pub mod session;
pub mod setup;
