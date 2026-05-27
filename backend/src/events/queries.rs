//! Parameterized console-DB queries for `event_sinks` / `event_deliveries`
//! (EVT-02) — placeholder filled in Task 3.
//!
//! All SQL will go through sqlx `query!`/`query_as!` (compile-time checked against
//! the committed `.sqlx` offline metadata) — NEVER string interpolation. Clones
//! the `webhooks::queries` queue functions keyed on `sink_id`, adds `event_sinks`
//! CRUD + the per-sink audit cursor reads/writes.
