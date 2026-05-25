# Vendored Ory config schemas — provenance

These JSON Schemas are vendored (committed) so the backend validates Ory service
config **offline and reproducibly** (no network fetch at build or runtime). They
are embedded into the binary via `include_str!` in `backend/src/config_edit/schema.rs`.

**Retrieval date:** 2026-05-25
**Pin policy:** service schemas are pinned to the `v26.2.0` git tag (lockstep with
the `oryd/<svc>:v26.2.0` images and the `ory-*-client` 26.2.0 crates). The five
`ory://` sub-schemas are pinned to the **vendored `oryx/` tree inside the Hydra
v26.2.0 source** (Ory vendors `github.com/ory/x` in-repo under `./oryx`), which is
the exact `ory/x` revision the v26.2.0 service line was built against — strictly
better than `ory/x` master (RESEARCH assumption A2).

## v26.2.0 tag → commit SHAs

| Repo | Tag | Commit SHA |
|------|-----|------------|
| ory/hydra | v26.2.0 | `0b84568fffccf151dc5e6c7955fdfb738555bf4b` |
| ory/kratos | v26.2.0 | `9d7085948039ffb8960160d4979f71527b5cf4d5` |
| ory/keto | v26.2.0 | `e4393662cd2e744deeb79de77669e07b6ccf51f3` |
| ory/oathkeeper | v26.2.0 | `c84dbe07ecbf6f10154f04ec49b137a115155289` |

## Service config schemas

| Local file | Source URL (pinned) |
|------------|---------------------|
| `kratos.config.schema.json` | https://raw.githubusercontent.com/ory/kratos/v26.2.0/embedx/config.schema.json |
| `hydra.config.schema.json` | https://raw.githubusercontent.com/ory/hydra/v26.2.0/spec/config.json |
| `keto.config.schema.json` | https://raw.githubusercontent.com/ory/keto/v26.2.0/embedx/config.schema.json |
| `oathkeeper.config.schema.json` | https://raw.githubusercontent.com/ory/oathkeeper/v26.2.0/spec/config.schema.json |

All four are JSON-Schema **draft-07**. Their `ory://` `$ref` usage (verified by
parsing the vendored files):

| Service | `ory://` refs used |
|---------|--------------------|
| kratos | `ory://tracing-config` |
| hydra | `ory://serve-config`, `ory://cors-config`, `ory://tls-config`, `ory://tracing-config` |
| keto | `ory://logging-config`, `ory://tracing-config` |
| oathkeeper | `ory://logging-config`, `ory://tracing-config` |

## `ory://` sub-schemas (resolved offline by the `OryRefs` Retriever)

Vendored from Hydra v26.2.0's in-repo `oryx/` tree (the pinned `ory/x` revision):

| Local file | `ory://` URI it answers | Source URL (pinned) | own `$id` |
|------------|-------------------------|---------------------|-----------|
| `ory/tracing-config.json` | `ory://tracing-config` | https://raw.githubusercontent.com/ory/hydra/v26.2.0/oryx/otelx/config.schema.json | `ory://tracing-config` |
| `ory/logging-config.json` | `ory://logging-config` | https://raw.githubusercontent.com/ory/hydra/v26.2.0/oryx/logrusx/config.schema.json | `ory://logging-config` |
| `ory/serve-config.json` | `ory://serve-config` | https://raw.githubusercontent.com/ory/hydra/v26.2.0/oryx/configx/serve.schema.json | `https://github.com/ory/x/configx/serve.schema.json` |
| `ory/cors-config.json` | `ory://cors-config` | https://raw.githubusercontent.com/ory/hydra/v26.2.0/oryx/configx/cors.schema.json | `https://github.com/ory/x/configx/cors.schema.json` |
| `ory/tls-config.json` | `ory://tls-config` | https://raw.githubusercontent.com/ory/hydra/v26.2.0/oryx/configx/tls.schema.json | `https://github.com/ory/x/tlsx/config.schema.json` |

> Note (RESEARCH A1): `otelx` and `logrusx` ship their own `$id` equal to the
> `ory://…` URI, but `configx/{serve,cors,tls}.schema.json` ship a NON-`ory://`
> `$id` (`https://github.com/ory/x/...`) — Ory binds the `ory://serve-config` /
> `ory://cors-config` / `ory://tls-config` URIs **programmatically** at load
> (`configx/schema.go` → `AddSchemaResources`). The `OryRefs` Retriever therefore
> keys on the `ory://…` URI from the parent `$ref`, NOT on each file's `$id`.

## Re-vendoring (reproducible)

```bash
cd backend
# service schemas (v26.2.0 tag)
curl -fsS -o config/schemas/kratos.config.schema.json     https://raw.githubusercontent.com/ory/kratos/v26.2.0/embedx/config.schema.json
curl -fsS -o config/schemas/hydra.config.schema.json      https://raw.githubusercontent.com/ory/hydra/v26.2.0/spec/config.json
curl -fsS -o config/schemas/keto.config.schema.json       https://raw.githubusercontent.com/ory/keto/v26.2.0/embedx/config.schema.json
curl -fsS -o config/schemas/oathkeeper.config.schema.json https://raw.githubusercontent.com/ory/oathkeeper/v26.2.0/spec/config.schema.json
# ory:// sub-schemas (Hydra v26.2.0 vendored oryx/ — the pinned ory/x revision)
ORYX=https://raw.githubusercontent.com/ory/hydra/v26.2.0/oryx
curl -fsS -o config/schemas/ory/tracing-config.json $ORYX/otelx/config.schema.json
curl -fsS -o config/schemas/ory/logging-config.json $ORYX/logrusx/config.schema.json
curl -fsS -o config/schemas/ory/serve-config.json   $ORYX/configx/serve.schema.json
curl -fsS -o config/schemas/ory/cors-config.json    $ORYX/configx/cors.schema.json
curl -fsS -o config/schemas/ory/tls-config.json     $ORYX/configx/tls.schema.json
```
