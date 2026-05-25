// config/keto/namespaces.ts
//
// Minimal Ory Permission Language (OPL) namespaces file.
// Keto loads this at start via `namespaces.location` in keto.yml.
// It MUST be valid for Keto to start cleanly (RESEARCH Pitfall 6).
//
// This ships ONE trivial namespace so the service boots. Real namespace/OPL
// editing (the Monaco-backed permissions editor) is Phase 9 — do not expand here.

import { Namespace, Context } from "@ory/keto-namespace-types"

// A trivial placeholder namespace. Defines no relations/permissions yet; it
// exists only so Keto has a valid, non-empty namespaces definition at boot.
class Default implements Namespace {}
