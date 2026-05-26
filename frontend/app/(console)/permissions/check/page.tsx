"use client";

// PERM-03 — the Check & Expand panel (09-UI-SPEC §B).
//
// A read-mostly page with two tabs mirroring the OAuth2 inspector:
//   - Check:  namespace/object/relation + subject (id or set) -> GET
//             /api/keto/check -> a definitive {allowed} drives an
//             "Allowed" (--success) / "Denied" (--destructive) result block.
//   - Expand: namespace/object/relation -> GET /api/keto/expand -> the subject
//             tree rendered read-only in a Monaco JSON block.
//
// CRITICAL (T-9-fe-deny — copy the inspector 404-vs-502 discipline): ONLY a
// definitive Keto {allowed} result drives the allowed/denied UI. An ApiError
// (e.g. a 502 AppError::Upstream — Keto unreachable/timed-out) surfaces a
// destructive "Check failed" Alert and is NEVER collapsed into "denied".
//
// All queries are GET (read-only) — no CSRF, no state-changing affordance, no
// AlertDialog. All egress via @/lib/api; no Ory host is ever called directly.

import * as React from "react";
import { Loader2Icon } from "lucide-react";

import { api } from "@/lib/api";
import { MonacoEditor } from "@/components/monaco-editor";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

type CheckResult = { allowed: boolean };

// A subject is EITHER a direct id OR a complete subject_set. Append whichever
// the operator filled to the query params.
function appendSubject(
  qp: URLSearchParams,
  subjectId: string,
  ss: { namespace: string; object: string; relation: string },
): void {
  if (subjectId.trim()) {
    qp.set("subject_id", subjectId.trim());
    return;
  }
  if (ss.namespace.trim() || ss.object.trim() || ss.relation.trim()) {
    qp.set("subject_set_namespace", ss.namespace.trim());
    qp.set("subject_set_object", ss.object.trim());
    qp.set("subject_set_relation", ss.relation.trim());
  }
}

function CheckTab() {
  const [namespace, setNamespace] = React.useState("");
  const [object, setObject] = React.useState("");
  const [relation, setRelation] = React.useState("");
  const [subjectId, setSubjectId] = React.useState("");
  const [ssNamespace, setSsNamespace] = React.useState("");
  const [ssObject, setSsObject] = React.useState("");
  const [ssRelation, setSsRelation] = React.useState("");

  // `result` is ONLY ever a definitive Keto answer; an error sets `status` to
  // "error" and leaves `result` null (never collapsed into a denied result).
  const [result, setResult] = React.useState<CheckResult | null>(null);
  const [status, setStatus] = React.useState<"idle" | "loading" | "error">(
    "idle",
  );

  const canSubmit =
    namespace.trim().length > 0 &&
    object.trim().length > 0 &&
    relation.trim().length > 0 &&
    (subjectId.trim().length > 0 ||
      (ssNamespace.trim().length > 0 &&
        ssObject.trim().length > 0 &&
        ssRelation.trim().length > 0));

  async function runCheck() {
    if (!canSubmit) return;
    setStatus("loading");
    setResult(null);
    try {
      const qp = new URLSearchParams();
      qp.set("namespace", namespace.trim());
      qp.set("object", object.trim());
      qp.set("relation", relation.trim());
      appendSubject(qp, subjectId, {
        namespace: ssNamespace,
        object: ssObject,
        relation: ssRelation,
      });
      const res = await api<CheckResult>(`/api/keto/check?${qp.toString()}`);
      setResult(res);
      setStatus("idle");
    } catch {
      // An ApiError (502 upstream, etc.) is an operational failure, NOT a deny.
      setStatus("error");
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-3">
        <Field id="check-namespace" label="Namespace" placeholder="e.g. documents" value={namespace} onChange={setNamespace} />
        <Field id="check-object" label="Object" placeholder="e.g. doc:readme" value={object} onChange={setObject} />
        <div className="grid gap-2">
          <Label htmlFor="check-relation">Relation</Label>
          <Input
            id="check-relation"
            className="font-mono text-xs"
            placeholder="e.g. view"
            value={relation}
            onChange={(e) => setRelation(e.target.value)}
          />
          <p className="text-muted-foreground text-sm">
            For an OPL permission, use the permits-function name from your
            permission model, not a raw relation.
          </p>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-[1fr_auto]">
        <Field id="check-subject-id" label="Subject ID" placeholder="e.g. user:alice" value={subjectId} onChange={setSubjectId} />
      </div>

      <div className="grid gap-2">
        <Label>Subject set (alternative to subject ID)</Label>
        <div className="grid gap-2 sm:grid-cols-3">
          <Input aria-label="Subject set namespace" className="font-mono text-xs" placeholder="namespace" value={ssNamespace} onChange={(e) => setSsNamespace(e.target.value)} />
          <Input aria-label="Subject set object" className="font-mono text-xs" placeholder="object" value={ssObject} onChange={(e) => setSsObject(e.target.value)} />
          <Input aria-label="Subject set relation" className="font-mono text-xs" placeholder="relation" value={ssRelation} onChange={(e) => setSsRelation(e.target.value)} />
        </div>
      </div>

      <div className="flex justify-end">
        <Button type="button" onClick={runCheck} disabled={!canSubmit || status === "loading"}>
          {status === "loading" ? (
            <>
              <Loader2Icon className="animate-spin" />
              Checking…
            </>
          ) : (
            "Check"
          )}
        </Button>
      </div>

      {/* Error branch is SEPARATE from the allowed/denied branch (T-9-fe-deny). */}
      {status === "error" ? (
        <Alert role="alert" variant="destructive">
          <AlertTitle>Check failed</AlertTitle>
          <AlertDescription>
            The permission check could not be completed. Try again later.
          </AlertDescription>
        </Alert>
      ) : null}

      {result ? (
        <div className="rounded-md border p-4">
          {result.allowed ? (
            <p className="text-[--success] font-medium">
              Allowed — the subject has this permission.
            </p>
          ) : (
            <p className="text-destructive font-medium">
              Denied — the subject does not have this permission.
            </p>
          )}
        </div>
      ) : null}
    </div>
  );
}

function ExpandTab() {
  const [namespace, setNamespace] = React.useState("");
  const [object, setObject] = React.useState("");
  const [relation, setRelation] = React.useState("");
  const [raw, setRaw] = React.useState<string | null>(null);
  const [empty, setEmpty] = React.useState(false);
  const [status, setStatus] = React.useState<"idle" | "loading" | "error">(
    "idle",
  );

  const canSubmit =
    namespace.trim().length > 0 &&
    object.trim().length > 0 &&
    relation.trim().length > 0;

  async function runExpand() {
    if (!canSubmit) return;
    setStatus("loading");
    setRaw(null);
    setEmpty(false);
    try {
      const qp = new URLSearchParams();
      qp.set("namespace", namespace.trim());
      qp.set("object", object.trim());
      qp.set("relation", relation.trim());
      const res = await api<Record<string, unknown>>(
        `/api/keto/expand?${qp.toString()}`,
      );
      // An empty subject tree (no children, no subject) resolves to an empty set.
      const children = (res?.children as unknown[] | undefined) ?? [];
      if (!res || (children.length === 0 && !res.subject_id && !res.subject_set)) {
        setEmpty(true);
        setRaw(null);
      } else {
        setRaw(JSON.stringify(res, null, 2));
      }
      setStatus("idle");
    } catch {
      setStatus("error");
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-3">
        <Field id="expand-namespace" label="Namespace" placeholder="e.g. documents" value={namespace} onChange={setNamespace} />
        <Field id="expand-object" label="Object" placeholder="e.g. doc:readme" value={object} onChange={setObject} />
        <Field id="expand-relation" label="Relation" placeholder="e.g. view" value={relation} onChange={setRelation} />
      </div>

      <div className="flex justify-end">
        <Button type="button" onClick={runExpand} disabled={!canSubmit || status === "loading"}>
          {status === "loading" ? (
            <>
              <Loader2Icon className="animate-spin" />
              Expanding…
            </>
          ) : (
            "Expand"
          )}
        </Button>
      </div>

      {status === "error" ? (
        <Alert role="alert" variant="destructive">
          <AlertTitle>Expand failed</AlertTitle>
          <AlertDescription>
            The subject tree could not be expanded. Try again later.
          </AlertDescription>
        </Alert>
      ) : null}

      {empty ? (
        <div className="rounded-md border p-4">
          <p className="text-muted-foreground text-sm">
            No subjects — this relation/permission resolves to an empty set.
          </p>
        </div>
      ) : null}

      {raw ? (
        <div className="space-y-2">
          <Label>Subject tree</Label>
          <MonacoEditor
            language="json"
            value={raw}
            onChange={() => {}}
            readOnly
            height={320}
            ariaLabel="Subject tree (read-only)"
          />
        </div>
      ) : null}
    </div>
  );
}

export default function CheckExpandPage() {
  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Check &amp; Expand</h1>
        <p className="text-sm text-muted-foreground">
          Check whether a subject has a permission, or expand a permission to see
          the full subject tree. Queries are read-only and change nothing.
        </p>
      </div>

      <Tabs defaultValue="check">
        <TabsList>
          <TabsTrigger value="check">Check</TabsTrigger>
          <TabsTrigger value="expand">Expand</TabsTrigger>
        </TabsList>
        <TabsContent value="check" className="pt-4">
          <CheckTab />
        </TabsContent>
        <TabsContent value="expand" className="pt-4">
          <ExpandTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function Field({
  id,
  label,
  placeholder,
  value,
  onChange,
}: {
  id: string;
  label: string;
  placeholder: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        className="font-mono text-xs"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}
