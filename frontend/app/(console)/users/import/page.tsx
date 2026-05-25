"use client";

// IDENT-04 — the bulk-import page (/users/import, UI-SPEC §5).
//
// Flow: paste OR upload a bare-array JSON -> Validate (client-side shape +
// 1000/200 limit mirror via lib/cli-identity) -> Import (POST the SAME bare array
// the `ory` CLI consumes) -> per-record result table. A backend 422 (the
// AUTHORITATIVE limit) is surfaced explicitly; nothing is ever silent.
//
// Export pages the identities list (following the keyset `next_token` to
// completion), maps to the bare CLI shape (toExportArray strips credential
// secrets, T-06-32), and triggers a client-side download — substantiating the
// CLI-interchange claim.
//
// All egress is via lib/api.ts (`/backend`); no Ory host/SDK literal (T-06-33).

import * as React from "react";

import { api, ApiError } from "@/lib/api";
import {
  CLEARTEXT_LIMIT,
  HASHED_LIMIT,
  checkLimits,
  parseImportArray,
  toExportArray,
  type CliIdentity,
} from "@/lib/cli-identity";
import type { Identity, IdentityListResponse } from "../identity-types";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2Icon, CircleAlertIcon, DownloadIcon } from "lucide-react";

const EXPORT_PAGE_SIZE = 200;

/** A single per-record outcome from the backend import response. */
type ImportRecordResult = {
  action?: string;
  identity?: { id?: string };
  error?: { message?: string; status?: string };
};

type ImportResponse = { results?: ImportRecordResult[] } | undefined;

type Validation =
  | { kind: "none" }
  | { kind: "error"; message: string }
  | {
      kind: "ok";
      records: CliIdentity[];
      cleartext: boolean;
      violations: string[];
    };

export default function ImportPage() {
  const [text, setText] = React.useState("");
  const [validation, setValidation] = React.useState<Validation>({
    kind: "none",
  });
  const [results, setResults] = React.useState<ImportRecordResult[] | null>(
    null,
  );
  const [importError, setImportError] = React.useState<string | null>(null);
  const [importing, setImporting] = React.useState(false);
  const [exporting, setExporting] = React.useState(false);
  const [exportError, setExportError] = React.useState<string | null>(null);

  function onValidate() {
    setResults(null);
    setImportError(null);
    const parsed = parseImportArray(text);
    if ("error" in parsed) {
      setValidation({ kind: "error", message: parsed.error });
      return;
    }
    const limit = checkLimits(parsed.records);
    const cleartext = parsed.records.some((r) => {
      const creds = r.credentials as Record<string, unknown> | undefined;
      const pw = creds?.password as Record<string, unknown> | undefined;
      const config = pw?.config as Record<string, unknown> | undefined;
      return typeof config?.password === "string";
    });
    setValidation({
      kind: "ok",
      records: parsed.records,
      cleartext,
      violations: limit.violations,
    });
  }

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const content = await file.text();
    setText(content);
    setValidation({ kind: "none" });
    setResults(null);
    setImportError(null);
  }

  const canImport =
    validation.kind === "ok" && validation.violations.length === 0;

  async function onImport() {
    if (validation.kind !== "ok") return;
    setImporting(true);
    setImportError(null);
    setResults(null);
    try {
      const res = await api<ImportResponse>("/api/kratos/identities/import", {
        method: "POST",
        body: JSON.stringify(validation.records),
      });
      setResults(res?.results ?? []);
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) {
        const msg =
          e.fieldErrors.map((f) => f.message).join("; ") ||
          "The import was rejected by the server (limit exceeded).";
        setImportError(msg);
      } else if (e instanceof ApiError) {
        setImportError(`Import failed (status ${e.status}).`);
      } else {
        setImportError("Import failed due to an unexpected error.");
      }
    } finally {
      setImporting(false);
    }
  }

  async function onExport() {
    setExporting(true);
    setExportError(null);
    try {
      const all: Identity[] = [];
      let token: string | null = null;
      // Page through the keyset cursor to completion.
      // Guard against an unbounded loop with a generous page ceiling.
      for (let page = 0; page < 10000; page++) {
        const qp = new URLSearchParams();
        qp.set("page_size", String(EXPORT_PAGE_SIZE));
        if (token) qp.set("page_token", token);
        const res: IdentityListResponse = await api<IdentityListResponse>(
          `/api/kratos/identities?${qp.toString()}`,
        );
        all.push(...res.rows);
        if (!res.next_token) break;
        token = res.next_token;
      }

      const exported = toExportArray(all);
      const blob = new Blob([JSON.stringify(exported, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "identities.json";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch {
      setExportError("Could not export identities.");
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Import users</h1>
        <p className="text-sm text-muted-foreground">
          Bulk-import Kratos identities from a JSON array. Validate before
          importing; the server enforces the same limits.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Import identities</CardTitle>
          <CardDescription>
            Paste or upload a JSON array. Format is interchangeable with the{" "}
            <code>ory</code> CLI (<code>ory import identities</code>). Limits:
            up to {HASHED_LIMIT} records, or {CLEARTEXT_LIMIT} when any record
            includes a cleartext password.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-4 pt-4">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="import-json">Paste identities JSON</Label>
            <Textarea
              id="import-json"
              aria-label="Paste identities JSON"
              value={text}
              onChange={(e) => {
                setText(e.target.value);
                setValidation({ kind: "none" });
              }}
              rows={12}
              className="font-mono text-xs"
              placeholder='[{"schema_id":"default","traits":{"email":"a@example.com"}}]'
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <input
              type="file"
              accept="application/json,.json"
              aria-label="Upload identities JSON file"
              onChange={onFile}
              className="text-sm"
            />
          </div>

          {validation.kind === "error" ? (
            <Alert role="alert" variant="destructive">
              <CircleAlertIcon />
              <AlertTitle>Invalid payload</AlertTitle>
              <AlertDescription>{validation.message}</AlertDescription>
            </Alert>
          ) : null}

          {validation.kind === "ok" ? (
            <Alert
              role={validation.violations.length > 0 ? "alert" : "status"}
              variant={
                validation.violations.length > 0 ? "destructive" : "default"
              }
              aria-live="polite"
            >
              {validation.violations.length > 0 ? (
                <CircleAlertIcon />
              ) : (
                <CheckCircle2Icon className="text-success" />
              )}
              <AlertTitle>
                {validation.records.length} records
                {validation.cleartext ? " (cleartext passwords detected)" : ""}
              </AlertTitle>
              <AlertDescription>
                {validation.violations.length > 0 ? (
                  <ul className="list-disc pl-5">
                    {validation.violations.map((v, i) => (
                      <li key={i}>{v}</li>
                    ))}
                  </ul>
                ) : (
                  "Payload looks valid. Click Import to create these identities."
                )}
              </AlertDescription>
            </Alert>
          ) : null}

          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" variant="outline" onClick={onValidate}>
              Validate
            </Button>
            <Button
              type="button"
              onClick={onImport}
              disabled={!canImport || importing}
            >
              {importing ? "Importing…" : "Import"}
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={onExport}
              disabled={exporting}
            >
              <DownloadIcon />
              {exporting ? "Exporting…" : "Export"}
            </Button>
          </div>

          {exportError ? (
            <Alert role="alert" variant="destructive">
              <CircleAlertIcon />
              <AlertTitle>Export failed</AlertTitle>
              <AlertDescription>{exportError}</AlertDescription>
            </Alert>
          ) : null}

          {importError ? (
            <Alert role="alert" variant="destructive">
              <CircleAlertIcon />
              <AlertTitle>Import rejected</AlertTitle>
              <AlertDescription>{importError}</AlertDescription>
            </Alert>
          ) : null}

          {results ? (
            <div className="space-y-2">
              <h2 className="text-sm font-medium">Import results</h2>
              {results.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No records processed.
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-12">#</TableHead>
                        <TableHead>Outcome</TableHead>
                        <TableHead>Detail</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {results.map((r, i) => {
                        const isError = !!r.error;
                        return (
                          <TableRow key={i}>
                            <TableCell className="font-mono text-xs">
                              {i + 1}
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant={isError ? "destructive" : "default"}
                              >
                                {isError ? "error" : (r.action ?? "ok")}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-sm break-words">
                              {isError
                                ? (r.error?.message ?? "Failed")
                                : (r.identity?.id ?? "Created")}
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </div>
              )}
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
