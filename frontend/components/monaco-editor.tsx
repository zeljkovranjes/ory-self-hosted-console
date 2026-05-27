"use client";

// MonacoEditor — the FE-04 reusable code/schema editor wrapper.
//
// Every editor-bearing feature page composes THIS component: identity-schema
// JSON (P6), Ory Permission Language (P9), service YAML (P7/P8), and email
// templates (P10). It exists so all of them share one hardened, themed,
// client-only Monaco mount with a JSON-Schema validation hook.
//
// Hardening / correctness invariants:
//   * CLIENT-ONLY: dynamically imported with `ssr:false` (threat T-05-13) — the
//     heavy editor never enters the server render path.
//   * NO CDN: `setupMonaco()` (lib/monaco-setup.ts) points the loader at our
//     same-origin /monaco/vs assets BEFORE the first mount, so the editor and
//     its language workers load with zero jsDelivr egress (threat T-05-11).
//   * CONTROLLED: `value` + `onChange` make it a controlled input; editor text
//     is data, never executed (threat T-05-12 — Monaco renders, never evals).
//   * THEMED: follows the app light/dark via next-themes (UI-SPEC §4).

import { useTheme } from "next-themes";
import dynamic from "next/dynamic";
import { useId, useMemo } from "react";
import type {
  BeforeMount,
  EditorProps,
  OnChange,
  OnMount,
} from "@monaco-editor/react";

import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import { setupMonaco } from "@/lib/monaco-setup";
import { registerOpl } from "@/lib/opl-monarch";

// Dynamically import the heavy editor with SSR disabled. The loader function
// also runs `setupMonaco()` so the local-bundle loader config is applied before
// `@monaco-editor/react` ever resolves Monaco — guaranteeing no CDN fetch even
// on the very first mount. A lightweight skeleton renders while it loads.
const Editor = dynamic(
  async () => {
    setupMonaco();
    const mod = await import("@monaco-editor/react");
    return mod.Editor;
  },
  {
    ssr: false,
    loading: () => (
      <div
        className="text-muted-foreground flex h-full w-full items-center justify-center text-sm"
        aria-hidden="true"
      >
        Loading editor…
      </div>
    ),
  },
);

/** The languages the console's editors use this phase. OPL rides on plaintext.
 *  `html` is used by the Phase-10 email-template HTML body editor (BRAND-01).
 *  `css` is used by the Phase-15 AX theming editor (AX-02) for the CSS-variable
 *  override — Monaco's built-in css language (syntax highlighting only; no
 *  network schema fetch).
 *  `ory-opl` is the custom Monarch language for the Ory Permission Language
 *  (PERM-04) — registered in beforeMount from the same-origin local bundle. */
export type MonacoLanguage =
  | "json"
  | "yaml"
  | "plaintext"
  | "html"
  | "css"
  | "ory-opl";

export interface MonacoEditorProps {
  /** Editor language mode. OPL (P9) uses "plaintext" until a token provider lands. */
  language: MonacoLanguage;
  /** Controlled editor content. */
  value: string;
  /** Called with the new content on every edit. */
  onChange: (value: string) => void;
  /** Editor height (number = px). Defaults to 320px — a sensible editor size. */
  height?: number | string;
  /** Render read-only (e.g. diff/preview surfaces). */
  readOnly?: boolean;
  /**
   * Optional JSON Schema (a parsed object) for in-editor diagnostics. When set
   * and `language === "json"`, invalid content shows red squiggles against this
   * schema — the identity-schema editing use case (P6).
   */
  jsonSchema?: object;
  /** Accessible label for the editor region (and the visible field label). */
  ariaLabel?: string;
  /** Optional extra classes on the bordered container. */
  className?: string;
  /**
   * Optional handle invoked once the editor mounts, with the editor + monaco
   * instances (the @monaco-editor/react `OnMount` signature). Callers use it to
   * drive `editor.setModelMarkers` for live diagnostics (the OPL live-validate
   * use case, Plan 18-02). When omitted the wrapper behaves exactly as before.
   */
  onMount?: OnMount;
}

/**
 * Reusable, client-only Monaco editor (FE-04). Controlled via `value`/`onChange`,
 * themed from next-themes, with an optional JSON-Schema validation hook.
 */
export function MonacoEditor({
  language,
  value,
  onChange,
  height = 320,
  readOnly = false,
  jsonSchema,
  ariaLabel,
  className,
  onMount,
}: MonacoEditorProps) {
  const { resolvedTheme } = useTheme();
  // Map the app theme onto Monaco's built-in themes. resolvedTheme accounts for
  // the "system" setting; default to light when undefined (pre-hydration).
  const monacoTheme = resolvedTheme === "dark" ? "vs-dark" : "light";

  const labelId = useId();

  // Before the editor mounts we ALWAYS register the `ory-opl` Monarch language
  // (idempotent — harmless for non-OPL pages; the language id is global to the
  // monaco instance), THEN — only for JSON with a schema — wire JSON-Schema
  // diagnostics. The two behaviors compose; neither suppresses the other. A
  // stable identity uri + fileMatch:["*"] applies the schema to the model.
  const beforeMount: BeforeMount = useMemo(() => {
    return (monaco) => {
      // (1) Register the OPL grammar from the same-origin bundle (no CDN, no
      //     new dependency). Idempotent, so safe on every mount.
      registerOpl(monaco);

      // (2) JSON-Schema diagnostics — unchanged; only meaningful for JSON.
      if (jsonSchema && language === "json") {
        monaco.languages.json.jsonDefaults.setDiagnosticsOptions({
          validate: true,
          // `enableSchemaRequest:false` keeps Monaco from fetching $ref'd
          // schemas over the network — reinforces no-egress (T-05-11).
          enableSchemaRequest: false,
          schemas: [
            {
              uri: "inmemory://schema/console-json-schema.json",
              fileMatch: ["*"],
              schema: jsonSchema,
            },
          ],
        });
      }
    };
  }, [jsonSchema, language]);

  const handleChange: OnChange = (next) => {
    onChange(next ?? "");
  };

  const options: EditorProps["options"] = useMemo(
    () => ({
      readOnly,
      minimap: { enabled: false },
      scrollBeyondLastLine: false,
      fontSize: 13,
      tabSize: 2,
      automaticLayout: true,
      // Editor is a data surface, not a code-runner; keep it focused.
      renderLineHighlight: "all" as const,
    }),
    [readOnly],
  );

  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      {ariaLabel ? <Label id={labelId}>{ariaLabel}</Label> : null}
      <div
        role="group"
        aria-label={ariaLabel}
        aria-labelledby={ariaLabel ? labelId : undefined}
        className="border-input overflow-hidden rounded-md border"
        style={{ height: typeof height === "number" ? `${height}px` : height }}
      >
        <Editor
          language={language}
          value={value}
          theme={monacoTheme}
          onChange={handleChange}
          beforeMount={beforeMount}
          onMount={onMount}
          options={options}
          height="100%"
          width="100%"
        />
      </div>
    </div>
  );
}

export default MonacoEditor;
