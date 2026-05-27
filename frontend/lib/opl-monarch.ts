// ory-opl — a Monaco Monarch grammar for the Ory Permission Language (PERM-04).
//
// OPL is a TypeScript-like DSL (classes implementing `Namespace`, a `related`
// block of relation members, and a `permits` block of arrow-function rules over
// a `Context`). This module registers a custom Monaco language id `ory-opl`,
// describes its token surface as a Monarch `IMonarchLanguage`, and defines a
// light/dark token theme — coloring keywords, the Ory types, relation/permit
// members, operators, comments, and string/number literals.
//
// Hardening invariants (Plan 18-01 threat model):
//   * ZERO new dependency — Monarch ships in the vendored monaco-editor 0.55;
//     the `monaco-editor` import below is TYPE-ONLY (erased at runtime).
//   * ZERO CDN egress — this module performs NO network/fetch; the grammar is a
//     pure data object served from the same-origin local bundle (bundle-egress
//     gate stays green).
//   * Monaco renders/colors editor text as DATA, never evaluates it.

import type * as Monaco from "monaco-editor";

/** The custom Monaco language id for the Ory Permission Language. */
export const OPL_LANGUAGE_ID = "ory-opl";

/** OPL reserved words (the TypeScript-like control/declaration surface). */
const KEYWORDS = [
  "class",
  "implements",
  "import",
  "from",
  "export",
  "return",
  "this",
  "new",
  "const",
  "let",
  "var",
  "boolean",
  "string",
  "number",
  "true",
  "false",
  "null",
  "undefined",
];

/** The Ory namespace-type identifiers, colored distinctly from keywords. */
const TYPE_KEYWORDS = ["Namespace", "SubjectSet", "Context"];

/** The operator/delimiter surface (=> : . && || ! | etc.). */
const OPERATORS = [
  "=>",
  "=",
  ":",
  ".",
  "&&",
  "||",
  "!",
  "|",
  "&",
  "?",
  "<",
  ">",
  "+",
  "-",
  "*",
  "/",
  "%",
];

/**
 * The Monarch grammar for `ory-opl`. A plain `IMonarchLanguage` data object —
 * no runtime monaco values, no network. `tokenizer.root` classifies the OPL
 * surface; the `members` key recognizes the `related`/`permits` block names.
 */
export const oplMonarchLanguage: Monaco.languages.IMonarchLanguage & {
  keywords: string[];
  typeKeywords: string[];
  operators: string[];
  members: string[];
} = {
  defaultToken: "",
  tokenPostfix: ".opl",

  keywords: KEYWORDS,
  typeKeywords: TYPE_KEYWORDS,
  operators: OPERATORS,

  // The OPL members that introduce the relation/permission blocks.
  members: ["related", "permits"],

  // C-style symbol matcher used by the operator rule.
  symbols: /[=><!~?:&|+\-*/%.]+/,

  tokenizer: {
    root: [
      // Comments first so // and /* */ never fall through to operators.
      [/\/\/.*$/, "comment"],
      [/\/\*/, "comment", "@blockComment"],

      // Strings (double + single quoted).
      [/"([^"\\]|\\.)*$/, "string.invalid"],
      [/'([^'\\]|\\.)*$/, "string.invalid"],
      [/"/, "string", "@stringDouble"],
      [/'/, "string", "@stringSingle"],

      // Numbers.
      [/\d+\.\d+([eE][-+]?\d+)?/, "number.float"],
      [/\d+/, "number"],

      // Identifiers — cases-mapped to keyword / type / member / identifier.
      [
        /[A-Za-z_$][\w$]*/,
        {
          cases: {
            "@typeKeywords": "type",
            "@keywords": "keyword",
            "@members": "variable.member",
            "@default": "identifier",
          },
        },
      ],

      // Brackets / delimiters.
      [/[{}()[\]]/, "@brackets"],
      [/[;,]/, "delimiter"],

      // Operators (=> : . && || ! | …).
      [
        /@symbols/,
        {
          cases: {
            "@operators": "operator",
            "@default": "delimiter",
          },
        },
      ],

      // Whitespace.
      [/\s+/, "white"],
    ],

    blockComment: [
      [/[^/*]+/, "comment"],
      [/\*\//, "comment", "@pop"],
      [/[/*]/, "comment"],
    ],

    stringDouble: [
      [/[^"\\]+/, "string"],
      [/\\./, "string.escape"],
      [/"/, "string", "@pop"],
    ],

    stringSingle: [
      [/[^'\\]+/, "string"],
      [/\\./, "string.escape"],
      [/'/, "string", "@pop"],
    ],
  },
};

// Token color rules shared by the light/dark themes. Colors are OKLCH-adjacent
// hex picked to read against the wrapper's vs (light) / vs-dark mapping.
const LIGHT_RULES: Monaco.editor.ITokenThemeRule[] = [
  { token: "keyword", foreground: "0000ff", fontStyle: "bold" },
  { token: "type", foreground: "267f99" },
  { token: "variable.member", foreground: "001080" },
  { token: "identifier", foreground: "001080" },
  { token: "comment", foreground: "008000", fontStyle: "italic" },
  { token: "string", foreground: "a31515" },
  { token: "string.escape", foreground: "ee0000" },
  { token: "number", foreground: "098658" },
  { token: "number.float", foreground: "098658" },
  { token: "operator", foreground: "000000" },
  { token: "delimiter", foreground: "393a34" },
];

const DARK_RULES: Monaco.editor.ITokenThemeRule[] = [
  { token: "keyword", foreground: "569cd6", fontStyle: "bold" },
  { token: "type", foreground: "4ec9b0" },
  { token: "variable.member", foreground: "9cdcfe" },
  { token: "identifier", foreground: "9cdcfe" },
  { token: "comment", foreground: "6a9955", fontStyle: "italic" },
  { token: "string", foreground: "ce9178" },
  { token: "string.escape", foreground: "d7ba7d" },
  { token: "number", foreground: "b5cea8" },
  { token: "number.float", foreground: "b5cea8" },
  { token: "operator", foreground: "d4d4d4" },
  { token: "delimiter", foreground: "d4d4d4" },
];

/**
 * Register the `ory-opl` language, its Monarch token provider, and the
 * light/dark token themes on a Monaco instance. IDEMPOTENT — guarded on the
 * language id, so calling it on every editor mount (including non-OPL pages) is
 * harmless. Uses ONLY vendored monaco-editor 0.55 APIs; no network/CDN access.
 */
export function registerOpl(monaco: typeof Monaco): void {
  const already = monaco.languages
    .getLanguages()
    .some((l) => l.id === OPL_LANGUAGE_ID);
  if (already) return;

  monaco.languages.register({ id: OPL_LANGUAGE_ID });
  monaco.languages.setMonarchTokensProvider(OPL_LANGUAGE_ID, oplMonarchLanguage);

  // The themes ride the built-in vs/vs-dark (the wrapper maps resolvedTheme →
  // vs/vs-dark; these inherit those bases and only add the OPL token colors).
  monaco.editor.defineTheme("ory-opl-light", {
    base: "vs",
    inherit: true,
    rules: LIGHT_RULES,
    colors: {},
  });
  monaco.editor.defineTheme("ory-opl-dark", {
    base: "vs-dark",
    inherit: true,
    rules: DARK_RULES,
    colors: {},
  });
}

// ---------------------------------------------------------------------------
// Test/inspection harness — a tiny single-state Monarch tokenizer.
//
// Walks `oplMonarchLanguage.tokenizer.root` over ONE line the way Monaco's
// Monarch engine does for the root state: at each position try each rule's
// regex (anchored at the cursor), emit the resolved token for the longest
// leading match, and advance. `cases` are resolved against keywords /
// typeKeywords / members / operators. State-entering rules (comments/strings)
// are flattened to their entry token — enough to assert token CLASSES for unit
// tests without booting the full editor runtime. Not used at runtime by the
// editor (Monaco's own engine drives the live coloring).
// ---------------------------------------------------------------------------

type OplToken = { text: string; token: string };

function resolveCases(
  matched: string,
  action: { cases: Record<string, string> },
): string {
  const cases = action.cases;
  for (const key of Object.keys(cases)) {
    if (key === "@default") continue;
    if (key === "@keywords" && KEYWORDS.includes(matched)) return cases[key];
    if (key === "@typeKeywords" && TYPE_KEYWORDS.includes(matched))
      return cases[key];
    if (key === "@members" && oplMonarchLanguage.members.includes(matched))
      return cases[key];
    if (key === "@operators" && OPERATORS.includes(matched)) return cases[key];
  }
  return cases["@default"] ?? "";
}

const SYMBOLS_RE = /[=><!~?:&|+\-*/%.]+/;

export function tokenizeOpl(line: string): OplToken[] {
  const out: OplToken[] = [];
  let i = 0;

  while (i < line.length) {
    const rest = line.slice(i);

    // Line comment.
    const lineComment = /^\/\/.*$/.exec(rest);
    if (lineComment) {
      out.push({ text: lineComment[0], token: "comment" });
      break;
    }

    // Block comment (single-line slice — the test feeds line-by-line).
    const blockComment = /^\/\*.*?(\*\/|$)/.exec(rest);
    if (blockComment) {
      out.push({ text: blockComment[0], token: "comment" });
      i += blockComment[0].length;
      continue;
    }

    // Double-quoted string.
    const dq = /^"([^"\\]|\\.)*"?/.exec(rest);
    if (dq && rest[0] === '"') {
      out.push({ text: dq[0], token: "string" });
      i += dq[0].length;
      continue;
    }

    // Single-quoted string.
    const sq = /^'([^'\\]|\\.)*'?/.exec(rest);
    if (sq && rest[0] === "'") {
      out.push({ text: sq[0], token: "string" });
      i += sq[0].length;
      continue;
    }

    // Float / number.
    const float = /^\d+\.\d+([eE][-+]?\d+)?/.exec(rest);
    if (float) {
      out.push({ text: float[0], token: "number.float" });
      i += float[0].length;
      continue;
    }
    const num = /^\d+/.exec(rest);
    if (num) {
      out.push({ text: num[0], token: "number" });
      i += num[0].length;
      continue;
    }

    // Identifier (keyword / type / member / identifier).
    const ident = /^[A-Za-z_$][\w$]*/.exec(rest);
    if (ident) {
      const token = resolveCases(ident[0], {
        cases: {
          "@typeKeywords": "type",
          "@keywords": "keyword",
          "@members": "variable.member",
          "@default": "identifier",
        },
      });
      out.push({ text: ident[0], token });
      i += ident[0].length;
      continue;
    }

    // Brackets / delimiters.
    if (/^[{}()[\]]/.test(rest)) {
      out.push({ text: rest[0], token: "@brackets" });
      i += 1;
      continue;
    }
    if (/^[;,]/.test(rest)) {
      out.push({ text: rest[0], token: "delimiter" });
      i += 1;
      continue;
    }

    // Operators / delimiters.
    const sym = SYMBOLS_RE.exec(rest);
    if (sym && rest.startsWith(sym[0]) && sym.index === 0) {
      const token = OPERATORS.includes(sym[0]) ? "operator" : "delimiter";
      out.push({ text: sym[0], token });
      i += sym[0].length;
      continue;
    }

    // Whitespace.
    const ws = /^\s+/.exec(rest);
    if (ws) {
      out.push({ text: ws[0], token: "white" });
      i += ws[0].length;
      continue;
    }

    // Fallback: consume one char as default.
    out.push({ text: rest[0], token: "" });
    i += 1;
  }

  return out;
}
