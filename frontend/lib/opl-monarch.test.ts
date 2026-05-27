import { describe, expect, it } from "vitest";

import {
  OPL_LANGUAGE_ID,
  oplMonarchLanguage,
  registerOpl,
  tokenizeOpl,
} from "./opl-monarch";

// Unit coverage for the ory-opl Monarch grammar (PERM-04, Plan 18-01).
//
// We do NOT boot a real Monaco runtime (the editor + AMD loader + workers are
// proven offline by FE-04; jsdom cannot host them). Instead we exercise the
// IMonarchLanguage data object through a tiny line-tokenizer harness
// (`tokenizeOpl`) that walks the grammar's own `tokenizer.root` rules the same
// way Monaco's Monarch engine does for a single state — enough to assert that
// the REAL OPL surface (keywords, Ory types, members, operators, comments,
// strings, numbers) maps to the expected DISTINCT token classes, not a soup.

// The representative OPL source from the plan <interfaces> block — the grammar
// must color THESE tokens.
const SAMPLE = [
  'import { Namespace, SubjectSet, Context } from "@ory/keto-namespace-types"',
  "// a relation comment",
  "class Group implements Namespace {",
  "  related: { members: User[] }",
  "}",
  "class Document implements Namespace {",
  "  /* block comment */",
  "  related: { owners: User[]; editors: (User | Group)[] }",
  "  permits = {",
  "    view: (ctx: Context): boolean =>",
  "      this.related.owners.includes(ctx.subject) ||",
  "      this.related.editors.includes(ctx.subject),",
  "  }",
  "}",
].join("\n");

// Flatten every (token-class) emitted across all lines, keeping the matched text.
function classify(source: string): { text: string; token: string }[] {
  return source
    .split("\n")
    .flatMap((line) => tokenizeOpl(line))
    .filter((t) => t.text.trim().length > 0 || t.token.startsWith("comment"));
}

function tokensFor(source: string, text: string): string[] {
  return classify(source)
    .filter((t) => t.text === text)
    .map((t) => t.token);
}

describe("ory-opl Monarch grammar", () => {
  it("exposes a stable language id", () => {
    expect(OPL_LANGUAGE_ID).toBe("ory-opl");
  });

  it("declares the OPL keyword and Ory-type surfaces", () => {
    expect(oplMonarchLanguage.keywords).toContain("class");
    expect(oplMonarchLanguage.keywords).toContain("implements");
    expect(oplMonarchLanguage.keywords).toContain("import");
    expect(oplMonarchLanguage.keywords).toContain("this");
    expect(oplMonarchLanguage.typeKeywords).toContain("Namespace");
    expect(oplMonarchLanguage.typeKeywords).toContain("SubjectSet");
    expect(oplMonarchLanguage.typeKeywords).toContain("Context");
  });

  it("tokenizes a keyword (class) as a keyword class", () => {
    expect(tokensFor(SAMPLE, "class")).toContain("keyword");
    expect(tokensFor(SAMPLE, "implements")).toContain("keyword");
    expect(tokensFor(SAMPLE, "import")).toContain("keyword");
  });

  it("tokenizes an Ory type (Namespace) distinctly from a keyword", () => {
    const nsTokens = tokensFor(SAMPLE, "Namespace");
    expect(nsTokens).toContain("type");
    expect(nsTokens).not.toContain("keyword");
    expect(tokensFor(SAMPLE, "Context")).toContain("type");
  });

  it("tokenizes line and block comments as a comment class", () => {
    const tokens = classify(SAMPLE);
    expect(tokens.some((t) => t.token.startsWith("comment"))).toBe(true);
    // both a // line comment and a /* block */ comment are present in SAMPLE
    const commentText = tokens
      .filter((t) => t.token.startsWith("comment"))
      .map((t) => t.text)
      .join("");
    expect(commentText).toContain("relation comment");
    expect(commentText).toContain("block comment");
  });

  it("tokenizes a double-quoted string as a string class", () => {
    const tokens = classify(SAMPLE);
    expect(tokens.some((t) => t.token.startsWith("string"))).toBe(true);
  });

  it("tokenizes operators/delimiters, not as identifiers", () => {
    // => and || appear in the permits arrow body; assert they are operators.
    const tokens = classify(SAMPLE);
    const arrow = tokens.find((t) => t.text === "=>");
    expect(arrow?.token).toMatch(/operator|delimiter/);
    const or = tokens.find((t) => t.text === "||");
    expect(or?.token).toMatch(/operator|delimiter/);
  });

  it("tokenizes a number as a number class", () => {
    expect(tokensFor("const max = 42", "42")).toContain("number");
  });

  it("registerOpl is idempotent and wires register + token provider + themes", () => {
    const calls = {
      register: [] as { id: string }[],
      provider: [] as string[],
      themes: [] as string[],
      languages: [] as { id: string }[],
    };
    const monaco = {
      languages: {
        getLanguages: () => calls.languages,
        register: (def: { id: string }) => {
          calls.register.push(def);
          calls.languages.push(def);
        },
        setMonarchTokensProvider: (id: string) => {
          calls.provider.push(id);
        },
      },
      editor: {
        defineTheme: (name: string) => {
          calls.themes.push(name);
        },
      },
    };

    registerOpl(monaco as never);
    registerOpl(monaco as never); // second call must be a no-op (guarded)

    expect(calls.register).toHaveLength(1);
    expect(calls.register[0].id).toBe(OPL_LANGUAGE_ID);
    expect(calls.provider).toEqual([OPL_LANGUAGE_ID]);
    expect(calls.themes).toContain("ory-opl-light");
    expect(calls.themes).toContain("ory-opl-dark");
  });

  it("uses no CDN/network reference in the grammar module surface", () => {
    // The grammar is a pure data object; assert it carries no http(s) host.
    const serialized = JSON.stringify(oplMonarchLanguage);
    expect(serialized).not.toMatch(/https?:\/\//);
  });
});
