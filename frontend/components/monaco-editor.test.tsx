import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

// Component test for the FE-04 MonacoEditor wrapper. We do NOT boot a real
// Monaco runtime (that is proven offline in Task 1's spike + the 05-07 live
// check). Instead we mock the heavy @monaco-editor/react `Editor` with a tiny
// <textarea> stand-in so we can assert the wrapper's CONTRACT under jsdom:
// it mounts client-only, honors the `language` prop, is controlled (onChange
// fires with the new value), and threads height/readOnly through.

// --- Mock next-themes: the wrapper reads resolvedTheme to pick vs/vs-dark. ---
const useThemeMock = vi.fn(() => ({ resolvedTheme: "light" }));
vi.mock("next-themes", () => ({
  useTheme: () => useThemeMock(),
}));

// --- Mock next/dynamic: run the loader synchronously and render the result, so
//     the (otherwise async, ssr:false) import resolves deterministically in the
//     test. This also exercises the wrapper's loader (which calls setupMonaco). ---
vi.mock("next/dynamic", () => ({
  default: (
    loader: () => Promise<React.ComponentType<EditorMockProps>>,
    _opts?: unknown,
  ) => {
    const Lazy = (props: EditorMockProps) => {
      const [Comp, setComp] = (
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        require("react") as typeof import("react")
      ).useState<React.ComponentType<EditorMockProps> | null>(null);
      (require("react") as typeof import("react")).useEffect(() => {
        let active = true;
        void loader().then((c) => {
          if (active) setComp(() => c);
        });
        return () => {
          active = false;
        };
      }, []);
      return Comp ? <Comp {...props} /> : null;
    };
    return Lazy;
  },
}));

// --- Mock the heavy editor with a controlled <textarea> capturing the props. ---
type EditorMockProps = {
  language?: string;
  value?: string;
  theme?: string;
  options?: { readOnly?: boolean };
  onChange?: (v: string | undefined) => void;
  beforeMount?: (monaco: unknown) => void;
};

const setDiagnosticsOptions = vi.fn();

vi.mock("@monaco-editor/react", () => ({
  Editor: (props: EditorMockProps) => {
    // Exercise beforeMount with a minimal monaco shim so the JSON-schema hook
    // path is covered when a schema is supplied.
    props.beforeMount?.({
      languages: { json: { jsonDefaults: { setDiagnosticsOptions } } },
    });
    return (
      <textarea
        data-testid="monaco-mock"
        data-language={props.language}
        data-theme={props.theme}
        readOnly={props.options?.readOnly}
        value={props.value ?? ""}
        onChange={(e) => props.onChange?.(e.target.value)}
      />
    );
  },
  loader: { config: vi.fn() },
}));

// setupMonaco is a no-op under jsdom (no window loader) but the wrapper calls
// it; stub it so the dynamic loader resolves without touching the real loader.
vi.mock("@/lib/monaco-setup", () => ({
  setupMonaco: vi.fn(),
  monacoVsPath: "/monaco/vs",
}));

import { MonacoEditor } from "./monaco-editor";

afterEach(() => {
  vi.clearAllMocks();
  useThemeMock.mockReturnValue({ resolvedTheme: "light" });
});

describe("MonacoEditor wrapper (FE-04)", () => {
  it("mounts client-only and renders the editor", async () => {
    render(<MonacoEditor language="json" value="{}" onChange={() => {}} />);
    expect(await screen.findByTestId("monaco-mock")).toBeInTheDocument();
  });

  it("honors the language prop", async () => {
    render(
      <MonacoEditor language="yaml" value="a: 1" onChange={() => {}} />,
    );
    const ed = await screen.findByTestId("monaco-mock");
    expect(ed).toHaveAttribute("data-language", "yaml");
  });

  it("is controlled: renders value and fires onChange with the new value", async () => {
    const onChange = vi.fn();
    render(
      <MonacoEditor language="plaintext" value="hello" onChange={onChange} />,
    );
    const ed = (await screen.findByTestId("monaco-mock")) as HTMLTextAreaElement;
    expect(ed.value).toBe("hello");

    await userEvent.type(ed, "!");
    expect(onChange).toHaveBeenCalled();
    // The mock textarea echoes a single change event carrying the edited value.
    expect(onChange.mock.calls.at(-1)?.[0]).toContain("hello");
  });

  it("threads readOnly through to the editor options", async () => {
    render(
      <MonacoEditor
        language="json"
        value="{}"
        onChange={() => {}}
        readOnly
      />,
    );
    const ed = (await screen.findByTestId("monaco-mock")) as HTMLTextAreaElement;
    expect(ed.readOnly).toBe(true);
  });

  it("applies the given height to the bordered container", async () => {
    const { container } = render(
      <MonacoEditor
        language="json"
        value="{}"
        onChange={() => {}}
        height={500}
      />,
    );
    await screen.findByTestId("monaco-mock");
    const group = container.querySelector('[role="group"]') as HTMLElement;
    expect(group.style.height).toBe("500px");
  });

  it("maps a dark app theme to Monaco's vs-dark", async () => {
    useThemeMock.mockReturnValue({ resolvedTheme: "dark" });
    render(<MonacoEditor language="json" value="{}" onChange={() => {}} />);
    const ed = await screen.findByTestId("monaco-mock");
    expect(ed).toHaveAttribute("data-theme", "vs-dark");
  });

  it("wires JSON-Schema diagnostics when jsonSchema is provided for json", async () => {
    const schema = { type: "object", required: ["traits"] };
    render(
      <MonacoEditor
        language="json"
        value="{}"
        onChange={() => {}}
        jsonSchema={schema}
      />,
    );
    await screen.findByTestId("monaco-mock");
    await waitFor(() => expect(setDiagnosticsOptions).toHaveBeenCalled());
    const arg = setDiagnosticsOptions.mock.calls.at(-1)?.[0];
    expect(arg.validate).toBe(true);
    expect(arg.schemas[0].schema).toEqual(schema);
  });

  it("does NOT wire JSON diagnostics for non-json languages", async () => {
    render(
      <MonacoEditor
        language="yaml"
        value="a: 1"
        onChange={() => {}}
        jsonSchema={{ type: "object" }}
      />,
    );
    await screen.findByTestId("monaco-mock");
    expect(setDiagnosticsOptions).not.toHaveBeenCalled();
  });

  it("exposes an accessible label for the editor region", async () => {
    render(
      <MonacoEditor
        language="json"
        value="{}"
        onChange={() => {}}
        ariaLabel="Identity schema"
      />,
    );
    await screen.findByTestId("monaco-mock");
    expect(
      screen.getByRole("group", { name: "Identity schema" }),
    ).toBeInTheDocument();
  });
});
