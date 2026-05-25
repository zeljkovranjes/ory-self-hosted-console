import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DataTable } from "./data-table";
import type { FetchArgs, FetchResult } from "@/lib/table-types";

// Component test for the FE-02 reusable server-side DataTable. We do NOT hit a
// real backend: a mock `fetcher` stands in for the lib/api.ts list call so we
// can assert the CONTRACT — that page/sort/filter changes call the fetcher with
// the correct MANUAL params, that rowCount drives pageCount (Next disabled on
// the last page), and that the loading / empty / error states render.

type Row = { id: string; name: string };

const columns: ColumnDef<Row>[] = [
  { accessorKey: "id", header: "ID" },
  { accessorKey: "name", header: "Name", enableSorting: true },
];

function makeRows(n: number, prefix = "r"): Row[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `${prefix}${i}`,
    name: `Name ${prefix}${i}`,
  }));
}

type RowFetcher = (args: FetchArgs) => Promise<FetchResult<Row>>;

/** Typed mock fetcher so `.mock.calls[i][0]` is `FetchArgs`, not `unknown`. */
function mockFetcher(impl: RowFetcher) {
  return vi.fn<RowFetcher>(impl);
}

function renderTable(
  fetcher: (args: FetchArgs) => Promise<FetchResult<Row>>,
  extra: Record<string, unknown> = {},
) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <DataTable
        columns={columns}
        fetcher={fetcher}
        queryKey="rows"
        searchPlaceholder="Search"
        {...extra}
      />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("DataTable (FE-02) — server-side", () => {
  it("calls the fetcher with initial manual params and renders rows", async () => {
    const fetcher = mockFetcher(async () => ({ rows: makeRows(3), total: 3 }));
    renderTable(fetcher);

    await waitFor(() =>
      expect(screen.getByText("Name r0")).toBeInTheDocument(),
    );
    expect(fetcher).toHaveBeenCalled();
    const args = fetcher.mock.calls[0][0];
    expect(args.pageIndex).toBe(0);
    expect(args.pageSize).toBeGreaterThan(0);
    expect(args.sorting).toEqual([]);
    expect(args.filters).toEqual([]);
  });

  it("Next calls the fetcher with the incremented pageIndex (same pageSize)", async () => {
    // total=30 over default pageSize=10 → 3 pages, so Next is enabled on page 0.
    const fetcher = mockFetcher(async ({ pageIndex }) => ({
      rows: makeRows(10, `p${pageIndex}-`),
      total: 30,
    }));
    renderTable(fetcher);

    await waitFor(() =>
      expect(screen.getByText("Name p0-0")).toBeInTheDocument(),
    );
    const initialPageSize = (fetcher.mock.calls[0][0] as FetchArgs).pageSize;

    await userEvent.click(screen.getByRole("button", { name: /next/i }));

    await waitFor(() => {
      const last = fetcher.mock.calls.at(-1)![0] as FetchArgs;
      expect(last.pageIndex).toBe(1);
      expect(last.pageSize).toBe(initialPageSize);
    });
  });

  it("rowCount drives pageCount → Next disabled on the last page", async () => {
    // total=5 over default pageSize=10 → a single page, Next disabled.
    const fetcher = vi.fn(async () => ({ rows: makeRows(5), total: 5 }));
    renderTable(fetcher);

    await waitFor(() =>
      expect(screen.getByText("Name r0")).toBeInTheDocument(),
    );
    expect(screen.getByRole("button", { name: /next/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /prev/i })).toBeDisabled();
  });

  it("sorting a column calls the fetcher with the new sorting state", async () => {
    const fetcher = mockFetcher(async () => ({ rows: makeRows(3), total: 3 }));
    renderTable(fetcher);
    await waitFor(() =>
      expect(screen.getByText("Name r0")).toBeInTheDocument(),
    );

    // The "Name" header is a sort toggle (column has enableSorting).
    await userEvent.click(screen.getByRole("button", { name: /name/i }));

    await waitFor(() => {
      const last = fetcher.mock.calls.at(-1)![0];
      expect(last.sorting.length).toBe(1);
      expect(last.sorting[0]).toMatchObject({ id: "name" });
    });
  });

  it("typing in the search box calls the fetcher with a new filter", async () => {
    const fetcher = mockFetcher(async () => ({ rows: makeRows(3), total: 3 }));
    renderTable(fetcher, { searchColumn: "name" });
    await waitFor(() =>
      expect(screen.getByText("Name r0")).toBeInTheDocument(),
    );

    await userEvent.type(
      screen.getByPlaceholderText("Search"),
      "alice",
    );

    await waitFor(() => {
      const last = fetcher.mock.calls.at(-1)![0];
      expect(last.filters.some((f) => f.id === "name" && f.value === "alice")).toBe(
        true,
      );
    });
  });

  it("renders skeleton rows while loading", async () => {
    let resolve!: (v: FetchResult<Row>) => void;
    const fetcher = vi.fn(
      () => new Promise<FetchResult<Row>>((r) => (resolve = r)),
    );
    const { container } = renderTable(fetcher);

    // Before the promise resolves, skeleton placeholders are present.
    await waitFor(() =>
      expect(
        container.querySelectorAll('[data-slot="skeleton"]').length,
      ).toBeGreaterThan(0),
    );
    resolve({ rows: makeRows(1), total: 1 });
    await waitFor(() =>
      expect(screen.getByText("Name r0")).toBeInTheDocument(),
    );
  });

  it("renders an empty state when there are no rows", async () => {
    const fetcher = vi.fn(async () => ({ rows: [], total: 0 }));
    renderTable(fetcher);
    expect(await screen.findByText(/no results/i)).toBeInTheDocument();
  });

  it("renders an error Alert with a retry control that refetches", async () => {
    const fetcher = vi
      .fn<(args: FetchArgs) => Promise<FetchResult<Row>>>()
      .mockRejectedValueOnce(new Error("boom"))
      .mockResolvedValueOnce({ rows: makeRows(2), total: 2 });
    renderTable(fetcher);

    const alert = await screen.findByRole("alert");
    expect(alert).toBeInTheDocument();
    const retry = within(alert).getByRole("button", { name: /retry/i });
    await userEvent.click(retry);

    await waitFor(() =>
      expect(screen.getByText("Name r0")).toBeInTheDocument(),
    );
  });

  it("marks sortable headers with scope=col and aria-sort", async () => {
    const fetcher = vi.fn(async () => ({ rows: makeRows(2), total: 2 }));
    renderTable(fetcher);
    await waitFor(() =>
      expect(screen.getByText("Name r0")).toBeInTheDocument(),
    );

    const headers = screen.getAllByRole("columnheader");
    expect(headers.length).toBeGreaterThan(0);
    for (const h of headers) {
      expect(h).toHaveAttribute("scope", "col");
    }
    // The sortable Name header advertises its sort state.
    const nameHeader = headers.find((h) => /name/i.test(h.textContent ?? ""));
    expect(nameHeader).toHaveAttribute("aria-sort");
  });

  it("renders a row-action slot per row when provided", async () => {
    const fetcher = vi.fn(async () => ({ rows: makeRows(2), total: 2 }));
    renderTable(fetcher, {
      rowActions: (row: Row) => (
        <button type="button">Edit {row.id}</button>
      ),
    });
    await waitFor(() =>
      expect(screen.getByText("Name r0")).toBeInTheDocument(),
    );
    expect(
      screen.getByRole("button", { name: "Edit r0" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Edit r1" }),
    ).toBeInTheDocument();
  });
});
