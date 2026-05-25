// Shared types for the FE-02 server-side DataTable.
//
// Feature list pages (P6 identities, P8 clients, P9 relationships, P10 sessions/
// courier) all compose `<DataTable>` and supply a `fetcher` that talks to the
// backend list endpoint through `lib/api.ts`. The table is headless and lifts
// pagination/sort/filter state; the fetcher owns the row math on the server.
//
// Phase-3 read endpoints currently return plain arrays (cursor pagination is a
// noted TODO). The `{ rows, total }` shape is forward-compatible: array-only
// backends return `total = rows.length` (server paging effectively a no-op)
// until counts/cursors land, with no DataTable API change required.

import type { ColumnFiltersState, SortingState } from "@tanstack/react-table";

/**
 * The arguments the {@link DataTable} hands its `fetcher` whenever the lifted
 * table state changes. `pageIndex` is zero-based (TanStack convention).
 */
export type FetchArgs = {
  pageIndex: number;
  pageSize: number;
  sorting: SortingState;
  filters: ColumnFiltersState;
};

/**
 * What a `fetcher` resolves with: the current page of `rows` plus the backend
 * `total` row count (drives `rowCount` → `pageCount`). For array-only backends,
 * set `total = rows.length`.
 */
export type FetchResult<T> = {
  rows: T[];
  total: number;
};

/** The fetcher prop signature for {@link DataTable}. */
export type Fetcher<T> = (args: FetchArgs) => Promise<FetchResult<T>>;
