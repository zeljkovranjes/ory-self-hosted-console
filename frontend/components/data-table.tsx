"use client";

// FE-02 — the one reusable server-side DataTable every feature list page
// (P6 identities, P8 clients, P9 relationships, P10 sessions/courier) composes.
//
// Design invariants (05-RESEARCH Pattern 4, UI-SPEC §2):
//   - TanStack Table v8 in MANUAL mode (manualPagination/manualSorting/
//     manualFiltering): the BACKEND owns the row math. The table only lifts
//     pagination/sorting/columnFilters state and renders. `getCoreRowModel`
//     ONLY — no client-side pagination/sort/filter row models.
//   - `rowCount={total}` so the table derives `pageCount = ceil(total/pageSize)`;
//     Next is disabled on the last page.
//   - `autoResetPageIndex: false` so a data refetch does not bounce pageIndex.
//   - Data fetched via TanStack Query keyed on the lifted state, calling the
//     caller-supplied `fetcher({pageIndex,pageSize,sorting,filters})`.
//   - Three states render: loading (skeleton rows), empty ("No results"),
//     error (destructive Alert + Retry → refetch).
//   - a11y: every header carries `scope="col"`; sortable headers advertise
//     `aria-sort`; the search input is labeled.

import * as React from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type ColumnFiltersState,
  type PaginationState,
  type SortingState,
} from "@tanstack/react-table";
import { AlertCircleIcon, ArrowUpDownIcon } from "lucide-react";

import { cn } from "@/lib/utils";
import type { Fetcher } from "@/lib/table-types";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const DEFAULT_PAGE_SIZE = 10;
const PAGE_SIZE_OPTIONS = [10, 20, 50, 100];

export type DataTableProps<T> = {
  /** Column defs (TanStack v8). Set `enableSorting` on sortable columns. */
  columns: ColumnDef<T, unknown>[];
  /** Server fetcher; called with the lifted table state on every change. */
  fetcher: Fetcher<T>;
  /** Stable cache key segment for TanStack Query (defaults to "data-table"). */
  queryKey?: string;
  /** Initial page size (defaults to 10). */
  initialPageSize?: number;
  /** Optional extra toolbar controls, right-aligned next to the search box. */
  toolbar?: React.ReactNode;
  /** When set, the search box drives a column filter on this column id. */
  searchColumn?: string;
  /** Placeholder for the search input (also used as its aria-label). */
  searchPlaceholder?: string;
  /** Per-row action slot (e.g. a kebab menu); rendered in a trailing column. */
  rowActions?: (row: T) => React.ReactNode;
  /** Optional CTA rendered inside the empty state. */
  emptyCta?: React.ReactNode;
  /** Accessible label / caption text for the table. */
  caption?: string;
};

export function DataTable<T>({
  columns,
  fetcher,
  queryKey = "data-table",
  initialPageSize = DEFAULT_PAGE_SIZE,
  toolbar,
  searchColumn,
  searchPlaceholder = "Search…",
  rowActions,
  emptyCta,
  caption,
}: DataTableProps<T>) {
  const [pagination, setPagination] = React.useState<PaginationState>({
    pageIndex: 0,
    pageSize: initialPageSize,
  });
  const [sorting, setSorting] = React.useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>(
    [],
  );

  const query = useQuery({
    queryKey: [queryKey, pagination, sorting, columnFilters],
    queryFn: () =>
      fetcher({
        pageIndex: pagination.pageIndex,
        pageSize: pagination.pageSize,
        sorting,
        filters: columnFilters,
      }),
    placeholderData: keepPreviousData,
  });

  const rows = query.data?.rows ?? [];
  const total = query.data?.total ?? 0;

  const table = useReactTable<T>({
    data: rows,
    columns,
    manualPagination: true,
    manualSorting: true,
    manualFiltering: true,
    rowCount: total,
    state: { pagination, sorting, columnFilters },
    onPaginationChange: setPagination,
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    getCoreRowModel: getCoreRowModel(),
    autoResetPageIndex: false,
  });

  // The search box drives a column filter (manualFiltering → fetcher refetch).
  const searchValue = searchColumn
    ? ((columnFilters.find((f) => f.id === searchColumn)?.value as
        | string
        | undefined) ?? "")
    : "";

  function onSearchChange(value: string) {
    if (!searchColumn) return;
    setColumnFilters((prev) => {
      const others = prev.filter((f) => f.id !== searchColumn);
      return value ? [...others, { id: searchColumn, value }] : others;
    });
    setPagination((p) => ({ ...p, pageIndex: 0 }));
  }

  const headerGroups = table.getHeaderGroups();
  const colSpan = columns.length + (rowActions ? 1 : 0);

  function ariaSortFor(
    sortDir: false | "asc" | "desc",
  ): React.AriaAttributes["aria-sort"] {
    if (sortDir === "asc") return "ascending";
    if (sortDir === "desc") return "descending";
    return "none";
  }

  return (
    <div className="space-y-3">
      {/* Toolbar: search (optional) + right-aligned actions slot. */}
      {(searchColumn || toolbar) && (
        <div className="flex items-center justify-between gap-2">
          {searchColumn ? (
            <Input
              type="search"
              aria-label={searchPlaceholder}
              placeholder={searchPlaceholder}
              value={searchValue}
              onChange={(e) => onSearchChange(e.target.value)}
              className="max-w-xs"
            />
          ) : (
            <span />
          )}
          {toolbar ? <div className="flex items-center gap-2">{toolbar}</div> : null}
        </div>
      )}

      <div className="rounded-md border">
        <Table>
          {caption ? (
            <caption className="sr-only">{caption}</caption>
          ) : null}
          <TableHeader className="sticky top-0 bg-background">
            {headerGroups.map((hg) => (
              <TableRow key={hg.id}>
                {hg.headers.map((header) => {
                  const canSort = header.column.getCanSort();
                  const sortDir = header.column.getIsSorted();
                  return (
                    <TableHead
                      key={header.id}
                      scope="col"
                      aria-sort={canSort ? ariaSortFor(sortDir) : undefined}
                    >
                      {header.isPlaceholder ? null : canSort ? (
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="-ml-2 h-8 data-[state=open]:bg-accent"
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          {flexRender(
                            header.column.columnDef.header,
                            header.getContext(),
                          )}
                          <ArrowUpDownIcon className="ml-1 size-3.5" />
                        </Button>
                      ) : (
                        flexRender(
                          header.column.columnDef.header,
                          header.getContext(),
                        )
                      )}
                    </TableHead>
                  );
                })}
                {rowActions ? (
                  <TableHead scope="col" className="w-12 text-right">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                ) : null}
              </TableRow>
            ))}
          </TableHeader>

          <TableBody>
            {query.isError ? (
              <TableRow>
                <TableCell colSpan={colSpan} className="p-4">
                  <Alert variant="destructive">
                    <AlertCircleIcon />
                    <AlertTitle>Failed to load data</AlertTitle>
                    <AlertDescription className="flex items-center gap-3">
                      <span>Something went wrong while fetching results.</span>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={() => void query.refetch()}
                      >
                        Retry
                      </Button>
                    </AlertDescription>
                  </Alert>
                </TableCell>
              </TableRow>
            ) : query.isPending ? (
              Array.from({ length: pagination.pageSize > 8 ? 8 : pagination.pageSize }).map(
                (_, i) => (
                  <TableRow key={`skeleton-${i}`}>
                    {Array.from({ length: colSpan }).map((__, j) => (
                      <TableCell key={`skeleton-${i}-${j}`}>
                        <Skeleton className="h-4 w-full" />
                      </TableCell>
                    ))}
                  </TableRow>
                ),
              )
            ) : table.getRowModel().rows.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={colSpan}
                  className="h-24 text-center text-muted-foreground"
                >
                  <div className="flex flex-col items-center justify-center gap-2">
                    <span>No results</span>
                    {emptyCta}
                  </div>
                </TableCell>
              </TableRow>
            ) : (
              table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  data-state={row.getIsSelected() ? "selected" : undefined}
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext(),
                      )}
                    </TableCell>
                  ))}
                  {rowActions ? (
                    <TableCell className="text-right">
                      {rowActions(row.original)}
                    </TableCell>
                  ) : null}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Footer: row count + page-size select + Prev/Next pager. */}
      <div className="flex flex-col items-center justify-between gap-3 sm:flex-row">
        <div className="text-sm text-muted-foreground">
          {total} {total === 1 ? "row" : "rows"}
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Rows per page</span>
            <Select
              value={String(pagination.pageSize)}
              onValueChange={(v) =>
                setPagination({ pageIndex: 0, pageSize: Number(v) })
              }
            >
              <SelectTrigger size="sm" aria-label="Rows per page">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {PAGE_SIZE_OPTIONS.map((n) => (
                  <SelectItem key={n} value={String(n)}>
                    {n}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center gap-2">
            <span
              className={cn("text-sm text-muted-foreground")}
              aria-live="polite"
            >
              Page {pagination.pageIndex + 1} of{" "}
              {Math.max(table.getPageCount(), 1)}
            </span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
            >
              Prev
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
            >
              Next
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
