"use client";

import * as React from "react";
import {
  type ColumnDef,
  type SortingState,
  type ColumnFiltersState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { ArrowUpDown, MoreHorizontal, Search } from "lucide-react";

import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
  CardContent,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { SeverityBadge, StatusBadge } from "@/components/severity-badge";
import { cn } from "@/lib/utils";
import type { Alert, AlertStatus } from "@/lib/data";

const severityRank: Record<Alert["severity"], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/** Classe responsive portée par une colonne (masquage selon la largeur). */
type ColumnMeta = { className?: string };

/** Callback de triage : l'analyste décide du sort d'un finding. */
type OnTriage = (alert: Alert, status: AlertStatus) => void;

const makeColumns = (
  onTriage?: OnTriage,
  showProject?: boolean
): ColumnDef<Alert>[] => [
  {
    accessorKey: "id",
    header: "ID",
    // Référence interne (F-82) : la moins essentielle, masquée sur écrans étroits.
    meta: { className: "hidden lg:table-cell" } satisfies ColumnMeta,
    cell: ({ row }) => (
      <span className="font-mono text-xs text-muted-foreground">
        {row.getValue("id")}
      </span>
    ),
  },
  ...(showProject
    ? ([
        {
          accessorKey: "projectName",
          header: "Projet",
          cell: ({ row }) => (
            <span className="text-sm font-medium">
              {row.original.projectName ?? "—"}
            </span>
          ),
        },
      ] satisfies ColumnDef<Alert>[])
    : []),
  {
    accessorKey: "title",
    header: ({ column }) => (
      <Button
        variant="ghost"
        size="sm"
        className="-ml-2 h-8"
        onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
      >
        Alert
        <ArrowUpDown className="size-3.5" />
      </Button>
    ),
    cell: ({ row }) => (
      // Largeur bornée + troncature : les titres longs (Gitleaks est verbeux)
      // ne doivent pas pousser les colonnes suivantes hors de l'écran.
      <div className="flex max-w-[13rem] min-w-0 flex-col lg:max-w-[18rem] xl:max-w-[19rem] 2xl:max-w-[30rem]">
        <span className="truncate font-medium" title={row.getValue("title")}>
          {row.getValue("title")}
        </span>
        <span
          className="truncate text-xs text-muted-foreground"
          title={`${row.original.repo} · ${row.original.resource}`}
        >
          {row.original.repo} · {row.original.resource}
        </span>
      </div>
    ),
  },
  {
    accessorKey: "source",
    header: "Source",
    cell: ({ row }) => (
      <Badge variant="outline" className="font-mono text-[11px] capitalize">
        {row.getValue("source")}
      </Badge>
    ),
  },
  {
    accessorKey: "severity",
    header: ({ column }) => (
      <Button
        variant="ghost"
        size="sm"
        className="-ml-2 h-8"
        onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
      >
        Severity
        <ArrowUpDown className="size-3.5" />
      </Button>
    ),
    sortingFn: (a, b) =>
      severityRank[a.original.severity] - severityRank[b.original.severity],
    cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => <StatusBadge status={row.original.status} />,
  },
  {
    accessorKey: "detectedAt",
    header: "Detected",
    // Utile mais secondaire : n'apparaît que sur les écrans larges.
    meta: { className: "hidden xl:table-cell" } satisfies ColumnMeta,
    cell: ({ row }) => (
      <span className="text-sm whitespace-nowrap text-muted-foreground">
        {new Date(row.getValue("detectedAt")).toLocaleDateString("fr-FR", {
          day: "numeric",
          month: "short",
        })}
      </span>
    ),
  },
  {
    id: "actions",
    enableHiding: false,
    cell: ({ row }) => (
      // Le menu vit dans une ligne cliquable (ouvre le détail) : on coupe la
      // propagation pour que choisir une action n'ouvre pas aussi le panneau.
      <div onClick={(e) => e.stopPropagation()}>
      <DropdownMenu>
        <DropdownMenuTrigger
          render={
            <Button variant="ghost" size="icon-sm" aria-label="Row actions">
              <MoreHorizontal className="size-4" />
            </Button>
          }
        />
        <DropdownMenuContent align="end" className="w-48">
          <DropdownMenuLabel>Triage</DropdownMenuLabel>
          {row.original.status === "open" ? (
            <>
              <DropdownMenuItem
                onClick={() => onTriage?.(row.original, "acknowledged")}
              >
                Acknowledge
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => onTriage?.(row.original, "resolved")}
              >
                Mark as resolved
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => onTriage?.(row.original, "false_positive")}
              >
                False positive
              </DropdownMenuItem>
            </>
          ) : (
            <>
              {row.original.status === "acknowledged" ? (
                <DropdownMenuItem
                  onClick={() => onTriage?.(row.original, "resolved")}
                >
                  Mark as resolved
                </DropdownMenuItem>
              ) : null}
              <DropdownMenuItem onClick={() => onTriage?.(row.original, "open")}>
                Reopen
              </DropdownMenuItem>
            </>
          )}
          <DropdownMenuSeparator />
          <DropdownMenuItem
            onClick={() => navigator.clipboard?.writeText(row.original.id)}
          >
            Copy alert ID
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      </div>
    ),
  },
];

export function AlertsDataTable({
  alerts,
  onTriage,
  onRowClick,
  showProjectColumn = false,
  title = "Latest Alerts",
  description = "Findings from Gitleaks, Checkov, Conftest and Semgrep across your repositories",
  pageSize = 6,
  headerAction,
}: {
  alerts: Alert[];
  onTriage?: OnTriage;
  /** Ouvre le panneau de détail d'une alerte quand on clique sa ligne. */
  onRowClick?: (alert: Alert) => void;
  /** Affiche la colonne "Projet" (vue cross-projets, page /alerts). */
  showProjectColumn?: boolean;
  title?: string;
  description?: string;
  pageSize?: number;
  /** Bouton(s) additionnel(s) affiché(s) à côté du titre, ex: "Agrandir". */
  headerAction?: React.ReactNode;
}) {
  const [sorting, setSorting] = React.useState<SortingState>([
    { id: "severity", desc: true },
  ]);
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>(
    []
  );

  const columns = React.useMemo(
    () => makeColumns(onTriage, showProjectColumn),
    [onTriage, showProjectColumn]
  );

  const table = useReactTable({
    data: alerts,
    columns,
    state: { sorting, columnFilters },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize } },
  });

  return (
    <Card>
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="grid flex-1 gap-1">
          <div className="flex items-center gap-2">
            <CardTitle>{title}</CardTitle>
          </div>
          <CardDescription>{description}</CardDescription>
        </div>
        <div className="flex w-full items-center gap-2 sm:w-auto">
          <div className="relative w-full sm:w-64">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Filter alerts…"
              value={(table.getColumn("title")?.getFilterValue() as string) ?? ""}
              onChange={(e) =>
                table.getColumn("title")?.setFilterValue(e.target.value)
              }
              className="h-9 pl-8"
            />
          </div>
          {headerAction}
        </div>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              {table.getHeaderGroups().map((hg) => (
                <TableRow key={hg.id} className="bg-muted/50">
                  {hg.headers.map((header) => (
                    <TableHead
                      key={header.id}
                      className={cn(
                        "whitespace-nowrap",
                        (header.column.columnDef.meta as ColumnMeta | undefined)
                          ?.className
                      )}
                    >
                      {header.isPlaceholder
                        ? null
                        : flexRender(
                            header.column.columnDef.header,
                            header.getContext()
                          )}
                    </TableHead>
                  ))}
                </TableRow>
              ))}
            </TableHeader>
            <TableBody>
              {table.getRowModel().rows.length ? (
                table.getRowModel().rows.map((row) => (
                  <TableRow
                    key={row.id}
                    className={onRowClick ? "cursor-pointer" : undefined}
                    onClick={() => onRowClick?.(row.original)}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <TableCell
                        key={cell.id}
                        className={
                          (cell.column.columnDef.meta as ColumnMeta | undefined)
                            ?.className
                        }
                      >
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext()
                        )}
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell
                    colSpan={columns.length}
                    className="h-24 text-center text-muted-foreground"
                  >
                    No alerts found.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
        <div className="flex items-center justify-between pt-4">
          <p className="text-xs text-muted-foreground">
            {table.getFilteredRowModel().rows.length} alert(s)
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
            >
              Previous
            </Button>
            <span className="text-xs text-muted-foreground tabular-nums">
              Page {table.getState().pagination.pageIndex + 1} /{" "}
              {Math.max(1, table.getPageCount())}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
            >
              Next
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
