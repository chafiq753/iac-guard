"use client";

import * as React from "react";
import { History } from "lucide-react";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { StatusBadge } from "@/components/severity-badge";
import type { AlertStatus } from "@/lib/data";
import { platformApi, type AuditLogPage, type ProjectOut } from "@/lib/platform-api";

const ALL = "all";
const PAGE_SIZE = 20;

/** Onglet « Audit » : historique append-only des décisions de triage. */
export function AuditLogViewer() {
  const [projects, setProjects] = React.useState<ProjectOut[] | null>(null);
  const [projectFilter, setProjectFilter] = React.useState(ALL);
  const [page, setPage] = React.useState(1);
  const [data, setData] = React.useState<AuditLogPage | null>(null);

  React.useEffect(() => {
    void platformApi.listProjects().then(setProjects).catch(() => setProjects([]));
  }, []);

  React.useEffect(() => {
    let cancelled = false;
    void platformApi
      .listAuditLog({
        project_id: projectFilter === ALL ? undefined : Number(projectFilter),
        page,
        page_size: PAGE_SIZE,
      })
      .then((p) => {
        if (!cancelled) setData(p);
      });
    return () => {
      cancelled = true;
    };
  }, [projectFilter, page]);

  if (projects === null || data === null) {
    return <Skeleton className="h-96 w-full" />;
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));

  return (
    <Card className="[--card-spacing:--spacing(6)]">
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="grid flex-1 gap-1">
          <CardTitle className="flex items-center gap-2">
            <History className="size-4" />
            Historique des décisions
          </CardTitle>
          <CardDescription>
            {data.total} action(s) enregistrée(s) — qui a changé quoi, et
            quand. Jamais modifié ni supprimé.
          </CardDescription>
        </div>
        <Select
          value={projectFilter}
          onValueChange={(v) => {
            setProjectFilter(v ?? ALL);
            setPage(1);
          }}
          items={{
            [ALL]: "Tous les projets",
            ...Object.fromEntries(projects.map((p) => [String(p.id), p.name])),
          }}
        >
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Projet" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>Tous les projets</SelectItem>
            {projects.map((p) => (
              <SelectItem key={p.id} value={String(p.id)}>
                {p.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow className="bg-muted/50">
                <TableHead>Quand</TableHead>
                <TableHead>Qui</TableHead>
                <TableHead>Projet</TableHead>
                <TableHead>Finding</TableHead>
                <TableHead>Changement</TableHead>
                <TableHead>Note</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="h-24 text-center text-muted-foreground">
                    Aucune action enregistrée pour l&apos;instant.
                  </TableCell>
                </TableRow>
              ) : (
                data.items.map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell className="text-sm text-muted-foreground whitespace-nowrap">
                      {new Date(entry.created_at).toLocaleString("fr-FR", {
                        day: "numeric",
                        month: "short",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </TableCell>
                    <TableCell className="text-sm">{entry.user_email ?? "—"}</TableCell>
                    <TableCell className="text-sm font-medium">
                      {entry.project_name}
                    </TableCell>
                    <TableCell className="max-w-64 truncate text-sm" title={entry.finding_title}>
                      {entry.finding_title}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        <StatusBadge status={entry.from_status as AlertStatus} />
                        <span className="text-muted-foreground">→</span>
                        <StatusBadge status={entry.to_status as AlertStatus} />
                      </div>
                    </TableCell>
                    <TableCell className="max-w-48 truncate text-sm text-muted-foreground" title={entry.note ?? undefined}>
                      {entry.note ?? "—"}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
        <div className="flex items-center justify-between pt-4">
          <p className="text-xs text-muted-foreground">
            Page {data.page} / {totalPages}
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => p + 1)}
              disabled={page >= totalPages}
            >
              Next
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
