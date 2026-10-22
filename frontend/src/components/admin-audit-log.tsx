"use client";

import * as React from "react";
import { ShieldCheck } from "lucide-react";

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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  ACTION_LABELS,
  ROLE_LABELS,
  adminApi,
  type AdminAuditLogEntry,
  type AdminAuditLogPage,
  type AdminUser,
} from "@/lib/admin-api";

const ALL = "all";
const PAGE_SIZE = 20;

/** Résume le `details` JSON en une phrase lisible par un auditeur. */
function describeDetails(entry: AdminAuditLogEntry): string {
  const d = entry.details;
  if (entry.action === "user.role_changed") {
    const from = ROLE_LABELS[String(d.old_role)] ?? String(d.old_role);
    const to = ROLE_LABELS[String(d.new_role)] ?? String(d.new_role);
    return `${from} → ${to}`;
  }
  if (entry.action === "user.invited") {
    return `Rôle attribué : ${ROLE_LABELS[String(d.role)] ?? String(d.role)}`;
  }
  if (entry.action === "user.project_access_updated") {
    const ids = Array.isArray(d.project_ids) ? d.project_ids : [];
    return ids.length === 0
      ? "Tous les accès révoqués"
      : `${ids.length} projet${ids.length > 1 ? "s" : ""} accessible${ids.length > 1 ? "s" : ""}`;
  }
  if (entry.action === "policy.exception_added" || entry.action === "policy.exception_removed") {
    return `${String(d.project_name)} · ${String(d.rule_id)} — ${String(d.note ?? "")}`;
  }
  return "—";
}

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString("fr-FR", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Onglet « Journal d'audit » : trace append-only des actions d'administration. */
export function AdminAuditLog() {
  const [users, setUsers] = React.useState<AdminUser[]>([]);
  const [actionFilter, setActionFilter] = React.useState(ALL);
  const [targetFilter, setTargetFilter] = React.useState(ALL);
  const [since, setSince] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [data, setData] = React.useState<AdminAuditLogPage | null>(null);

  // Tout changement de filtre ramène à la première page : rester en page 3
  // d'un résultat qui n'en compte plus qu'une afficherait du vide.
  function applyFilter(apply: () => void) {
    apply();
    setPage(1);
  }

  React.useEffect(() => {
    void adminApi
      .listUsers(1, 100)
      .then((p) => setUsers(p.items))
      .catch(() => setUsers([]));
  }, []);

  React.useEffect(() => {
    let cancelled = false;
    void adminApi
      .listAuditLogs({
        action: actionFilter === ALL ? undefined : actionFilter,
        target_user_id: targetFilter === ALL ? undefined : Number(targetFilter),
        // `datetime-local` donne "2026-08-20T14:30" — le backend attend un ISO
        // complet, que FastAPI parse sans souci.
        since: since ? new Date(since).toISOString() : undefined,
        page,
        page_size: PAGE_SIZE,
      })
      .then((p) => {
        if (!cancelled) setData(p);
      })
      .catch(() => {
        if (!cancelled) setData({ items: [], total: 0, page: 1, page_size: PAGE_SIZE });
      });
    return () => {
      cancelled = true;
    };
  }, [actionFilter, targetFilter, since, page]);

  if (data === null) {
    return <Skeleton className="h-96 w-full" />;
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));

  return (
    <Card>
      <CardHeader>
        <div className="grid gap-1">
          <CardTitle>Journal d&apos;audit</CardTitle>
          <CardDescription>
            Chaque action d&apos;administration est enregistrée définitivement :
            ni modifiable, ni supprimable.
          </CardDescription>
        </div>

        <div className="flex flex-wrap items-end gap-3 pt-4">
          <div className="grid gap-1.5">
            <Label className="text-xs">Action</Label>
            <Select
              value={actionFilter}
              onValueChange={(v) => applyFilter(() => setActionFilter(v ?? ALL))}
            >
              <SelectTrigger size="sm" className="w-56">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>Toutes les actions</SelectItem>
                {Object.entries(ACTION_LABELS).map(([value, label]) => (
                  <SelectItem key={value} value={value}>
                    {label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid gap-1.5">
            <Label className="text-xs">Compte concerné</Label>
            <Select
              value={targetFilter}
              onValueChange={(v) => applyFilter(() => setTargetFilter(v ?? ALL))}
            >
              <SelectTrigger size="sm" className="w-56">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>Tous les comptes</SelectItem>
                {users.map((u) => (
                  <SelectItem key={u.id} value={String(u.id)}>
                    {u.email}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid gap-1.5">
            <Label className="text-xs" htmlFor="audit-since">
              Depuis le
            </Label>
            <Input
              id="audit-since"
              type="datetime-local"
              className="h-8 w-52"
              value={since}
              onChange={(e) => applyFilter(() => setSince(e.target.value))}
            />
          </div>

          {(actionFilter !== ALL || targetFilter !== ALL || since) && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() =>
                applyFilter(() => {
                  setActionFilter(ALL);
                  setTargetFilter(ALL);
                  setSince("");
                })
              }
            >
              Réinitialiser
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent>
        {data.items.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-12 text-center">
            <ShieldCheck className="size-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              Aucune action ne correspond à ces filtres.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Date</TableHead>
                  <TableHead>Auteur</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Compte concerné</TableHead>
                  <TableHead>Détail</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell className="whitespace-nowrap text-sm text-muted-foreground">
                      {formatDateTime(entry.created_at)}
                    </TableCell>
                    <TableCell className="text-sm">{entry.actor_email}</TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {ACTION_LABELS[entry.action] ?? entry.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm">
                      {entry.target_user_email ?? "—"}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {describeDetails(entry)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}

        {totalPages > 1 && (
          <div className="flex items-center justify-between pt-4">
            <span className="text-xs text-muted-foreground">
              {data.total} entrée{data.total > 1 ? "s" : ""} · page {data.page} sur{" "}
              {totalPages}
            </span>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                Précédent
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
              >
                Suivant
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
