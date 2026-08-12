"use client";

import * as React from "react";
import { useSearchParams } from "next/navigation";
import { ShieldAlert } from "lucide-react";
import { toast } from "sonner";

import { AlertsDataTable } from "@/components/alerts-data-table";
import { FindingDetailSheet } from "@/components/finding-detail-sheet";
import { Card, CardContent } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import type { Alert, AlertStatus } from "@/lib/data";
import {
  platformApi,
  type FindingWithProject,
  type ProjectOut,
} from "@/lib/platform-api";

const ALL = "all";

// Libellés pour que le Select affiche un texte lisible et non la valeur brute.
const SEVERITY_ITEMS: Record<string, string> = {
  [ALL]: "Toutes gravités",
  critical: "Critique",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
  info: "Info",
};
const CATEGORY_ITEMS: Record<string, string> = {
  [ALL]: "Toutes catégories",
  secret: "Secret exposé",
  misconfiguration: "Mauvaise configuration",
  policy: "Non-conformité",
};
const STATUS_ITEMS: Record<string, string> = {
  [ALL]: "Tous statuts",
  open: "Open",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
  false_positive: "False positive",
};

function toAlert(f: FindingWithProject): Alert {
  return {
    id: `F-${f.id}`,
    title: f.title,
    source: f.source as Alert["source"],
    category: f.category as Alert["category"],
    severity: f.severity as Alert["severity"],
    ruleId: f.rule_id,
    // Repli seulement pour la COLONNE ressource du tableau (un secret n'a pas
    // de ressource Terraform). L'emplacement réel est porté à part, sinon la
    // ligne se perd ici et le panneau de détail ne peut plus l'afficher.
    resource: f.resource ?? f.file ?? "—",
    repo: f.repo,
    status: f.status as AlertStatus,
    detectedAt: f.detected_at,
    findingId: f.id,
    scanId: f.scan_id,
    projectId: f.project_id,
    projectName: f.project_name,
    remediation: f.remediation,
    file: f.file,
    lineStart: f.line_start,
    lineEnd: f.line_end,
    commitSha: f.commit_sha,
  };
}

/**
 * Vue « Toutes les alertes » : plein écran, tous projets confondus, avec
 * filtres et un panneau de détail par alerte. Accessible via le bouton
 * « Agrandir » du dashboard ou le lien « Alertes » de la sidebar.
 */
export function AlertsManager() {
  const params = useSearchParams();
  const projectFromUrl = params.get("project");
  // Terme de recherche venu du header (?q=...) : filtre le texte des alertes.
  const queryFromUrl = (params.get("q") ?? "").trim().toLowerCase();

  const [projects, setProjects] = React.useState<ProjectOut[] | null>(null);
  const [items, setItems] = React.useState<FindingWithProject[] | null>(null);
  const [selectedAlert, setSelectedAlert] = React.useState<Alert | null>(null);

  const [projectFilter, setProjectFilter] = React.useState(projectFromUrl ?? ALL);
  const [severityFilter, setSeverityFilter] = React.useState(ALL);
  const [categoryFilter, setCategoryFilter] = React.useState(ALL);
  const [statusFilter, setStatusFilter] = React.useState(ALL);

  React.useEffect(() => {
    void platformApi.listProjects().then(setProjects).catch(() => setProjects([]));
  }, []);

  const load = React.useCallback(async () => {
    try {
      const page = await platformApi.listAlerts({ page_size: 100 });
      setItems(page.items);
    } catch {
      setItems([]);
      toast.error("Impossible de charger les alertes.");
    }
  }, []);

  React.useEffect(() => {
    void load();
    // Rafraîchissement silencieux : une nouvelle alerte livrée par le
    // pipeline apparaît sans que l'utilisateur ait à recharger la page.
    const interval = setInterval(() => void load(), 30_000);
    return () => clearInterval(interval);
  }, [load]);

  async function onTriage(alert: Alert, status: AlertStatus) {
    if (alert.findingId === undefined || alert.scanId === undefined) return;
    try {
      const updated = await platformApi.triageFinding(
        alert.scanId,
        alert.findingId,
        status
      );
      setItems((prev) =>
        prev
          ? prev.map((f) =>
              f.id === updated.id
                ? { ...f, status: updated.status, triage_note: updated.triage_note }
                : f
            )
          : prev
      );
      setSelectedAlert((prev) =>
        prev && prev.findingId === updated.id
          ? { ...prev, status: updated.status as AlertStatus }
          : prev
      );
      toast.success(
        status === "open" ? "Finding ré-ouvert." : "Décision enregistrée."
      );
    } catch {
      toast.error("Impossible d'enregistrer la décision.");
    }
  }

  if (projects === null || items === null) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-96 w-full" />
      </div>
    );
  }

  if (projects.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
          <ShieldAlert className="size-10 text-muted-foreground" />
          <p className="font-medium">Aucun projet pour l&apos;instant</p>
          <p className="max-w-sm text-sm text-muted-foreground">
            Créez un projet et envoyez-lui un scan : les alertes détectées
            s&apos;afficheront ici, tous projets confondus.
          </p>
        </CardContent>
      </Card>
    );
  }

  const filtered = items.filter((f) => {
    if (projectFilter !== ALL && String(f.project_id) !== projectFilter) return false;
    if (severityFilter !== ALL && f.severity !== severityFilter) return false;
    if (categoryFilter !== ALL && f.category !== categoryFilter) return false;
    if (statusFilter !== ALL && f.status !== statusFilter) return false;
    if (queryFromUrl) {
      const haystack = [f.title, f.resource, f.file, f.rule_id, f.project_name, f.repo]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(queryFromUrl)) return false;
    }
    return true;
  });

  const alerts = filtered.map(toAlert);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={projectFilter}
          onValueChange={(v) => setProjectFilter(v ?? ALL)}
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

        <Select
          value={severityFilter}
          onValueChange={(v) => setSeverityFilter(v ?? ALL)}
          items={SEVERITY_ITEMS}
        >
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Gravité" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>Toutes gravités</SelectItem>
            <SelectItem value="critical">Critique</SelectItem>
            <SelectItem value="high">Élevée</SelectItem>
            <SelectItem value="medium">Moyenne</SelectItem>
            <SelectItem value="low">Faible</SelectItem>
            <SelectItem value="info">Info</SelectItem>
          </SelectContent>
        </Select>

        <Select
          value={categoryFilter}
          onValueChange={(v) => setCategoryFilter(v ?? ALL)}
          items={CATEGORY_ITEMS}
        >
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Catégorie" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>Toutes catégories</SelectItem>
            <SelectItem value="secret">Secret exposé</SelectItem>
            <SelectItem value="misconfiguration">Mauvaise configuration</SelectItem>
            <SelectItem value="policy">Non-conformité</SelectItem>
          </SelectContent>
        </Select>

        <Select
          value={statusFilter}
          onValueChange={(v) => setStatusFilter(v ?? ALL)}
          items={STATUS_ITEMS}
        >
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Statut" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>Tous statuts</SelectItem>
            <SelectItem value="open">Open</SelectItem>
            <SelectItem value="acknowledged">Acknowledged</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
            <SelectItem value="false_positive">False positive</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <AlertsDataTable
        alerts={alerts}
        onTriage={(a, s) => void onTriage(a, s)}
        onRowClick={setSelectedAlert}
        showProjectColumn
        pageSize={15}
        title="Toutes les alertes"
        description={
          queryFromUrl
            ? `${filtered.length} résultat(s) pour « ${queryFromUrl} »`
            : `${filtered.length} alerte(s) sur ${items.length} au total, tous projets confondus`
        }
      />

      <FindingDetailSheet
        alert={selectedAlert}
        open={selectedAlert !== null}
        onOpenChange={(open) => !open && setSelectedAlert(null)}
        onTriage={(a, s) => void onTriage(a, s)}
      />
    </div>
  );
}
