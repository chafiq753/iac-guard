"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ChevronsUpDown, FolderGit2, Inbox, Maximize2, Plus } from "lucide-react";

import { KpiCards } from "@/components/kpi-cards";
import { ActivityChart } from "@/components/activity-chart";
import { AlertsDataTable } from "@/components/alerts-data-table";
import { ComplianceCard } from "@/components/compliance-card";
import { FindingDetailSheet } from "@/components/finding-detail-sheet";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { toast } from "sonner";

import type { ActivityPoint, Alert, AlertStatus, Kpi } from "@/lib/data";
import {
  platformApi,
  type FindingOut,
  type ProjectOut,
  type ScanDetail,
  type ScanListItem,
} from "@/lib/platform-api";

/** Variation en % entre deux valeurs (0 si pas de référence). */
function pctDelta(current: number, previous: number | null): number {
  if (previous === null || previous === 0) return 0;
  return Math.round(((current - previous) / previous) * 1000) / 10;
}

function sevCount(by: Record<string, number>, ...keys: string[]): number {
  return keys.reduce((acc, k) => acc + (by[k] ?? 0), 0);
}

interface DashboardData {
  scans: ScanListItem[];
  latest: ScanDetail | null;
  previous: ScanDetail | null;
  findings: FindingOut[];
  /** Détail des derniers scans (max 7) pour la courbe d'activité. */
  history: ScanDetail[];
}

export function DashboardLive() {
  const params = useSearchParams();
  const requestedId = params.get("project");

  const [projects, setProjects] = React.useState<ProjectOut[] | null>(null);
  const [selectedId, setSelectedId] = React.useState<number | null>(null);
  const [data, setData] = React.useState<DashboardData | null>(null);
  const [loadingData, setLoadingData] = React.useState(false);
  const [selectedAlert, setSelectedAlert] = React.useState<Alert | null>(null);

  // 1. Charger les projets, choisir celui de l'URL ou le premier.
  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await platformApi.listProjects();
        if (cancelled) return;
        setProjects(list);
        if (list.length > 0) {
          const fromUrl = list.find((p) => String(p.id) === requestedId);
          setSelectedId((fromUrl ?? list[0]).id);
        }
      } catch {
        if (!cancelled) setProjects([]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [requestedId]);

  // 2. Charger scans + findings du projet sélectionné, puis re-vérifier en
  // arrière-plan toutes les 30s (silencieusement) : si le pipeline envoie un
  // nouveau scan pendant que le dashboard est ouvert, il apparaît tout seul,
  // sans que l'utilisateur ait à rafraîchir la page.
  React.useEffect(() => {
    if (selectedId === null) return;
    let cancelled = false;

    async function refresh(silent: boolean) {
      if (!silent) setLoadingData(true);
      try {
        const scans = await platformApi.listScans(selectedId as number);
        if (scans.length === 0) {
          if (!cancelled)
            setData({ scans, latest: null, previous: null, findings: [], history: [] });
          return;
        }
        // Détail (score) des 7 scans les plus récents, en parallèle.
        const detailed = await Promise.all(
          scans.slice(0, 7).map((s) => platformApi.getScan(s.id))
        );
        const findings = await platformApi.listFindings(scans[0].id);
        if (!cancelled)
          setData({
            scans,
            latest: detailed[0],
            previous: detailed[1] ?? null,
            findings,
            history: detailed,
          });
      } catch {
        if (!cancelled && !silent)
          setData({ scans: [], latest: null, previous: null, findings: [], history: [] });
      } finally {
        if (!cancelled && !silent) setLoadingData(false);
      }
    }

    void refresh(false);
    const interval = setInterval(() => void refresh(true), 30_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [selectedId]);

  // --- États vides ---------------------------------------------------------

  if (projects === null) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-9 w-56" />
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {[0, 1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-32 w-full" />
          ))}
        </div>
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (projects.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
          <FolderGit2 className="size-10 text-muted-foreground" />
          <div>
            <p className="font-medium">Bienvenue sur iac-guard</p>
            <p className="mx-auto mt-1 max-w-md text-sm text-muted-foreground">
              Créez votre premier projet pour obtenir un token d&apos;API, puis
              envoyez-lui des scans depuis votre pipeline CI. Les résultats
              s&apos;afficheront ici.
            </p>
          </div>
          <Button nativeButton={false} render={<Link href="/projects" />}>
            <Plus className="size-4" />
            Créer mon premier projet
          </Button>
        </CardContent>
      </Card>
    );
  }

  const selected = projects.find((p) => p.id === selectedId) ?? projects[0];

  const selector = (
    <div className="flex items-center gap-2">
      <DropdownMenu>
        <DropdownMenuTrigger
          render={
            <Button variant="outline" size="sm" className="gap-2">
              <FolderGit2 className="size-4" />
              {selected.name}
              <ChevronsUpDown className="size-3.5 text-muted-foreground" />
            </Button>
          }
        />
        <DropdownMenuContent align="start" className="w-56">
          <DropdownMenuLabel>Projets</DropdownMenuLabel>
          {projects.map((p) => (
            <DropdownMenuItem key={p.id} onClick={() => setSelectedId(p.id)}>
              {p.name}
            </DropdownMenuItem>
          ))}
          <DropdownMenuSeparator />
          <DropdownMenuItem render={<Link href="/projects" />}>
            <Plus className="size-4" />
            Gérer les projets
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );

  if (loadingData || data === null) {
    return (
      <div className="space-y-4">
        {selector}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {[0, 1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-32 w-full" />
          ))}
        </div>
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (data.latest === null) {
    return (
      <div className="space-y-4">
        {selector}
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
            <Inbox className="size-10 text-muted-foreground" />
            <div>
              <p className="font-medium">Aucun scan reçu pour « {selected.name} »</p>
              <p className="mx-auto mt-1 max-w-md text-sm text-muted-foreground">
                Lancez le pipeline avec le token du projet : il enverra son
                rapport sur <code className="font-mono text-xs">POST /api/scans</code>{" "}
                et le tableau de bord s&apos;animera.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // --- Données réelles -> formats des composants d'affichage ----------------

  const { latest, previous } = data;
  const by = latest.score.by_severity;
  const prevBy = previous?.score.by_severity ?? null;

  const last7days = data.scans.filter(
    (s) => Date.now() - new Date(s.scanned_at).getTime() < 7 * 24 * 3600 * 1000
  ).length;

  // Un finding est "à traiter" tant qu'un analyste ne l'a pas résolu ou
  // classé faux positif.
  const isActionable = (s: string) => s !== "resolved" && s !== "false_positive";
  const openCount = data.findings.filter((f) => f.status === "open").length;
  const treatedCount = data.findings.length - data.findings.filter((f) => isActionable(f.status)).length;
  const criticalHighActive = data.findings.filter(
    (f) => isActionable(f.status) && (f.severity === "critical" || f.severity === "high")
  ).length;

  const kpis: Kpi[] = [
    {
      key: "score",
      label: "Compliance Score",
      value: `${latest.score.score} / 100`,
      delta: pctDelta(latest.score.score, previous?.score.score ?? null),
      hint: `Grade ${latest.score.grade} · dernier scan ${new Date(
        latest.scanned_at
      ).toLocaleDateString("fr-FR", { day: "numeric", month: "short" })}`,
    },
    {
      key: "open",
      label: "Findings ouverts",
      value: String(openCount),
      delta: pctDelta(latest.total_findings, previous?.total_findings ?? null),
      hint:
        treatedCount > 0
          ? `${treatedCount} traité(s) · ${latest.total_findings} détecté(s)`
          : previous
            ? `${previous.total_findings} au scan précédent`
            : "Premier scan du projet",
    },
    {
      key: "critical",
      label: "Critical & High",
      value: String(criticalHighActive),
      delta: pctDelta(
        sevCount(by, "critical", "high"),
        prevBy ? sevCount(prevBy, "critical", "high") : null
      ),
      hint: `${by["critical"] ?? 0} critical · ${by["high"] ?? 0} high détectés`,
    },
    {
      key: "scans",
      label: "Scans (7j)",
      value: String(last7days),
      delta: 0,
      hint: `${data.scans.length} scans au total`,
    },
  ];

  // Courbe : un point par scan récent (du plus ancien au plus récent).
  const series: ActivityPoint[] = [...data.history].reverse().map((s) => ({
    date: s.scanned_at,
    critical: s.score.by_severity["critical"] ?? 0,
    high: s.score.by_severity["high"] ?? 0,
    medium: s.score.by_severity["medium"] ?? 0,
  }));

  const alerts: Alert[] = data.findings.map((f) => ({
    id: `F-${f.id}`,
    title: f.title,
    source: f.source as Alert["source"],
    category: f.category as Alert["category"],
    severity: f.severity as Alert["severity"],
    ruleId: f.rule_id,
    // Voir alerts-manager : repli d'affichage pour la colonne, l'emplacement
    // exact reste porté par file/lineStart/lineEnd.
    resource: f.resource ?? f.file ?? "—",
    repo: latest.repo,
    status: f.status as AlertStatus,
    detectedAt: latest.scanned_at,
    findingId: f.id,
    scanId: latest.id,
    projectId: selected.id,
    projectName: selected.name,
    remediation: f.remediation,
    file: f.file,
    lineStart: f.line_start,
    lineEnd: f.line_end,
    commitSha: latest.commit_sha,
  }));

  async function onTriage(alert: Alert, status: AlertStatus) {
    if (alert.findingId === undefined || alert.scanId === undefined) return;
    try {
      const updated = await platformApi.triageFinding(
        alert.scanId,
        alert.findingId,
        status
      );
      // Mise à jour locale immédiate, sans re-fetch complet.
      setData((prev) =>
        prev
          ? {
              ...prev,
              findings: prev.findings.map((f) =>
                f.id === updated.id ? updated : f
              ),
            }
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

  return (
    <div className="flex flex-col gap-4 md:gap-6">
      {selector}

      <KpiCards kpis={kpis} />

      <div className="grid grid-cols-1 gap-4 md:gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <ActivityChart series={series} />
        </div>
        <ComplianceCard score={latest.score} />
      </div>

      <AlertsDataTable
        alerts={alerts}
        onTriage={(a, s) => void onTriage(a, s)}
        onRowClick={setSelectedAlert}
        headerAction={
          <Button
            variant="outline"
            size="sm"
            nativeButton={false}
            render={<Link href={`/alerts?project=${selected.id}`} />}
          >
            <Maximize2 className="size-4" />
            Agrandir
          </Button>
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
