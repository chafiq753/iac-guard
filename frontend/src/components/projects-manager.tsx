"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  Copy,
  FolderGit2,
  KeyRound,
  Loader2,
  MoreHorizontal,
  Plus,
  RotateCw,
  Search,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";
import { ApiError } from "@/lib/auth-api";
import {
  platformApi,
  type ProjectCreated,
  type ProjectDetail,
  type ProjectOut,
} from "@/lib/platform-api";

/** Un projet de la liste, enrichi (si déjà chargé) de son détail. */
type ProjectRow = ProjectOut & { detail?: ProjectDetail };

/** Le token n'est jamais réaffiché après sa création ou sa rotation. */
interface TokenReveal {
  projectName: string;
  token: string;
  rotated: boolean;
}

const STALE_AFTER_DAYS = 14;

/** Couleur actionnable du score : vert (A/B), orange (C/D), rouge (F). */
function scoreBadgeClass(grade: string): string {
  if (grade === "A" || grade === "B") {
    return "border-emerald-600/30 bg-emerald-500/12 text-emerald-700 dark:text-emerald-300";
  }
  if (grade === "C" || grade === "D") {
    return "border-amber-600/30 bg-amber-500/12 text-amber-700 dark:text-amber-300";
  }
  return "border-red-600/30 bg-red-500/12 text-red-700 dark:text-red-300";
}

function daysSince(iso: string): number {
  return Math.floor((Date.now() - new Date(iso).getTime()) / (24 * 3600 * 1000));
}

/** "Dernière activité" : silence prolongé = signal à part entière, pas juste "aucun scan". */
function LastActivity({ detail }: { detail?: ProjectDetail }) {
  if (!detail || detail.scan_count === 0) {
    return <span className="text-xs text-muted-foreground">Aucun scan reçu</span>;
  }
  if (!detail.last_scan_at) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }
  const days = daysSince(detail.last_scan_at);
  const label =
    days <= 0 ? "aujourd'hui" : days === 1 ? "il y a 1 jour" : `il y a ${days} jours`;
  const stale = days > STALE_AFTER_DAYS;
  return (
    <span
      className={cn(
        "flex items-center gap-1.5 text-xs",
        stale ? "text-amber-600 dark:text-amber-400" : "text-muted-foreground"
      )}
    >
      {stale ? <AlertTriangle className="size-3.5 shrink-0" /> : null}
      {stale ? `Aucun scan depuis ${days}j` : label}
    </span>
  );
}

export function ProjectsManager() {
  const router = useRouter();
  const [projects, setProjects] = React.useState<ProjectRow[] | null>(null);
  const [search, setSearch] = React.useState("");
  const [createOpen, setCreateOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [creating, setCreating] = React.useState(false);
  const [tokenReveal, setTokenReveal] = React.useState<TokenReveal | null>(null);
  const [deleteTarget, setDeleteTarget] = React.useState<ProjectRow | null>(null);
  const [deleting, setDeleting] = React.useState(false);
  const [rotateTarget, setRotateTarget] = React.useState<ProjectRow | null>(null);
  const [rotating, setRotating] = React.useState(false);

  const load = React.useCallback(async () => {
    try {
      const list = await platformApi.listProjects();
      setProjects(list);
      // Enrichissement (nb de scans + dernier score) en arrière-plan.
      const details = await Promise.all(
        list.map((p) => platformApi.getProject(p.id).catch(() => undefined))
      );
      setProjects(list.map((p, i) => ({ ...p, detail: details[i] })));
    } catch (err) {
      setProjects([]);
      toast.error(
        err instanceof ApiError ? err.message : "Impossible de charger les projets."
      );
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    try {
      const project: ProjectCreated = await platformApi.createProject(name.trim());
      setCreateOpen(false);
      setName("");
      setTokenReveal({ projectName: project.name, token: project.token, rotated: false });
      void load();
    } catch (err) {
      toast.error(
        err instanceof ApiError ? err.message : "La création du projet a échoué."
      );
    } finally {
      setCreating(false);
    }
  }

  async function onConfirmRotate() {
    if (!rotateTarget) return;
    setRotating(true);
    try {
      const result = await platformApi.rotateToken(rotateTarget.id);
      setRotateTarget(null);
      setTokenReveal({
        projectName: rotateTarget.name,
        token: result.token,
        rotated: true,
      });
    } catch (err) {
      toast.error(
        err instanceof ApiError ? err.message : "La rotation du token a échoué."
      );
    } finally {
      setRotating(false);
    }
  }

  async function onConfirmDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await platformApi.deleteProject(deleteTarget.id);
      toast.success(`Projet « ${deleteTarget.name} » supprimé.`);
      setDeleteTarget(null);
      void load();
    } catch (err) {
      toast.error(
        err instanceof ApiError ? err.message : "La suppression a échoué."
      );
    } finally {
      setDeleting(false);
    }
  }

  function copyToken() {
    if (tokenReveal) {
      void navigator.clipboard.writeText(tokenReveal.token);
      toast.success("Token copié dans le presse-papiers.");
    }
  }

  const filtered = projects?.filter((p) =>
    p.name.toLowerCase().includes(search.trim().toLowerCase())
  );

  return (
    <>
      <Card>
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="grid flex-1 gap-1">
            <CardTitle>Projets</CardTitle>
            <CardDescription>
              Chaque projet reçoit un token d&apos;API : c&apos;est lui que le
              pipeline utilise pour envoyer ses scans.
            </CardDescription>
          </div>
          {projects && projects.length > 0 ? (
            <div className="relative w-full sm:w-56">
              <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Rechercher un projet…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="h-9 pl-8"
              />
            </div>
          ) : null}
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="size-4" />
            Nouveau projet
          </Button>
        </CardHeader>
        <CardContent>
          {projects === null ? (
            <div className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : projects.length === 0 ? (
            <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed py-12 text-center">
              <FolderGit2 className="size-8 text-muted-foreground" />
              <p className="font-medium">Aucun projet pour l&apos;instant</p>
              <p className="max-w-sm text-sm text-muted-foreground">
                Créez votre premier projet pour obtenir un token et commencer à
                recevoir des scans du pipeline.
              </p>
              <Button size="sm" className="mt-2" onClick={() => setCreateOpen(true)}>
                <Plus className="size-4" />
                Créer un projet
              </Button>
            </div>
          ) : (
            <div className="overflow-hidden rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow className="bg-muted/50">
                    <TableHead>Nom</TableHead>
                    <TableHead>Token</TableHead>
                    <TableHead className="text-right">Scans</TableHead>
                    <TableHead className="text-right">Dernier score</TableHead>
                    <TableHead>Dernière activité</TableHead>
                    <TableHead>Créé le</TableHead>
                    <TableHead className="w-10" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered && filtered.length === 0 ? (
                    <TableRow>
                      <TableCell
                        colSpan={7}
                        className="h-20 text-center text-sm text-muted-foreground"
                      >
                        Aucun projet ne correspond à « {search} ».
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered?.map((p) => (
                      <TableRow
                        key={p.id}
                        className="cursor-pointer"
                        onClick={() => router.push(`/?project=${p.id}`)}
                      >
                        <TableCell className="font-medium">{p.name}</TableCell>
                        <TableCell>
                          <span className="font-mono text-xs text-muted-foreground">
                            {p.token_prefix}…
                          </span>
                        </TableCell>
                        <TableCell className="text-right tabular-nums">
                          {p.detail ? p.detail.scan_count : "—"}
                        </TableCell>
                        <TableCell className="text-right">
                          {p.detail?.latest_score ? (
                            <Badge
                              variant="outline"
                              className={cn(
                                "tabular-nums",
                                scoreBadgeClass(p.detail.latest_score.grade)
                              )}
                            >
                              {p.detail.latest_score.score} / 100 ·{" "}
                              {p.detail.latest_score.grade}
                            </Badge>
                          ) : (
                            <span className="text-xs text-muted-foreground">
                              aucun scan
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          <LastActivity detail={p.detail} />
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {new Date(p.created_at).toLocaleDateString("fr-FR", {
                            day: "numeric",
                            month: "short",
                            year: "numeric",
                          })}
                        </TableCell>
                        <TableCell onClick={(e) => e.stopPropagation()}>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon-sm"
                                aria-label={`Actions pour ${p.name}`}
                              >
                                <MoreHorizontal className="size-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="w-56">
                              <DropdownMenuLabel>{p.name}</DropdownMenuLabel>
                              <DropdownMenuItem onClick={() => setRotateTarget(p)}>
                                <RotateCw className="size-4" />
                                Régénérer le token
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                variant="destructive"
                                onClick={() => setDeleteTarget(p)}
                              >
                                <Trash2 className="size-4" />
                                Supprimer le projet
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* --- Dialog de création --- */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="sm:max-w-md">
          <form onSubmit={onCreate}>
            <DialogHeader>
              <DialogTitle>Nouveau projet</DialogTitle>
              <DialogDescription>
                Donnez-lui le nom du dépôt ou de l&apos;infrastructure à surveiller.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-2 py-4">
              <Label htmlFor="project-name">Nom du projet</Label>
              <Input
                id="project-name"
                placeholder="ex. payments-infra"
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoFocus
                required
              />
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setCreateOpen(false)}
              >
                Annuler
              </Button>
              <Button type="submit" disabled={creating || !name.trim()}>
                {creating ? <Loader2 className="size-4 animate-spin" /> : null}
                Créer
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* --- Dialog token (affiché une seule fois, création ou rotation) --- */}
      <Dialog
        open={tokenReveal !== null}
        onOpenChange={(v) => !v && setTokenReveal(null)}
      >
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {tokenReveal?.rotated
                ? `Token régénéré pour « ${tokenReveal?.projectName} »`
                : `Projet « ${tokenReveal?.projectName} » créé`}
            </DialogTitle>
            <DialogDescription>
              {tokenReveal?.rotated
                ? "L'ancien token ne fonctionne plus. Mettez à jour le secret CI du pipeline avec celui-ci."
                : "Voici le token d'API du projet. Le pipeline l'utilisera pour authentifier ses envois de scans."}
            </DialogDescription>
          </DialogHeader>

          <Alert>
            <KeyRound className="size-4" />
            <AlertTitle>Affiché une seule fois</AlertTitle>
            <AlertDescription>
              Nous n&apos;en conservons qu&apos;une empreinte : copiez-le
              maintenant et stockez-le comme secret CI (jamais dans le code).
            </AlertDescription>
          </Alert>

          <div className="flex items-center gap-2 rounded-lg border bg-muted/40 p-3">
            <code className="flex-1 break-all font-mono text-xs" dir="ltr">
              {tokenReveal?.token}
            </code>
            <Button variant="outline" size="icon-sm" onClick={copyToken}>
              <Copy className="size-4" />
            </Button>
          </div>

          <DialogFooter>
            <Button onClick={() => setTokenReveal(null)}>
              J&apos;ai copié le token
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* --- Confirmation de rotation --- */}
      <Dialog
        open={rotateTarget !== null}
        onOpenChange={(v) => !v && setRotateTarget(null)}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Régénérer le token ?</DialogTitle>
            <DialogDescription>
              L&apos;ancien token de « {rotateTarget?.name} » cessera de
              fonctionner immédiatement. Le pipeline devra être reconfiguré
              avec le nouveau avant son prochain scan.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setRotateTarget(null)}
            >
              Annuler
            </Button>
            <Button onClick={onConfirmRotate} disabled={rotating}>
              {rotating ? <Loader2 className="size-4 animate-spin" /> : null}
              Régénérer
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* --- Confirmation de suppression --- */}
      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(v) => !v && setDeleteTarget(null)}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Supprimer « {deleteTarget?.name} » ?</DialogTitle>
            <DialogDescription>
              Cette action est irréversible : tous les scans, alertes et
              décisions de triage de ce projet seront définitivement supprimés,
              et son token cessera de fonctionner.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setDeleteTarget(null)}
            >
              Annuler
            </Button>
            <Button
              variant="destructive"
              onClick={onConfirmDelete}
              disabled={deleting}
            >
              {deleting ? <Loader2 className="size-4 animate-spin" /> : null}
              Supprimer définitivement
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
