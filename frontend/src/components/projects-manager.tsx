"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Copy, FolderGit2, KeyRound, Loader2, Plus } from "lucide-react";
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
import { ApiError } from "@/lib/auth-api";
import {
  platformApi,
  type ProjectCreated,
  type ProjectDetail,
  type ProjectOut,
} from "@/lib/platform-api";

/** Un projet de la liste, enrichi (si déjà chargé) de son détail. */
type ProjectRow = ProjectOut & { detail?: ProjectDetail };

export function ProjectsManager() {
  const router = useRouter();
  const [projects, setProjects] = React.useState<ProjectRow[] | null>(null);
  const [createOpen, setCreateOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [creating, setCreating] = React.useState(false);
  // Token affiché UNE seule fois après création (le backend n'en garde qu'un hash).
  const [created, setCreated] = React.useState<ProjectCreated | null>(null);

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
      const project = await platformApi.createProject(name.trim());
      setCreateOpen(false);
      setName("");
      setCreated(project);
      void load();
    } catch (err) {
      toast.error(
        err instanceof ApiError ? err.message : "La création du projet a échoué."
      );
    } finally {
      setCreating(false);
    }
  }

  function copyToken() {
    if (created) {
      void navigator.clipboard.writeText(created.token);
      toast.success("Token copié dans le presse-papiers.");
    }
  }

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
                    <TableHead>Créé le</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {projects.map((p) => (
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
                          <Badge variant="outline" className="tabular-nums">
                            {p.detail.latest_score.score} / 100 ·{" "}
                            {p.detail.latest_score.grade}
                          </Badge>
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            aucun scan
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(p.created_at).toLocaleDateString("fr-FR", {
                          day: "numeric",
                          month: "short",
                          year: "numeric",
                        })}
                      </TableCell>
                    </TableRow>
                  ))}
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

      {/* --- Dialog token (affiché une seule fois) --- */}
      <Dialog open={created !== null} onOpenChange={(v) => !v && setCreated(null)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Projet « {created?.name} » créé</DialogTitle>
            <DialogDescription>
              Voici le token d&apos;API du projet. Le pipeline l&apos;utilisera
              pour authentifier ses envois de scans.
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
              {created?.token}
            </code>
            <Button variant="outline" size="icon-sm" onClick={copyToken}>
              <Copy className="size-4" />
            </Button>
          </div>

          <DialogFooter>
            <Button onClick={() => setCreated(null)}>J&apos;ai copié le token</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
