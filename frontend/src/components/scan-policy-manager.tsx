"use client";

import * as React from "react";
import { AlertTriangle, FolderGit2, Loader2, Plus, ShieldOff, Trash2 } from "lucide-react";
import { toast } from "sonner";

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
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/components/auth-provider";
import { ApiError } from "@/lib/auth-api";
import { canManagePolicy } from "@/lib/permissions";
import { platformApi, type ProjectOut, type ScanPolicyOut } from "@/lib/platform-api";

const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critique",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
  info: "Info",
};

const NONE = "none";

/** Onglet « Politiques de scan » : seuil de blocage + exceptions, par projet. */
export function ScanPolicyManager() {
  // Seuil et exceptions : admin / security_lead (les autres rôles lisent).
  const { user } = useAuth();
  const policyAllowed = canManagePolicy(user?.role);
  const [projects, setProjects] = React.useState<ProjectOut[] | null>(null);
  const [selectedId, setSelectedId] = React.useState<number | null>(null);
  const [policy, setPolicy] = React.useState<ScanPolicyOut | null>(null);
  const [savingThreshold, setSavingThreshold] = React.useState(false);
  const [newRuleId, setNewRuleId] = React.useState("");
  const [newRuleNote, setNewRuleNote] = React.useState("");
  const [addingRule, setAddingRule] = React.useState(false);

  React.useEffect(() => {
    void platformApi.listProjects().then((list) => {
      setProjects(list);
      if (list.length > 0) setSelectedId(list[0].id);
    });
  }, []);

  const loadPolicy = React.useCallback(async (projectId: number) => {
    setPolicy(null);
    try {
      setPolicy(await platformApi.getPolicy(projectId));
    } catch {
      toast.error("Impossible de charger la politique de ce projet.");
    }
  }, []);

  React.useEffect(() => {
    if (selectedId !== null) void loadPolicy(selectedId);
  }, [selectedId, loadPolicy]);

  async function onThresholdChange(value: string | null) {
    if (selectedId === null || value === null) return;
    const severity = value === NONE ? null : value;
    setSavingThreshold(true);
    try {
      setPolicy(await platformApi.updatePolicy(selectedId, severity));
      toast.success(
        severity
          ? `Le pipeline échouera dès qu'un finding "${SEVERITY_LABELS[severity]}" ou pire sera détecté.`
          : "Le pipeline ne sera plus jamais bloqué par ce projet."
      );
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Échec de la mise à jour.");
    } finally {
      setSavingThreshold(false);
    }
  }

  async function onAddRule(e: React.FormEvent) {
    e.preventDefault();
    if (selectedId === null || !newRuleId.trim() || !newRuleNote.trim()) return;
    setAddingRule(true);
    try {
      await platformApi.addIgnoredRule(selectedId, newRuleId.trim(), newRuleNote.trim());
      setNewRuleId("");
      setNewRuleNote("");
      void loadPolicy(selectedId);
      toast.success("Règle ajoutée aux exceptions.");
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Échec de l'ajout.");
    } finally {
      setAddingRule(false);
    }
  }

  async function onRemoveRule(ruleId: number) {
    if (selectedId === null) return;
    try {
      await platformApi.removeIgnoredRule(selectedId, ruleId);
      void loadPolicy(selectedId);
      toast.success("Règle retirée : ses findings recomptent dans le score.");
    } catch {
      toast.error("Échec de la suppression.");
    }
  }

  if (projects === null) {
    return <Skeleton className="h-64 w-full" />;
  }

  if (projects.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center gap-2 py-12 text-center">
          <FolderGit2 className="size-8 text-muted-foreground" />
          <p className="font-medium">Aucun projet pour l&apos;instant</p>
          <p className="max-w-sm text-sm text-muted-foreground">
            Créez un projet pour définir sa politique de scan.
          </p>
        </CardContent>
      </Card>
    );
  }

  const selected = projects.find((p) => p.id === selectedId) ?? projects[0];

  return (
    <div className="space-y-6">
      <Select
        value={String(selected.id)}
        onValueChange={(v) => v && setSelectedId(Number(v))}
        items={Object.fromEntries(projects.map((p) => [String(p.id), p.name]))}
      >
        <SelectTrigger className="w-64">
          <FolderGit2 className="size-4" />
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {projects.map((p) => (
            <SelectItem key={p.id} value={String(p.id)}>
              {p.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {policy === null ? (
        <Skeleton className="h-64 w-full" />
      ) : (
        <>
          <Card className="[--card-spacing:--spacing(6)]">
            <CardHeader className="gap-1.5">
              <CardTitle className="flex items-center gap-2">
                <ShieldOff className="size-4" />
                Seuil de blocage du pipeline
              </CardTitle>
              <CardDescription>
                Si un finding non ignoré atteint cette gravité ou pire, le job
                CI/CD sort en erreur (le scan reste enregistré, seul le
                pipeline échoue).
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Select
                value={policy.fail_on_severity ?? NONE}
                onValueChange={onThresholdChange}
                disabled={savingThreshold || !policyAllowed}
                items={{
                  [NONE]: "Ne jamais bloquer",
                  critical: "Critique",
                  high: "Élevée ou pire",
                  medium: "Moyenne ou pire",
                  low: "Faible ou pire",
                }}
              >
                <SelectTrigger className="w-56">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={NONE}>Ne jamais bloquer</SelectItem>
                  <SelectItem value="critical">Critique</SelectItem>
                  <SelectItem value="high">Élevée ou pire</SelectItem>
                  <SelectItem value="medium">Moyenne ou pire</SelectItem>
                  <SelectItem value="low">Faible ou pire</SelectItem>
                </SelectContent>
              </Select>
            </CardContent>
          </Card>

          <Card className="[--card-spacing:--spacing(6)]">
            <CardHeader className="gap-1.5">
              <CardTitle>Règles ignorées (risques acceptés)</CardTitle>
              <CardDescription>
                Une règle ici ne compte plus dans le score ni dans le seuil
                ci-dessus, pour TOUTES ses occurrences sur ce projet — mais
                reste visible dans les alertes.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-5 pt-2">
              {policyAllowed ? (
              <form onSubmit={onAddRule} className="flex flex-wrap items-end gap-2">
                <div className="space-y-1.5">
                  <Label htmlFor="rule-id" className="text-xs">
                    Identifiant de règle
                  </Label>
                  <Input
                    id="rule-id"
                    placeholder="ex. CKV_AWS_20"
                    value={newRuleId}
                    onChange={(e) => setNewRuleId(e.target.value)}
                    className="w-48"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="rule-note" className="text-xs">
                    Justification (obligatoire)
                  </Label>
                  <Input
                    id="rule-note"
                    placeholder="ex. Bucket public volontaire (CDN)"
                    value={newRuleNote}
                    onChange={(e) => setNewRuleNote(e.target.value)}
                    required
                    className="w-64"
                  />
                </div>
                <Button type="submit" disabled={addingRule || !newRuleId.trim() || !newRuleNote.trim()}>
                  {addingRule ? (
                    <Loader2 className="size-4 animate-spin" />
                  ) : (
                    <Plus className="size-4" />
                  )}
                  Ajouter
                </Button>
              </form>
              ) : (
                <p className="text-sm text-muted-foreground">
                  Lecture seule : seuls les administrateurs et responsables
                  sécurité modifient la politique et les exceptions.
                </p>
              )}

              {policy.ignored_rules.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  Aucune exception pour ce projet.
                </p>
              ) : (
                <div className="space-y-2">
                  {policy.ignored_rules.map((r) => (
                    <div
                      key={r.id}
                      className="flex items-center justify-between rounded-lg border p-3"
                    >
                      <div className="flex items-center gap-3">
                        <Badge variant="outline" className="font-mono text-[11px]">
                          {r.rule_id}
                        </Badge>
                        {r.note ? (
                          <span className="text-sm text-muted-foreground">
                            {r.note}
                          </span>
                        ) : null}
                      </div>
                      {policyAllowed ? (
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        onClick={() => onRemoveRule(r.id)}
                        aria-label="Retirer l'exception"
                      >
                        <Trash2 className="size-4 text-destructive" />
                      </Button>
                      ) : null}
                    </div>
                  ))}
                </div>
              )}

              {policy.ignored_rules.length > 0 ? (
                <Alert>
                  <AlertTriangle className="size-4" />
                  <AlertTitle>Exception de politique</AlertTitle>
                  <AlertDescription>
                    Documentez toujours la justification : un auditeur externe
                    doit pouvoir comprendre pourquoi un risque a été accepté.
                  </AlertDescription>
                </Alert>
              ) : null}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
