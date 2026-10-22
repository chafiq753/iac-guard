"use client";

import * as React from "react";
import {
  AlertTriangle,
  Boxes,
  Check,
  ExternalLink,
  FileCode2,
  FolderGit2,
  ShieldAlert,
  Undo2,
} from "lucide-react";

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import { ExceptionBadge, SeverityBadge, StatusBadge } from "@/components/severity-badge";
import {
  CATEGORY_LABELS,
  SOURCE_LABELS,
  explainFinding,
} from "@/lib/finding-explainer";
import type { Alert, AlertStatus } from "@/lib/data";

type OnTriage = (alert: Alert, status: AlertStatus, note?: string) => void;

/** Checkov préfixe ses chemins d'un "/" — ni GitHub ni l'affichage n'en veulent. */
function cleanPath(file: string): string {
  return file.replace(/^\/+/, "");
}

/** "main.tf:102", ou "main.tf:16-22" quand le finding couvre un bloc. */
function locationLabel(alert: Alert): string | null {
  if (!alert.file) return null;
  const path = cleanPath(alert.file);
  if (!alert.lineStart) return path;
  const end =
    alert.lineEnd && alert.lineEnd !== alert.lineStart ? `-${alert.lineEnd}` : "";
  return `${path}:${alert.lineStart}${end}`;
}

/**
 * Lien vers la ligne exacte, AU COMMIT SCANNÉ — pas sur la branche par
 * défaut : le fichier a pu bouger depuis, et le lien pointerait à côté.
 * Suppose un dépôt GitHub (le pipeline fourni est GitHub Actions).
 */
function codeUrl(alert: Alert): string | null {
  if (!alert.repo || !alert.commitSha || !alert.file) return null;
  const anchor = alert.lineStart
    ? `#L${alert.lineStart}${
        alert.lineEnd && alert.lineEnd !== alert.lineStart ? `-L${alert.lineEnd}` : ""
      }`
    : "";
  return `https://github.com/${alert.repo}/blob/${alert.commitSha}/${cleanPath(
    alert.file
  )}${anchor}`;
}

/**
 * Panneau latéral : le détail complet d'une alerte, en langage clair.
 * Répond à "comment, quand, pourquoi, qu'est-ce que ça peut faire" — pas
 * juste les champs bruts du scanner.
 */
export function FindingDetailSheet({
  alert,
  open,
  onOpenChange,
  onTriage,
}: {
  alert: Alert | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onTriage?: OnTriage;
}) {
  // Justification jointe à la décision (tracée dans le journal d'audit).
  // Vidée à chaque changement de finding (ajustement d'état pendant le rendu).
  const [note, setNote] = React.useState("");
  const [noteFor, setNoteFor] = React.useState(alert?.id);
  if (noteFor !== alert?.id) {
    setNoteFor(alert?.id);
    setNote("");
  }

  if (!alert) return null;

  const decide = (status: AlertStatus) => onTriage?.(alert, status, note.trim() || undefined);

  const codeLocation = locationLabel(alert);
  const codeHref = codeUrl(alert);

  const explanation = explainFinding({
    rule_id: alert.ruleId,
    category: alert.category,
  });

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={alert.status} />
            {alert.excepted ? <ExceptionBadge /> : null}
          </div>
          <SheetTitle className="text-left text-base leading-snug">
            {alert.title}
          </SheetTitle>
          <SheetDescription className="text-left">
            Détecté le{" "}
            {new Date(alert.detectedAt).toLocaleString("fr-FR", {
              day: "numeric",
              month: "long",
              year: "numeric",
              hour: "2-digit",
              minute: "2-digit",
            })}
          </SheetDescription>
        </SheetHeader>

        <div className="space-y-6 px-4 pb-6">
          {/* --- Où --- */}
          <div className="grid gap-2 rounded-lg border bg-muted/30 p-3 text-sm">
            <div className="flex items-center gap-2 text-muted-foreground">
              <FolderGit2 className="size-4 shrink-0" />
              <span className="truncate">
                {alert.projectName ? `${alert.projectName} · ` : ""}
                {alert.repo}
              </span>
            </div>

            {/* La ressource n'existe que pour les findings d'infrastructure.
                On la masque quand elle ne fait que répéter le fichier (repli
                d'affichage du tableau pour les secrets). */}
            {alert.resource && alert.resource !== "—" && alert.resource !== alert.file ? (
              <div className="flex items-center gap-2 text-muted-foreground">
                <Boxes className="size-4 shrink-0" />
                <span className="truncate font-mono text-xs">{alert.resource}</span>
              </div>
            ) : null}

            {/* L'emplacement exact : c'est CE qui permet d'aller corriger. */}
            {codeLocation ? (
              <div className="flex items-center gap-2">
                <FileCode2 className="size-4 shrink-0 text-muted-foreground" />
                {codeHref ? (
                  <a
                    href={codeHref}
                    target="_blank"
                    rel="noreferrer"
                    className="truncate font-mono text-xs font-medium underline underline-offset-2 hover:text-foreground"
                  >
                    {codeLocation}
                    <ExternalLink className="ml-1 inline size-3 align-[-1px]" />
                  </a>
                ) : (
                  <span className="truncate font-mono text-xs font-medium">
                    {codeLocation}
                  </span>
                )}
              </div>
            ) : null}
          </div>

          {/* --- Quoi (source / catégorie / règle) --- */}
          <div>
            <h3 className="mb-2 text-sm font-semibold">Détails techniques</h3>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 text-sm">
              <dt className="text-muted-foreground">Détecté par</dt>
              <dd>{SOURCE_LABELS[alert.source] ?? alert.source}</dd>
              <dt className="text-muted-foreground">Catégorie</dt>
              <dd>{CATEGORY_LABELS[alert.category] ?? alert.category}</dd>
              <dt className="text-muted-foreground">Règle</dt>
              <dd>
                <Badge variant="outline" className="font-mono text-[11px]">
                  {alert.ruleId}
                </Badge>
              </dd>
            </dl>
          </div>

          <Separator />

          {/* --- Pourquoi c'est un risque --- */}
          <div className="space-y-3">
            <div className="flex gap-2">
              <ShieldAlert className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400" />
              <div>
                <h3 className="text-sm font-semibold">Pourquoi c&apos;est un risque</h3>
                <p className="mt-1 text-sm text-muted-foreground">
                  {explanation.impact}
                </p>
              </div>
            </div>
            <div className="flex gap-2">
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-red-600 dark:text-red-400" />
              <div>
                <h3 className="text-sm font-semibold">Ce qu&apos;un attaquant peut en faire</h3>
                <p className="mt-1 text-sm text-muted-foreground">
                  {explanation.exploit}
                </p>
              </div>
            </div>
          </div>

          <Separator />

          {/* --- Comment corriger --- */}
          <div>
            <h3 className="mb-1 text-sm font-semibold">Comment corriger</h3>
            <p className="text-sm text-muted-foreground">
              {alert.remediation || explanation.fix}
            </p>
          </div>

          {alert.status !== "open" ? (
            <div className="rounded-lg border bg-muted/30 p-3 text-sm text-muted-foreground">
              Statut actuel : <StatusBadge status={alert.status} />
            </div>
          ) : null}

          <Separator />

          {/* --- Actions de triage (absentes pour les rôles en lecture seule) --- */}
          {onTriage ? (
          <div className="space-y-2">
            <h3 className="text-sm font-semibold">Actions</h3>
            <div className="space-y-1.5">
              <Label htmlFor="triage-note" className="text-xs">
                Note / justification
              </Label>
              <Textarea
                id="triage-note"
                placeholder="ex. Risque accepté : base isolée dans un VPC privé, revue au T1"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                maxLength={2000}
              />
            </div>
            <div className="flex flex-wrap gap-2">
              {alert.status === "open" ? (
                <>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => decide("acknowledged")}
                  >
                    Acknowledge
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => decide("resolved")}
                  >
                    <Check className="size-4" />
                    Marquer résolu
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => decide("false_positive")}
                  >
                    Faux positif
                  </Button>
                </>
              ) : (
                <>
                  {alert.status === "acknowledged" ? (
                    <Button
                      size="sm"
                      onClick={() => decide("resolved")}
                    >
                      <Check className="size-4" />
                      Marquer résolu
                    </Button>
                  ) : null}
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => decide("open")}
                  >
                    <Undo2 className="size-4" />
                    Ré-ouvrir
                  </Button>
                </>
              )}
            </div>
          </div>
          ) : null}
        </div>
      </SheetContent>
    </Sheet>
  );
}
