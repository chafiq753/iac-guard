"use client";

import { Copy, Download, ShieldAlert } from "lucide-react";
import { toast } from "sonner";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

/** Affiche les codes de secours UNE fois : ils ne sont plus jamais récupérables. */
export function RecoveryCodesDialog({
  codes,
  onClose,
}: {
  codes: string[] | null;
  onClose: () => void;
}) {
  const open = codes !== null && codes.length > 0;

  function copyAll() {
    void navigator.clipboard.writeText((codes ?? []).join("\n"));
    toast.success("Codes copiés dans le presse-papiers.");
  }

  function download() {
    const blob = new Blob([(codes ?? []).join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "iac-guard-recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Vos codes de récupération</DialogTitle>
          <DialogDescription>
            Conservez-les hors ligne. Ils permettent de vous connecter si vous
            perdez votre appareil.
          </DialogDescription>
        </DialogHeader>

        <Alert>
          <ShieldAlert className="size-4" />
          <AlertTitle>Affichés une seule fois</AlertTitle>
          <AlertDescription>
            Nous ne pouvons pas vous les remontrer. Chaque code ne sert
            qu&apos;une fois.
          </AlertDescription>
        </Alert>

        <div className="grid grid-cols-2 gap-2 rounded-lg border bg-muted/40 p-3 font-mono text-sm">
          {(codes ?? []).map((c) => (
            <span key={c} className="tabular-nums">
              {c}
            </span>
          ))}
        </div>

        <DialogFooter className="gap-2 sm:justify-between">
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={copyAll}>
              <Copy className="size-4" /> Copier
            </Button>
            <Button variant="outline" size="sm" onClick={download}>
              <Download className="size-4" /> Télécharger
            </Button>
          </div>
          <Button size="sm" onClick={onClose}>
            J&apos;ai sauvegardé mes codes
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
