"use client";

import * as React from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Check, Loader2, X } from "lucide-react";
import { toast } from "sonner";

import { AuthShell } from "@/components/auth-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { ApiError } from "@/lib/auth-api";
import { adminApi } from "@/lib/admin-api";
import { cn } from "@/lib/utils";

const PASSWORD_MIN = 12;

// Miroir de la politique serveur (InvitationAcceptIn réutilise la même règle
// que UserCreate) : retour visuel immédiat, le serveur reste la référence.
const PASSWORD_RULES: { label: string; test: (v: string) => boolean }[] = [
  { label: `Au moins ${PASSWORD_MIN} caractères`, test: (v) => v.length >= PASSWORD_MIN },
  { label: "Une minuscule", test: (v) => /[a-z]/.test(v) },
  { label: "Une majuscule", test: (v) => /[A-Z]/.test(v) },
  { label: "Un chiffre", test: (v) => /\d/.test(v) },
  { label: "Un caractère spécial", test: (v) => /[^A-Za-z0-9]/.test(v) },
];

function AcceptInviteForm() {
  const router = useRouter();
  const params = useSearchParams();
  const token = params.get("token");

  const [password, setPassword] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);

  const rulesOk = PASSWORD_RULES.every((r) => r.test(password));
  const mismatch = confirm.length > 0 && confirm !== password;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!token) return;

    if (!rulesOk) {
      setError("Le mot de passe ne respecte pas encore toutes les règles.");
      return;
    }
    if (password !== confirm) {
      setError("Les deux mots de passe ne correspondent pas.");
      return;
    }

    setLoading(true);
    try {
      await adminApi.acceptInvitation(token, password);
      toast.success("Compte activé. Vous pouvez maintenant vous connecter.");
      router.push("/login");
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : "Impossible d'activer le compte. Réessayez."
      );
    } finally {
      setLoading(false);
    }
  }

  if (!token) {
    return (
      <AuthShell
        title="Lien invalide"
        description="Ce lien d'invitation est incomplet."
      >
        <Alert variant="destructive">
          <AlertDescription>
            Aucun jeton d&apos;invitation trouvé dans l&apos;adresse. Utilisez le
            lien reçu par e-mail, ou demandez à votre administrateur de vous
            renvoyer une invitation.
          </AlertDescription>
        </Alert>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Activer votre compte"
      description="Choisissez un mot de passe pour finaliser votre inscription."
    >
      <form onSubmit={onSubmit} className="space-y-4" noValidate>
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}

        <div className="space-y-2">
          <Label htmlFor="password">Mot de passe</Label>
          <Input
            id="password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            aria-invalid={password.length > 0 && !rulesOk}
            required
          />
          <ul className="space-y-1 pt-1">
            {PASSWORD_RULES.map(({ label, test }) => {
              const ok = test(password);
              return (
                <li
                  key={label}
                  className={cn(
                    "flex items-center gap-1.5 text-xs",
                    ok
                      ? "text-emerald-600 dark:text-emerald-400"
                      : "text-muted-foreground"
                  )}
                >
                  {ok ? <Check className="size-3.5" /> : <X className="size-3.5" />}
                  {label}
                </li>
              );
            })}
          </ul>
        </div>

        <div className="space-y-2">
          <Label htmlFor="confirm">Confirmer le mot de passe</Label>
          <Input
            id="confirm"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            aria-invalid={mismatch}
            required
          />
          {mismatch ? (
            <p className="text-xs text-destructive">
              Les deux mots de passe ne correspondent pas.
            </p>
          ) : null}
        </div>

        <Button
          type="submit"
          className="w-full"
          disabled={loading || !rulesOk || mismatch}
        >
          {loading ? <Loader2 className="size-4 animate-spin" /> : null}
          Activer mon compte
        </Button>
      </form>
    </AuthShell>
  );
}

export default function AcceptInvitePage() {
  // `useSearchParams` impose un boundary Suspense au prerender.
  return (
    <React.Suspense
      fallback={
        <div className="flex min-h-svh items-center justify-center">
          <Loader2 className="size-6 animate-spin text-muted-foreground" />
        </div>
      }
    >
      <AcceptInviteForm />
    </React.Suspense>
  );
}
