"use client";

import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Check, Loader2, X } from "lucide-react";
import { toast } from "sonner";

import { AuthShell } from "@/components/auth-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { authApi, ApiError } from "@/lib/auth-api";
import { useLang, type TranslationKey } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const PASSWORD_MIN = 12;

// Miroir de la politique appliquée par le serveur (UserCreate) : le serveur
// reste la référence, ceci n'est qu'un retour visuel immédiat.
const PASSWORD_RULES: { labelKey: TranslationKey; test: (v: string) => boolean }[] = [
  { labelKey: "rule.length", test: (v) => v.length >= PASSWORD_MIN },
  { labelKey: "rule.lower", test: (v) => /[a-z]/.test(v) },
  { labelKey: "rule.upper", test: (v) => /[A-Z]/.test(v) },
  { labelKey: "rule.digit", test: (v) => /\d/.test(v) },
  { labelKey: "rule.special", test: (v) => /[^A-Za-z0-9]/.test(v) },
];

function PasswordChecklist({ value }: { value: string }) {
  const { t } = useLang();
  return (
    <ul className="space-y-1 pt-1">
      {PASSWORD_RULES.map(({ labelKey, test }) => {
        const ok = test(value);
        return (
          <li
            key={labelKey}
            className={cn(
              "flex items-center gap-1.5 text-xs",
              ok ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground"
            )}
          >
            {ok ? <Check className="size-3.5" /> : <X className="size-3.5" />}
            {t(labelKey)}
          </li>
        );
      })}
    </ul>
  );
}

export default function SignupPage() {
  const router = useRouter();
  const { t } = useLang();
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);

  const rulesOk = PASSWORD_RULES.every((r) => r.test(password));
  const mismatch = confirm.length > 0 && confirm !== password;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!rulesOk) {
      setError(t("signup.rulesIncomplete"));
      return;
    }
    if (password !== confirm) {
      setError(t("signup.mismatch"));
      return;
    }

    setLoading(true);
    try {
      await authApi.register(email, password);
      // Pas de connexion automatique : l'utilisateur passe par la page de
      // login et saisit ses identifiants lui-même.
      toast.success(t("signup.created"));
      router.push("/login");
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? err.status === 409
            ? t("signup.emailTaken")
            : err.message
          : t("login.genericError");
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthShell
      title={t("signup.title")}
      description={t("signup.desc")}
      footer={
        <>
          {t("signup.haveAccount")}{" "}
          <Link href="/login" className="font-medium text-foreground hover:underline">
            {t("signup.signIn")}
          </Link>
        </>
      }
    >
      <form onSubmit={onSubmit} className="space-y-4" noValidate>
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}

        <div className="space-y-2">
          <Label htmlFor="email">{t("login.email")}</Label>
          <Input
            id="email"
            type="email"
            autoComplete="email"
            autoCapitalize="none"
            spellCheck={false}
            dir="ltr"
            placeholder="vous@entreprise.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="password">{t("login.password")}</Label>
          <Input
            id="password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            aria-invalid={password.length > 0 && !rulesOk}
            required
          />
          <PasswordChecklist value={password} />
        </div>

        <div className="space-y-2">
          <Label htmlFor="confirm">{t("signup.confirm")}</Label>
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
            <p className="text-xs text-destructive">{t("signup.mismatch")}</p>
          ) : null}
        </div>

        <Button
          type="submit"
          className="w-full"
          disabled={loading || !rulesOk || mismatch || !email}
        >
          {loading ? <Loader2 className="size-4 animate-spin" /> : null}
          {t("signup.submit")}
        </Button>
      </form>
    </AuthShell>
  );
}
