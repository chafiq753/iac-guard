"use client";

import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { startAuthentication } from "@simplewebauthn/browser";
import { ArrowLeft, Fingerprint, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { AuthShell } from "@/components/auth-shell";
import { MfaLoginStep } from "@/components/mfa-login-step";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { authApi, ApiError, type UserOut } from "@/lib/auth-api";
import { useAuth } from "@/components/auth-provider";
import { useLang } from "@/lib/i18n";

type Step = "email" | "auth" | "mfa";

/** Logo GitHub (lucide a retiré les icônes de marques). */
function GithubIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden className="size-4" {...props}>
      <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.55 0-.27-.01-1.17-.02-2.12-3.2.7-3.87-1.36-3.87-1.36-.52-1.33-1.28-1.68-1.28-1.68-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.03 1.76 2.69 1.25 3.35.96.1-.75.4-1.25.72-1.54-2.55-.29-5.23-1.28-5.23-5.68 0-1.26.45-2.28 1.18-3.09-.12-.29-.51-1.46.11-3.05 0 0 .96-.31 3.15 1.18a10.9 10.9 0 0 1 5.74 0c2.19-1.49 3.15-1.18 3.15-1.18.62 1.59.23 2.76.11 3.05.73.81 1.18 1.83 1.18 3.09 0 4.41-2.69 5.38-5.25 5.67.41.35.77 1.05.77 2.12 0 1.53-.01 2.76-.01 3.14 0 .3.2.66.8.55A10.52 10.52 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5Z" />
    </svg>
  );
}

export default function LoginPage() {
  const router = useRouter();
  const { refresh } = useAuth();
  const { t } = useLang();

  const [step, setStep] = React.useState<Step>("email");
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  // Méthodes renvoyées par l'API pour CE compte (étape 1 -> étape 2).
  const [methods, setMethods] = React.useState<string[]>(["password"]);
  // Méthodes 2FA (si le compte en a activé une après le mot de passe).
  const [mfaMethods, setMfaMethods] = React.useState<string[]>([]);
  const [error, setError] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);

  const offersWebauthn = methods.includes("webauthn");
  const offersGithub = methods.includes("github"); // futur : OAuth GitHub lié

  async function finish(user: UserOut) {
    await refresh();
    toast.success(user.email);
    router.push("/");
  }

  // Étape 1 : e-mail -> quelles méthodes proposer ?
  async function onContinue(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const { methods } = await authApi.loginMethods(email);
      setMethods(methods);
      setStep("auth");
    } catch {
      setError(t("login.genericError"));
    } finally {
      setLoading(false);
    }
  }

  // Étape 2a : passkey (proposée en priorité si le compte en a une).
  async function onBiometric() {
    setError(null);
    setLoading(true);
    try {
      const options = await authApi.webauthnLoginOptions(email);
      const assertion = await startAuthentication({ optionsJSON: options as never });
      await finish(await authApi.webauthnLoginVerify(email, assertion));
    } catch (err) {
      if (err instanceof ApiError) setError(err.message);
      else if (err instanceof Error && err.name === "NotAllowedError")
        setError(t("login.biometricCancelled"));
      else setError(t("login.biometricFailed"));
    } finally {
      setLoading(false);
    }
  }

  // Étape 2b : mot de passe (repli universel, toujours présent).
  async function onPassword(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const result = await authApi.login(email, password);
      if (result.mfa_required) {
        setMfaMethods(result.methods);
        setStep("mfa");
      } else if (result.user) {
        await finish(result.user);
      }
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? err.status === 429
            ? t("login.locked")
            : t("login.badCredentials")
          : t("login.genericError");
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  if (step === "mfa") {
    return (
      <AuthShell
        title={t("login.mfaTitle")}
        description={t("login.mfaDesc")}
        footer={
          <button
            className="hover:underline"
            onClick={() => {
              setStep("email");
              setPassword("");
            }}
          >
            {t("login.restart")}
          </button>
        }
      >
        <MfaLoginStep methods={mfaMethods} onSuccess={finish} />
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title={t("login.title")}
      description={t("login.desc")}
      footer={
        <>
          {t("login.noAccount")}{" "}
          <Link href="/signup" className="font-medium text-foreground hover:underline">
            {t("login.create")}
          </Link>
        </>
      }
    >
      {step === "email" ? (
        /* ---- Étape 1 : identifiant ---- */
        <form onSubmit={onContinue} className="space-y-4" noValidate>
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
              autoComplete="email username webauthn"
              autoCapitalize="none"
              spellCheck={false}
              dir="ltr"
              placeholder="vous@entreprise.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoFocus
              required
            />
          </div>

          <Button type="submit" className="w-full" disabled={loading || !email}>
            {loading ? <Loader2 className="size-4 animate-spin" /> : null}
            {t("login.continue")}
          </Button>
        </form>
      ) : (
        /* ---- Étape 2 : selon les méthodes du compte ---- */
        <div className="space-y-4">
          <button
            type="button"
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
            onClick={() => {
              setStep("email");
              setPassword("");
              setError(null);
            }}
          >
            <ArrowLeft className="size-3.5 rtl:rotate-180" />
            <span dir="ltr">{email}</span> — {t("login.changeEmail")}
          </button>

          {error ? (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}

          {/* Passkey en priorité visuelle quand le compte en a une. */}
          {offersWebauthn ? (
            <>
              <Button
                type="button"
                className="w-full"
                onClick={onBiometric}
                disabled={loading}
              >
                {loading ? (
                  <Loader2 className="size-4 animate-spin" />
                ) : (
                  <Fingerprint className="size-4" />
                )}
                {t("login.biometric")}
              </Button>
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-card px-2 text-muted-foreground">
                    {t("login.or")}
                  </span>
                </div>
              </div>
            </>
          ) : null}

          {/* Mot de passe : repli universel, toujours accessible. */}
          <form onSubmit={onPassword} className="space-y-4" noValidate>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="password">{t("login.password")}</Label>
                <Link
                  href="/forgot-password"
                  className="text-xs text-muted-foreground hover:text-foreground hover:underline"
                >
                  {t("login.forgot")}
                </Link>
              </div>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoFocus={!offersWebauthn}
                required
              />
            </div>

            <Button
              type="submit"
              variant={offersWebauthn ? "outline" : "default"}
              className="w-full"
              disabled={loading || !password}
            >
              {loading ? <Loader2 className="size-4 animate-spin" /> : null}
              {t("login.submit")}
            </Button>
          </form>

          {/* GitHub : visible uniquement si le compte a été lié (OAuth à venir). */}
          {offersGithub ? (
            <Button type="button" variant="outline" className="w-full" disabled>
              <GithubIcon />
              {t("login.github")}
            </Button>
          ) : null}
        </div>
      )}
    </AuthShell>
  );
}
