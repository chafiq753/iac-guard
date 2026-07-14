"use client";

import * as React from "react";
import { startAuthentication } from "@simplewebauthn/browser";
import { Fingerprint, KeyRound, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import { authApi, ApiError, type UserOut } from "@/lib/auth-api";

/**
 * Étape 2FA du login. L'utilisateur choisit la méthode qu'IL a activée :
 * biométrie (WebAuthn) et/ou code (TOTP), avec les codes de secours en repli.
 */
export function MfaLoginStep({
  methods,
  onSuccess,
}: {
  methods: string[];
  onSuccess: (user: UserOut) => void;
}) {
  const hasWebauthn = methods.includes("webauthn");
  const hasTotp = methods.includes("totp");

  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [useRecovery, setUseRecovery] = React.useState(false);
  const [code, setCode] = React.useState("");
  const [recovery, setRecovery] = React.useState("");

  async function withBusy(fn: () => Promise<UserOut>) {
    setBusy(true);
    setError(null);
    try {
      onSuccess(await fn());
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : "Vérification échouée.";
      setError(msg);
    } finally {
      setBusy(false);
    }
  }

  async function onBiometric() {
    setError(null);
    setBusy(true);
    try {
      const options = await authApi.webauthnAuthOptions();
      // Ouvre Windows Hello / Touch ID : l'empreinte ne quitte pas l'appareil.
      const assertion = await startAuthentication({ optionsJSON: options as never });
      onSuccess(await authApi.webauthnAuthVerify(assertion));
    } catch (err) {
      if (err instanceof ApiError) setError(err.message);
      else if (err instanceof Error && err.name === "NotAllowedError")
        setError("Vérification biométrique annulée.");
      else setError("La vérification biométrique a échoué.");
    } finally {
      setBusy(false);
    }
  }

  async function onTotp(e: React.FormEvent) {
    e.preventDefault();
    await withBusy(() => authApi.verifyTotp(code));
  }

  async function onRecovery(e: React.FormEvent) {
    e.preventDefault();
    await withBusy(() => authApi.verifyRecovery(recovery.trim()));
  }

  return (
    <div className="space-y-5">
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      {useRecovery ? (
        <form onSubmit={onRecovery} className="space-y-3">
          <div className="space-y-2">
            <Label htmlFor="recovery">Code de récupération</Label>
            <input
              id="recovery"
              className="flex h-9 w-full rounded-lg border border-border bg-transparent px-3 py-1 text-sm font-mono shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
              placeholder="xxxx-xxxx"
              value={recovery}
              onChange={(e) => setRecovery(e.target.value)}
              autoFocus
            />
            <p className="text-xs text-muted-foreground">
              Un des codes à usage unique fournis à l&apos;activation de la 2FA.
            </p>
          </div>
          <Button type="submit" className="w-full" disabled={busy || !recovery}>
            {busy ? <Loader2 className="size-4 animate-spin" /> : null}
            Valider le code de secours
          </Button>
        </form>
      ) : (
        <>
          {hasWebauthn ? (
            <Button
              type="button"
              variant="outline"
              className="w-full"
              onClick={onBiometric}
              disabled={busy}
            >
              {busy ? (
                <Loader2 className="size-4 animate-spin" />
              ) : (
                <Fingerprint className="size-4" />
              )}
              Utiliser la biométrie
            </Button>
          ) : null}

          {hasWebauthn && hasTotp ? (
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-card px-2 text-muted-foreground">ou</span>
              </div>
            </div>
          ) : null}

          {hasTotp ? (
            <form onSubmit={onTotp} className="space-y-3">
              <div className="space-y-2">
                <Label htmlFor="otp">Code de votre application</Label>
                <InputOTP
                  id="otp"
                  maxLength={6}
                  value={code}
                  onChange={setCode}
                  containerClassName="justify-center"
                >
                  <InputOTPGroup>
                    {[0, 1, 2, 3, 4, 5].map((i) => (
                      <InputOTPSlot key={i} index={i} />
                    ))}
                  </InputOTPGroup>
                </InputOTP>
              </div>
              <Button
                type="submit"
                className="w-full"
                disabled={busy || code.length < 6}
              >
                {busy ? <Loader2 className="size-4 animate-spin" /> : null}
                Vérifier
              </Button>
            </form>
          ) : null}
        </>
      )}

      <button
        type="button"
        className="flex w-full items-center justify-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
        onClick={() => {
          setUseRecovery((v) => !v);
          setError(null);
        }}
      >
        <KeyRound className="size-3.5" />
        {useRecovery
          ? "Revenir aux méthodes habituelles"
          : "Appareil perdu ? Utiliser un code de récupération"}
      </button>
    </div>
  );
}
