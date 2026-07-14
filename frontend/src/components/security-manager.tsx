"use client";

import * as React from "react";
import { QRCodeSVG } from "qrcode.react";
import { startRegistration } from "@simplewebauthn/browser";
import {
  Check,
  Fingerprint,
  Loader2,
  Plus,
  Smartphone,
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
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { RecoveryCodesDialog } from "@/components/recovery-codes-dialog";
import { authApi, ApiError, type MfaStatus, type TotpSetup } from "@/lib/auth-api";

export function SecurityManager() {
  const [status, setStatus] = React.useState<MfaStatus | null>(null);
  const [recoveryCodes, setRecoveryCodes] = React.useState<string[] | null>(null);

  const load = React.useCallback(async () => {
    try {
      setStatus(await authApi.mfaStatus());
    } catch (err) {
      if (err instanceof ApiError) toast.error(err.message);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  if (status === null) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <WebAuthnCard status={status} onChange={load} onCodes={setRecoveryCodes} />
      <TotpCard status={status} onChange={load} onCodes={setRecoveryCodes} />
      <RecoveryCard status={status} onCodes={setRecoveryCodes} />
      <RecoveryCodesDialog
        codes={recoveryCodes}
        onClose={() => setRecoveryCodes(null)}
      />
    </div>
  );
}

// --------------------------------------------------------------------------- #
// Biométrie (WebAuthn)
// --------------------------------------------------------------------------- #

function WebAuthnCard({
  status,
  onChange,
  onCodes,
}: {
  status: MfaStatus;
  onChange: () => Promise<void>;
  onCodes: (c: string[]) => void;
}) {
  const [busy, setBusy] = React.useState(false);

  async function enroll() {
    setBusy(true);
    try {
      const options = await authApi.webauthnRegisterOptions();
      // Déclenche Windows Hello / Touch ID : la clé privée reste dans le TPM.
      const attestation = await startRegistration({ optionsJSON: options as never });
      const deviceName =
        typeof navigator !== "undefined" && navigator.platform
          ? navigator.platform
          : "Cet appareil";
      const result = await authApi.webauthnRegisterVerify(attestation, deviceName);
      await onChange();
      if (result.recovery_codes.length > 0) onCodes(result.recovery_codes);
      toast.success("Appareil biométrique enregistré.");
    } catch (err) {
      if (err instanceof ApiError) toast.error(err.message);
      else if (err instanceof Error && err.name === "NotAllowedError")
        toast.error("Enregistrement annulé.");
      else toast.error("Impossible d'enregistrer l'appareil.");
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: number) {
    try {
      await authApi.webauthnDeleteDevice(id);
      await onChange();
      toast.success("Appareil supprimé.");
    } catch (err) {
      if (err instanceof ApiError) toast.error(err.message);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2">
              <Fingerprint className="size-4.5" />
              Biométrie / clé de sécurité
              {status.webauthn_enabled ? (
                <Badge className="bg-emerald-500/12 text-emerald-700 dark:text-emerald-300">
                  Activée
                </Badge>
              ) : null}
            </CardTitle>
            <CardDescription>
              Windows Hello, Touch ID ou clé physique. Votre empreinte ne quitte
              jamais l&apos;appareil.
            </CardDescription>
          </div>
          <Button onClick={enroll} disabled={busy} size="sm">
            {busy ? <Loader2 className="size-4 animate-spin" /> : <Plus className="size-4" />}
            Ajouter
          </Button>
        </div>
      </CardHeader>
      {status.devices.length > 0 ? (
        <CardContent className="space-y-2">
          {status.devices.map((d) => (
            <div
              key={d.id}
              className="flex items-center justify-between rounded-lg border p-3"
            >
              <div className="flex items-center gap-3">
                <Smartphone className="size-4 text-muted-foreground" />
                <div>
                  <p className="text-sm font-medium">{d.name}</p>
                  <p className="text-xs text-muted-foreground">
                    Ajouté le{" "}
                    {new Date(d.created_at).toLocaleDateString("fr-FR")}
                  </p>
                </div>
              </div>
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={() => remove(d.id)}
                aria-label="Supprimer l'appareil"
              >
                <Trash2 className="size-4 text-destructive" />
              </Button>
            </div>
          ))}
        </CardContent>
      ) : null}
    </Card>
  );
}

// --------------------------------------------------------------------------- #
// TOTP (application d'authentification)
// --------------------------------------------------------------------------- #

function TotpCard({
  status,
  onChange,
  onCodes,
}: {
  status: MfaStatus;
  onChange: () => Promise<void>;
  onCodes: (c: string[]) => void;
}) {
  const [open, setOpen] = React.useState(false);
  const [setup, setSetup] = React.useState<TotpSetup | null>(null);
  const [code, setCode] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  async function startSetup() {
    setBusy(true);
    try {
      setSetup(await authApi.totpSetup());
      setCode("");
      setOpen(true);
    } catch (err) {
      if (err instanceof ApiError) toast.error(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function confirm() {
    setBusy(true);
    try {
      const result = await authApi.totpConfirm(code);
      setOpen(false);
      await onChange();
      if (result.recovery_codes.length > 0) onCodes(result.recovery_codes);
      toast.success("Application d'authentification activée.");
    } catch {
      toast.error("Code invalide. Réessayez.");
    } finally {
      setBusy(false);
    }
  }

  async function disable() {
    try {
      await authApi.totpDisable();
      await onChange();
      toast.success("TOTP désactivé.");
    } catch (err) {
      if (err instanceof ApiError) toast.error(err.message);
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between gap-4">
            <div className="space-y-1">
              <CardTitle className="flex items-center gap-2">
                <Smartphone className="size-4.5" />
                Application d&apos;authentification
                {status.totp_enabled ? (
                  <Badge className="bg-emerald-500/12 text-emerald-700 dark:text-emerald-300">
                    Activée
                  </Badge>
                ) : null}
              </CardTitle>
              <CardDescription>
                Google Authenticator, Authy… Un code à 6 chiffres qui change
                toutes les 30 secondes.
              </CardDescription>
            </div>
            {status.totp_enabled ? (
              <Button variant="outline" size="sm" onClick={disable}>
                Désactiver
              </Button>
            ) : (
              <Button size="sm" onClick={startSetup} disabled={busy}>
                {busy ? <Loader2 className="size-4 animate-spin" /> : null}
                Configurer
              </Button>
            )}
          </div>
        </CardHeader>
      </Card>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Configurer l&apos;application</DialogTitle>
            <DialogDescription>
              Scannez ce QR code, puis saisissez le code affiché pour confirmer.
            </DialogDescription>
          </DialogHeader>

          {setup ? (
            <div className="space-y-4">
              <div className="flex justify-center rounded-lg bg-white p-4">
                <QRCodeSVG value={setup.otpauth_uri} size={180} />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Ou saisissez la clé manuellement</Label>
                <Input
                  readOnly
                  value={setup.secret}
                  className="font-mono text-xs"
                  onFocus={(e) => e.currentTarget.select()}
                />
              </div>
              <div className="space-y-2">
                <Label>Code de vérification</Label>
                <InputOTP
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
                className="w-full"
                onClick={confirm}
                disabled={busy || code.length < 6}
              >
                {busy ? (
                  <Loader2 className="size-4 animate-spin" />
                ) : (
                  <Check className="size-4" />
                )}
                Activer
              </Button>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </>
  );
}

// --------------------------------------------------------------------------- #
// Codes de récupération
// --------------------------------------------------------------------------- #

function RecoveryCard({
  status,
  onCodes,
}: {
  status: MfaStatus;
  onCodes: (c: string[]) => void;
}) {
  const [busy, setBusy] = React.useState(false);
  const enabled = status.totp_enabled || status.webauthn_enabled;

  async function regenerate() {
    setBusy(true);
    try {
      const { codes } = await authApi.regenerateRecoveryCodes();
      onCodes(codes);
      toast.success("Nouveaux codes générés. Les anciens sont invalidés.");
    } catch (err) {
      if (err instanceof ApiError) toast.error(err.message);
    } finally {
      setBusy(false);
    }
  }

  if (!enabled) return null;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <CardTitle>Codes de récupération</CardTitle>
            <CardDescription>
              {status.recovery_codes_remaining} code(s) restant(s). Ils
              permettent de vous connecter si vous perdez vos appareils.
            </CardDescription>
          </div>
          <Button variant="outline" size="sm" onClick={regenerate} disabled={busy}>
            {busy ? <Loader2 className="size-4 animate-spin" /> : null}
            Régénérer
          </Button>
        </div>
      </CardHeader>
    </Card>
  );
}
