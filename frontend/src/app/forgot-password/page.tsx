"use client";

import * as React from "react";
import Link from "next/link";
import { Loader2, MailCheck } from "lucide-react";

import { AuthShell } from "@/components/auth-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { authApi } from "@/lib/auth-api";
import { useLang } from "@/lib/i18n";

export default function ForgotPasswordPage() {
  const { t } = useLang();
  const [email, setEmail] = React.useState("");
  const [sent, setSent] = React.useState(false);
  const [loading, setLoading] = React.useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    try {
      await authApi.forgotPassword(email);
    } finally {
      // Réponse identique quoi qu'il arrive (anti-énumération, cf. backend).
      setSent(true);
      setLoading(false);
    }
  }

  return (
    <AuthShell
      title={t("forgot.title")}
      description={t("forgot.desc")}
      footer={
        <Link href="/login" className="font-medium text-foreground hover:underline">
          {t("forgot.back")}
        </Link>
      }
    >
      {sent ? (
        <Alert>
          <MailCheck className="size-4" />
          <AlertDescription>{t("forgot.sent")}</AlertDescription>
        </Alert>
      ) : (
        <form onSubmit={onSubmit} className="space-y-4" noValidate>
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
              autoFocus
              required
            />
          </div>
          <Button type="submit" className="w-full" disabled={loading || !email}>
            {loading ? <Loader2 className="size-4 animate-spin" /> : null}
            {t("forgot.submit")}
          </Button>
        </form>
      )}
    </AuthShell>
  );
}
