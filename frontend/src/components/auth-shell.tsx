"use client";

import { Languages } from "lucide-react";

import { ZenithLogo } from "@/components/zenith-logo";
import { Button } from "@/components/ui/button";
import { useLang } from "@/lib/i18n";

/** Cadre centré partagé par les pages login / signup / 2FA / mot de passe oublié.

Porte le sélecteur FR/العربية et bascule toute la zone en RTL quand l'arabe
est actif. */
export function AuthShell({
  title,
  description,
  children,
  footer,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
}) {
  const { lang, setLang, t, dir } = useLang();

  return (
    <div
      dir={dir}
      className="flex min-h-svh flex-col items-center justify-center gap-6 bg-muted/40 px-4 py-10"
    >
      <div className="flex w-full max-w-sm items-center justify-between">
        {/* Logo ZenithSoft : currentColor -> navy en clair, blanc en sombre. */}
        <div className="flex flex-col gap-0.5">
          <ZenithLogo className="h-9 w-auto text-foreground" />
          <span className="ps-1 text-[11px] font-medium tracking-wide text-muted-foreground">
            iac-guard
          </span>
        </div>

        {/* Toggle de langue, visible dès le login. */}
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => setLang(lang === "fr" ? "ar" : "fr")}
          aria-label={lang === "fr" ? "التبديل إلى العربية" : "Passer en français"}
        >
          <Languages className="size-4" />
          {lang === "fr" ? "العربية" : "Français"}
        </Button>
      </div>

      <div className="w-full max-w-sm">
        <div className="rounded-xl border bg-card p-6 shadow-sm sm:p-8">
          <div className="mb-6 space-y-1.5">
            <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
            {description ? (
              <p className="text-sm text-muted-foreground">{description}</p>
            ) : null}
          </div>
          {children}
        </div>
        {footer ? (
          <p className="mt-4 text-center text-sm text-muted-foreground">{footer}</p>
        ) : null}
      </div>

      <p className="max-w-sm text-center text-xs text-muted-foreground">
        {t("tagline")}
      </p>
    </div>
  );
}
