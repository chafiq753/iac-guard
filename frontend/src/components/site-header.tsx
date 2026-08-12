"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Bell, Search, LogOut, Settings, CircleHelp, Inbox } from "lucide-react";

import { useAuth } from "@/components/auth-provider";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { SeverityBadge } from "@/components/severity-badge";
import { platformApi, type FindingWithProject } from "@/lib/platform-api";
import type { Severity } from "@/lib/data";

/** Titre + sous-titre du header, par route — évite qu'il reste figé sur "Dashboard". */
const PAGE_TITLES: Record<string, { title: string; subtitle: string }> = {
  "/": { title: "Dashboard", subtitle: "Security posture overview" },
  "/projects": { title: "Projets", subtitle: "Dépôts surveillés et tokens d'ingestion" },
  "/alerts": { title: "Alertes", subtitle: "Toutes les alertes, tous projets confondus" },
  "/security": { title: "Sécurité", subtitle: "Authentification et appareils" },
  "/settings": { title: "Settings", subtitle: "Compte, sécurité, politiques et audit" },
};

export function SiteHeader() {
  const { user, logout } = useAuth();
  const pathname = usePathname();
  const router = useRouter();

  const [query, setQuery] = React.useState("");
  const [openAlerts, setOpenAlerts] = React.useState<FindingWithProject[]>([]);
  const [openCount, setOpenCount] = React.useState(0);

  // Notifications réelles : les alertes ouvertes, tous projets confondus,
  // triées par gravité (l'API renvoie déjà les plus graves en premier).
  React.useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const page = await platformApi.listAlerts({ status: "open", page_size: 5 });
        if (cancelled) return;
        setOpenAlerts(page.items);
        setOpenCount(page.total);
      } catch {
        if (!cancelled) {
          setOpenAlerts([]);
          setOpenCount(0);
        }
      }
    }
    void load();
    // Rafraîchissement discret : une nouvelle alerte apparaît sans recharger.
    const interval = setInterval(() => void load(), 30_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [pathname]);

  const email = user?.email ?? "";
  const displayName = user?.name || email.split("@")[0] || "Mon compte";
  const initials = (user?.name || email || "··")
    .split(/[\s@.]+/)
    .slice(0, 2)
    .map((s) => s[0]?.toUpperCase() ?? "")
    .join("") || "··";

  const page = PAGE_TITLES[pathname] ?? PAGE_TITLES["/"];

  function onSearch(e: React.FormEvent) {
    e.preventDefault();
    const q = query.trim();
    router.push(q ? `/alerts?q=${encodeURIComponent(q)}` : "/alerts");
  }

  return (
    <header className="sticky top-0 z-30 flex h-16 shrink-0 items-center gap-2 border-b bg-background/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/80">
      <SidebarTrigger className="-ml-1" />
      <Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-5" />

      <div className="hidden md:block">
        <h1 className="text-sm font-semibold">{page.title}</h1>
        <p className="text-xs text-muted-foreground">{page.subtitle}</p>
      </div>

      <div className="ml-auto flex items-center gap-2">
        <form onSubmit={onSearch} className="relative hidden sm:block">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            type="search"
            placeholder="Rechercher une alerte…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="h-9 w-48 pl-8 lg:w-72"
            aria-label="Rechercher"
          />
        </form>

        {/* Recherche compacte sur mobile : un bouton qui mène à la page Alertes. */}
        <Button
          variant="ghost"
          size="icon"
          className="sm:hidden"
          aria-label="Rechercher"
          onClick={() => router.push("/alerts")}
        >
          <Search className="size-4.5" />
        </Button>

        {/* Notifications (données réelles) */}
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button variant="ghost" size="icon" className="relative" aria-label="Notifications">
                <Bell className="size-4.5" />
                {openCount > 0 ? (
                  <span className="absolute -top-0.5 -right-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-semibold text-white ring-2 ring-background">
                    {openCount > 99 ? "99+" : openCount}
                  </span>
                ) : null}
              </Button>
            }
          />
          <DropdownMenuContent align="end" className="w-80">
            <DropdownMenuLabel className="flex items-center justify-between">
              <span>Notifications</span>
              <span className="text-xs font-normal text-muted-foreground">
                {openCount} ouverte{openCount > 1 ? "s" : ""}
              </span>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            {openAlerts.length === 0 ? (
              <div className="flex flex-col items-center gap-1.5 px-3 py-6 text-center">
                <Inbox className="size-6 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">
                  Aucune alerte ouverte.
                </p>
              </div>
            ) : (
              openAlerts.map((a) => (
                <DropdownMenuItem
                  key={a.id}
                  className="flex-col items-start gap-1 py-2"
                  onClick={() => router.push(`/alerts?project=${a.project_id}`)}
                >
                  <div className="flex w-full items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium">{a.title}</span>
                    <SeverityBadge severity={a.severity as Severity} />
                  </div>
                  <span className="truncate text-xs text-muted-foreground">
                    {a.project_name} · {a.resource ?? a.file ?? "—"}
                  </span>
                </DropdownMenuItem>
              ))
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="justify-center text-sm font-medium"
              onClick={() => router.push("/alerts")}
            >
              Voir toutes les alertes
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Avatar menu */}
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button variant="ghost" className="size-9 rounded-full p-0" aria-label="Compte">
                <Avatar className="size-9">
                  <AvatarFallback>{initials}</AvatarFallback>
                </Avatar>
              </Button>
            }
          />
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel className="flex flex-col gap-0.5">
              <span className="text-sm font-medium">{displayName}</span>
              <span className="truncate text-xs font-normal text-muted-foreground">
                {email || "—"}
              </span>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem render={<Link href="/settings" />}>
              <Settings />
              Settings
            </DropdownMenuItem>
            <DropdownMenuItem
              render={
                <a href="mailto:support@iac-guard.io?subject=Support%20iac-guard" />
              }
            >
              <CircleHelp />
              Support
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem variant="destructive" onClick={() => void logout()}>
              <LogOut />
              Se déconnecter
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
