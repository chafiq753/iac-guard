"use client";

import Link from "next/link";
import { Bell, Search, LogOut, Settings, CircleHelp } from "lucide-react";

import { useAuth } from "@/components/auth-provider";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
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
import { alerts } from "@/lib/data";
import { SeverityBadge } from "@/components/severity-badge";

export function SiteHeader() {
  const { user, logout } = useAuth();
  const recent = alerts.filter((a) => a.status === "open").slice(0, 4);

  const email = user?.email ?? "";
  const initials = email
    ? email.split("@")[0].slice(0, 2).toUpperCase()
    : "··";

  return (
    <header className="sticky top-0 z-30 flex h-16 shrink-0 items-center gap-2 border-b bg-background/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/80">
      <SidebarTrigger className="-ml-1" />
      <Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-5" />

      <div className="hidden md:block">
        <h1 className="text-sm font-semibold">Dashboard</h1>
        <p className="text-xs text-muted-foreground">Security posture overview</p>
      </div>

      <div className="ml-auto flex items-center gap-2">
        <div className="relative hidden sm:block">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            type="search"
            placeholder="Search alerts, resources…"
            className="h-9 w-56 pl-8 lg:w-72"
          />
        </div>

        {/* Notifications */}
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button variant="ghost" size="icon" className="relative" aria-label="Notifications">
                <Bell className="size-4.5" />
                <span className="absolute top-1.5 right-1.5 flex size-2 rounded-full bg-destructive ring-2 ring-background" />
              </Button>
            }
          />
          <DropdownMenuContent align="end" className="w-80">
            <DropdownMenuLabel className="flex items-center justify-between">
              <span>Notifications</span>
              <span className="text-xs font-normal text-muted-foreground">
                {recent.length} new
              </span>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            {recent.map((a) => (
              <DropdownMenuItem key={a.id} className="flex-col items-start gap-1 py-2">
                <div className="flex w-full items-center justify-between gap-2">
                  <span className="truncate text-sm font-medium">{a.title}</span>
                  <SeverityBadge severity={a.severity} />
                </div>
                <span className="text-xs text-muted-foreground">
                  {a.repo} · {a.resource}
                </span>
              </DropdownMenuItem>
            ))}
            <DropdownMenuSeparator />
            <DropdownMenuItem className="justify-center text-sm font-medium">
              View all alerts
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
              <span className="text-sm font-medium">Mon compte</span>
              <span className="truncate text-xs font-normal text-muted-foreground">
                {email || "—"}
              </span>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem render={<Link href="/security" />}>
              <Settings />
              Sécurité &amp; 2FA
            </DropdownMenuItem>
            <DropdownMenuItem>
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
