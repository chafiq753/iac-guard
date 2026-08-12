"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  FolderGit2,
  ShieldAlert,
  ShieldCheck,
  ClipboardCheck,
  Settings,
  LifeBuoy,
  LogOut,
} from "lucide-react";

import { useAuth } from "@/components/auth-provider";
import { ZenithMark } from "@/components/zenith-logo";

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";

const navMain = [
  { title: "Dashboard", icon: LayoutDashboard, key: "dashboard", href: "/" },
  { title: "Projets", icon: FolderGit2, key: "projects", href: "/projects" },
  { title: "Alertes", icon: ShieldAlert, key: "alerts", href: "/alerts" },
  { title: "Compliance", icon: ClipboardCheck, key: "compliance", href: "/" },
  { title: "Settings", icon: Settings, key: "settings", href: "/settings" },
] as const;

export function AppSidebar(props: React.ComponentProps<typeof Sidebar>) {
  const pathname = usePathname();
  const { logout } = useAuth();

  // L'entrée active est celle dont la route correspond exactement ; les items
  // pointant encore vers "/" (pages à venir) ne s'activent que sur l'accueil.
  const active =
    navMain.find((item) => item.href === pathname)?.key ?? "dashboard";

  return (
    <Sidebar {...props}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" className="gap-3">
              <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                <ShieldCheck className="size-4.5" />
              </div>
              <div className="grid flex-1 text-left leading-tight">
                <span className="truncate font-semibold">iac-guard</span>
                <span className="truncate text-xs text-muted-foreground">
                  Security Platform
                </span>
              </div>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Platform</SidebarGroupLabel>
          <SidebarMenu>
            {navMain.map((item) => (
              <SidebarMenuItem key={item.key}>
                <SidebarMenuButton
                  isActive={active === item.key}
                  tooltip={item.title}
                  render={<Link href={item.href} />}
                >
                  <item.icon />
                  <span>{item.title}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            ))}
          </SidebarMenu>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton tooltip="Help & Support">
              <LifeBuoy />
              <span>Help &amp; Support</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
          <SidebarMenuItem>
            <SidebarMenuButton
              tooltip="Se déconnecter"
              onClick={() => void logout()}
              className="text-destructive hover:text-destructive"
            >
              <LogOut />
              <span>Se déconnecter</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  );
}
