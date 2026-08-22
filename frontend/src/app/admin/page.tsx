"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Loader2, ShieldX } from "lucide-react";

import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import { SiteHeader } from "@/components/site-header";
import { AuthGuard } from "@/components/auth-guard";
import { UsersManager } from "@/components/users-manager";
import { AdminAuditLog } from "@/components/admin-audit-log";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/components/auth-provider";

/**
 * Garde de rôle. Le vrai contrôle reste côté serveur (`require_role("admin")`
 * sur chaque route) : masquer l'écran n'est qu'un confort, un non-admin qui
 * forcerait l'URL recevrait de toute façon des 403 sur chaque appel.
 */
function AdminOnly({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();

  if (loading) {
    return (
      <div className="flex min-h-svh items-center justify-center">
        <Loader2 className="size-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (user?.role !== "admin") {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
        <ShieldX className="size-10 text-muted-foreground" />
        <h2 className="text-lg font-semibold">Accès réservé</h2>
        <p className="max-w-sm text-sm text-muted-foreground">
          La gestion des comptes est réservée aux administrateurs de votre
          organisation.
        </p>
        <Button variant="outline" onClick={() => router.push("/")}>
          Retour au dashboard
        </Button>
      </div>
    );
  }

  return <>{children}</>;
}

export default function AdminPage() {
  return (
    <AuthGuard>
      <SidebarProvider>
        <AppSidebar />
        <SidebarInset>
          <SiteHeader />
          <AdminOnly>
            <main className="flex flex-1 flex-col p-4 md:p-8">
              <div className="mx-auto w-full max-w-5xl space-y-8">
                <div className="space-y-1.5">
                  <h2 className="text-2xl font-semibold tracking-tight">
                    Administration
                  </h2>
                  <p className="text-sm text-muted-foreground">
                    Comptes, rôles, périmètres d&apos;accès et journal
                    d&apos;audit.
                  </p>
                </div>

                <Tabs defaultValue="users" className="gap-6">
                  <TabsList>
                    <TabsTrigger value="users">Comptes</TabsTrigger>
                    <TabsTrigger value="audit">Journal d&apos;audit</TabsTrigger>
                  </TabsList>

                  <TabsContent value="users">
                    <UsersManager />
                  </TabsContent>
                  <TabsContent value="audit">
                    <AdminAuditLog />
                  </TabsContent>
                </Tabs>
              </div>
            </main>
          </AdminOnly>
        </SidebarInset>
      </SidebarProvider>
    </AuthGuard>
  );
}
