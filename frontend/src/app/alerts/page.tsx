import * as React from "react";

import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import { SiteHeader } from "@/components/site-header";
import { AuthGuard } from "@/components/auth-guard";
import { AlertsManager } from "@/components/alerts-manager";

export default function AlertsPage() {
  return (
    <AuthGuard>
      <SidebarProvider>
        <AppSidebar />
        <SidebarInset>
          <SiteHeader />
          <main className="flex flex-1 flex-col gap-4 p-4 md:gap-6 md:p-6">
            <div>
              <h2 className="text-xl font-semibold tracking-tight">Alertes</h2>
              <p className="text-sm text-muted-foreground">
                Toutes les alertes détectées, tous projets confondus.
              </p>
            </div>

            {/* useSearchParams (?project=) impose une frontière Suspense. */}
            <React.Suspense>
              <AlertsManager />
            </React.Suspense>
          </main>
        </SidebarInset>
      </SidebarProvider>
    </AuthGuard>
  );
}
