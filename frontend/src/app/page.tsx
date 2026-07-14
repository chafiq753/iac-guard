import * as React from "react";

import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import { SiteHeader } from "@/components/site-header";
import { DashboardLive } from "@/components/dashboard-live";
import { AuthGuard } from "@/components/auth-guard";

export default function DashboardPage() {
  return (
    <AuthGuard>
      <SidebarProvider>
        <AppSidebar />
        <SidebarInset>
          <SiteHeader />
          <main className="flex flex-1 flex-col gap-4 p-4 md:gap-6 md:p-6">
            <div>
              <h2 className="text-xl font-semibold tracking-tight">
                Security Overview
              </h2>
              <p className="text-sm text-muted-foreground">
                Real-time posture across secrets, misconfigurations and policy checks.
              </p>
            </div>

            {/* useSearchParams (?project=) impose une frontière Suspense. */}
            <React.Suspense>
              <DashboardLive />
            </React.Suspense>
          </main>
        </SidebarInset>
      </SidebarProvider>
    </AuthGuard>
  );
}
