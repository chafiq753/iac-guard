import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import { SiteHeader } from "@/components/site-header";
import { AuthGuard } from "@/components/auth-guard";
import { ProjectsManager } from "@/components/projects-manager";

export default function ProjectsPage() {
  return (
    <AuthGuard>
      <SidebarProvider>
        <AppSidebar />
        <SidebarInset>
          <SiteHeader />
          <main className="flex flex-1 flex-col gap-4 p-4 md:gap-6 md:p-6">
            <div>
              <h2 className="text-xl font-semibold tracking-tight">Projets</h2>
              <p className="text-sm text-muted-foreground">
                Vos dépôts surveillés et leurs tokens d&apos;ingestion.
              </p>
            </div>
            <ProjectsManager />
          </main>
        </SidebarInset>
      </SidebarProvider>
    </AuthGuard>
  );
}
