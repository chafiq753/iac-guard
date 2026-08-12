import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import { SiteHeader } from "@/components/site-header";
import { AuthGuard } from "@/components/auth-guard";
import { AccountSettings } from "@/components/account-settings";
import { ScanPolicyManager } from "@/components/scan-policy-manager";
import { AuditLogViewer } from "@/components/audit-log-viewer";
import { SecurityManager } from "@/components/security-manager";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export default function SettingsPage() {
  return (
    <AuthGuard>
      <SidebarProvider>
        <AppSidebar />
        <SidebarInset>
          <SiteHeader />
          <main className="flex flex-1 flex-col p-4 md:p-8">
            <div className="mx-auto w-full max-w-3xl space-y-8">
              <div className="space-y-1.5">
                <h2 className="text-2xl font-semibold tracking-tight">Settings</h2>
                <p className="text-sm text-muted-foreground">
                  Compte, sécurité, politiques de scan et audit.
                </p>
              </div>

              <Tabs defaultValue="account" className="gap-6">
                <TabsList>
                  <TabsTrigger value="account">Compte</TabsTrigger>
                  <TabsTrigger value="security">Sécurité</TabsTrigger>
                  <TabsTrigger value="policy">Politiques de scan</TabsTrigger>
                  <TabsTrigger value="audit">Audit</TabsTrigger>
                </TabsList>

                <TabsContent value="account">
                  <AccountSettings />
                </TabsContent>
                <TabsContent value="security">
                  <SecurityManager />
                </TabsContent>
                <TabsContent value="policy">
                  <ScanPolicyManager />
                </TabsContent>
                <TabsContent value="audit">
                  <AuditLogViewer />
                </TabsContent>
              </Tabs>
            </div>
          </main>
        </SidebarInset>
      </SidebarProvider>
    </AuthGuard>
  );
}
