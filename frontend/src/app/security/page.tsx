import Link from "next/link";
import { ArrowLeft } from "lucide-react";

import { AuthGuard } from "@/components/auth-guard";
import { SecurityManager } from "@/components/security-manager";
import { Button } from "@/components/ui/button";

export default function SecurityPage() {
  return (
    <AuthGuard>
      <main className="mx-auto w-full max-w-2xl px-4 py-8 md:py-12">
        <Button
          variant="ghost"
          size="sm"
          className="mb-4 -ml-2"
          nativeButton={false}
          render={<Link href="/" />}
        >
          <ArrowLeft className="size-4" />
          Retour au tableau de bord
        </Button>

        <div className="mb-6 space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">Sécurité</h1>
          <p className="text-sm text-muted-foreground">
            Renforcez votre compte avec une double authentification. Choisissez
            la ou les méthodes qui vous conviennent.
          </p>
        </div>

        <SecurityManager />
      </main>
    </AuthGuard>
  );
}
