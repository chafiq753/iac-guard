"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";

import { useAuth } from "@/components/auth-provider";

/**
 * Protège une page côté client : redirige vers /login si aucune session.
 *
 * Le contrôle est forcément côté client : le cookie de session est posé par
 * l'API (origine :8000) et n'est donc pas lisible par un middleware Next
 * tournant sur l'origine du front (:3000).
 */
export function AuthGuard({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();

  React.useEffect(() => {
    if (!loading && user === null) {
      router.replace("/login");
    }
  }, [loading, user, router]);

  if (loading || user === null) {
    return (
      <div className="flex min-h-svh items-center justify-center">
        <Loader2 className="size-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return <>{children}</>;
}
