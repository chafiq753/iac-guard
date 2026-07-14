"use client";

import * as React from "react";
import { useRouter } from "next/navigation";

import { authApi, ApiError, type UserOut } from "@/lib/auth-api";

interface AuthContextValue {
  user: UserOut | null;
  loading: boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = React.createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = React.useState<UserOut | null>(null);
  const [loading, setLoading] = React.useState(true);
  const router = useRouter();

  const refresh = React.useCallback(async () => {
    try {
      setUser(await authApi.me());
    } catch (err) {
      // 401 = pas de session : cas normal, on reste déconnecté sans crier.
      if (!(err instanceof ApiError) || err.status !== 401) {
        console.error(err);
      }
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  const logout = React.useCallback(async () => {
    try {
      await authApi.logout();
    } finally {
      setUser(null);
      router.push("/login");
    }
  }, [router]);

  return (
    <AuthContext.Provider value={{ user, loading, refresh, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = React.useContext(AuthContext);
  if (ctx === null) {
    throw new Error("useAuth doit être utilisé dans <AuthProvider>.");
  }
  return ctx;
}
