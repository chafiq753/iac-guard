/**
 * Client d'authentification : parle à l'API FastAPI.
 *
 * `credentials: "include"` est ESSENTIEL : sans ça le navigateur n'enverrait
 * pas le cookie de session httpOnly (qui vit sur l'origine de l'API). C'est ce
 * cookie — jamais un token en localStorage — qui porte la session, pour qu'une
 * faille XSS ne puisse pas la voler.
 */

const API_URL =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ?? "http://localhost:8000";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let resp: Response;
  try {
    resp = await fetch(`${API_URL}${path}`, {
      ...init,
      credentials: "include",
      headers: { "Content-Type": "application/json", ...init?.headers },
    });
  } catch {
    throw new ApiError(0, "Impossible de joindre le serveur. Est-il démarré ?");
  }

  if (resp.status === 204) return undefined as T;

  const data = await resp.json().catch(() => null);
  if (!resp.ok) {
    const detail =
      (data && (data.detail ?? data.message)) || `Erreur ${resp.status}`;
    // `detail` peut être une liste (erreurs de validation Pydantic).
    const message = Array.isArray(detail)
      ? detail.map((d: { msg?: string }) => d.msg ?? String(d)).join(", ")
      : String(detail);
    throw new ApiError(resp.status, message);
  }
  return data as T;
}

// --- Types ---------------------------------------------------------------- #

export interface UserOut {
  id: number;
  email: string;
  name: string | null;
  created_at: string;
  mfa_methods: string[];
}

export interface LoginResult {
  mfa_required: boolean;
  methods: string[];
  user: UserOut | null;
}

export interface MfaStatus {
  totp_enabled: boolean;
  webauthn_enabled: boolean;
  devices: {
    id: number;
    name: string;
    created_at: string;
    last_used_at: string | null;
  }[];
  recovery_codes_remaining: number;
}

export interface TotpSetup {
  secret: string;
  otpauth_uri: string;
}

export interface MfaEnabled {
  method: "totp" | "webauthn";
  recovery_codes: string[];
}

// --- Auth ----------------------------------------------------------------- #

export const authApi = {
  register: (email: string, password: string) =>
    request<UserOut>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  login: (email: string, password: string) =>
    request<LoginResult>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  /** Étape 1 du login : méthodes proposables pour cet e-mail.
      Contient toujours "password" ; "webauthn" en tête si passkey enrôlée. */
  loginMethods: (email: string) =>
    request<{ methods: string[] }>("/api/auth/methods", {
      method: "POST",
      body: JSON.stringify({ email }),
    }),

  /** Connexion par passkey en PREMIER facteur (sans mot de passe). */
  webauthnLoginOptions: (email: string) =>
    request<Record<string, unknown>>("/api/auth/webauthn/login/options", {
      method: "POST",
      body: JSON.stringify({ email }),
    }),

  webauthnLoginVerify: (email: string, credential: unknown) =>
    request<UserOut>("/api/auth/webauthn/login/verify", {
      method: "POST",
      body: JSON.stringify({ email, credential }),
    }),

  forgotPassword: (email: string) =>
    request<{ message: string }>("/api/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email }),
    }),

  logout: () => request<void>("/api/auth/logout", { method: "POST" }),

  me: () => request<UserOut>("/api/auth/me"),

  /** Change le nom et/ou l'e-mail affichés. */
  updateProfile: (payload: { name?: string; email?: string }) =>
    request<UserOut>("/api/auth/me", {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),

  /** Exige le mot de passe actuel — évite qu'une session volée suffise à en changer un. */
  changePassword: (currentPassword: string, newPassword: string) =>
    request<void>("/api/auth/me/password", {
      method: "POST",
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    }),

  // --- 2FA : vérification au login --- #
  verifyTotp: (code: string) =>
    request<UserOut>("/api/auth/2fa/totp/verify", {
      method: "POST",
      body: JSON.stringify({ code }),
    }),

  verifyRecovery: (code: string) =>
    request<UserOut>("/api/auth/2fa/recovery/verify", {
      method: "POST",
      body: JSON.stringify({ code }),
    }),

  webauthnAuthOptions: () =>
    request<Record<string, unknown>>(
      "/api/auth/2fa/webauthn/authenticate/options",
      { method: "POST" }
    ),

  webauthnAuthVerify: (credential: unknown) =>
    request<UserOut>("/api/auth/2fa/webauthn/authenticate/verify", {
      method: "POST",
      body: JSON.stringify({ credential }),
    }),

  // --- 2FA : gestion (session active) --- #
  mfaStatus: () => request<MfaStatus>("/api/auth/2fa/status"),

  totpSetup: () =>
    request<TotpSetup>("/api/auth/2fa/totp/setup", { method: "POST" }),

  totpConfirm: (code: string) =>
    request<MfaEnabled>("/api/auth/2fa/totp/confirm", {
      method: "POST",
      body: JSON.stringify({ code }),
    }),

  totpDisable: () => request<void>("/api/auth/2fa/totp", { method: "DELETE" }),

  webauthnRegisterOptions: () =>
    request<Record<string, unknown>>(
      "/api/auth/2fa/webauthn/register/options",
      { method: "POST" }
    ),

  webauthnRegisterVerify: (credential: unknown, deviceName: string) =>
    request<MfaEnabled>("/api/auth/2fa/webauthn/register/verify", {
      method: "POST",
      body: JSON.stringify({ credential, device_name: deviceName }),
    }),

  webauthnDeleteDevice: (id: number) =>
    request<void>(`/api/auth/2fa/webauthn/${id}`, { method: "DELETE" }),

  regenerateRecoveryCodes: () =>
    request<{ codes: string[] }>("/api/auth/2fa/recovery/regenerate", {
      method: "POST",
    }),
};
