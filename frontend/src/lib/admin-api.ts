/**
 * Client des API d'administration des comptes (réservées au rôle `admin`).
 *
 * Miroir de `app/schemas/admin.py`. Réutilise `request` de auth-api : même
 * cookie de session httpOnly, mêmes erreurs normalisées en ApiError (403 si
 * l'utilisateur n'est pas admin).
 */

import { request } from "@/lib/auth-api";

export const ROLES = [
  "admin",
  "security_lead",
  "developer",
  "auditor",
  "viewer",
] as const;

export type Role = (typeof ROLES)[number];

/** Libellés FR des rôles, réutilisés dans les selects et les tableaux. */
export const ROLE_LABELS: Record<string, string> = {
  admin: "Administrateur",
  security_lead: "Responsable sécurité",
  developer: "Développeur",
  auditor: "Auditeur",
  viewer: "Lecteur",
};

/** Ces deux rôles voient tous les projets de l'organisation sans octroi. */
export const GLOBAL_ACCESS_ROLES = ["admin", "security_lead"];

export type UserStatus = "active" | "disabled" | "pending_invitation";

export const STATUS_LABELS: Record<string, string> = {
  active: "Actif",
  disabled: "Désactivé",
  pending_invitation: "En attente",
};

export const ACTION_LABELS: Record<string, string> = {
  "user.invited": "Invitation envoyée",
  "user.role_changed": "Rôle modifié",
  "user.enabled": "Compte réactivé",
  "user.disabled": "Compte désactivé",
  "user.webauthn_reset": "Biométrie réinitialisée",
  "user.project_access_updated": "Accès aux projets modifié",
  "policy.exception_added": "Exception ajoutée",
  "policy.exception_removed": "Exception retirée",
};

export interface AdminUser {
  id: number;
  email: string;
  name: string | null;
  role: string;
  status: UserStatus | string;
  created_at: string;
  last_login_at: string | null;
  /** Si vrai, le front doit désactiver « changer de rôle » et « désactiver ». */
  is_last_active_admin: boolean;
}

export interface AdminUsersPage {
  items: AdminUser[];
  total: number;
  page: number;
  page_size: number;
}

export interface Invitation {
  email: string;
  role: string;
  expires_at: string;
}

export interface ProjectAccessItem {
  id: number;
  name: string;
}

export interface AdminAuditLogEntry {
  id: number;
  actor_id: number;
  actor_email: string;
  action: string;
  target_user_id: number | null;
  target_user_email: string | null;
  details: Record<string, unknown>;
  created_at: string;
}

export interface AdminAuditLogPage {
  items: AdminAuditLogEntry[];
  total: number;
  page: number;
  page_size: number;
}

export interface AuditLogFilters {
  actor_id?: number;
  target_user_id?: number;
  action?: string;
  since?: string;
  until?: string;
  page?: number;
  page_size?: number;
}

export const adminApi = {
  listUsers: (page = 1, pageSize = 20) =>
    request<AdminUsersPage>(`/api/admin/users?page=${page}&page_size=${pageSize}`),

  /** Le jeton part par e-mail : la réponse ne le contient jamais. */
  invite: (email: string, role: string) =>
    request<Invitation>("/api/admin/users/invite", {
      method: "POST",
      body: JSON.stringify({ email, role }),
    }),

  acceptInvitation: (token: string, password: string) =>
    request<{ id: number; email: string; role: string }>(
      `/api/admin/invitations/${encodeURIComponent(token)}/accept`,
      { method: "POST", body: JSON.stringify({ password }) }
    ),

  changeRole: (userId: number, role: string) =>
    request<AdminUser>(`/api/admin/users/${userId}/role`, {
      method: "PATCH",
      body: JSON.stringify({ role }),
    }),

  changeStatus: (userId: number, isActive: boolean) =>
    request<AdminUser>(`/api/admin/users/${userId}/status`, {
      method: "PATCH",
      body: JSON.stringify({ is_active: isActive }),
    }),

  /** Révoque les passkeys : ré-enrôlement obligatoire à la prochaine 2FA. */
  resetWebauthn: (userId: number) =>
    request<void>(`/api/admin/users/${userId}/reset-webauthn`, { method: "POST" }),

  getProjectAccess: (userId: number) =>
    request<ProjectAccessItem[]>(`/api/admin/users/${userId}/project-access`),

  /** Remplace INTÉGRALEMENT la liste des projets accessibles. */
  setProjectAccess: (userId: number, projectIds: number[]) =>
    request<ProjectAccessItem[]>(`/api/admin/users/${userId}/project-access`, {
      method: "PUT",
      body: JSON.stringify({ project_ids: projectIds }),
    }),

  listAuditLogs: (filters?: AuditLogFilters) => {
    const params = new URLSearchParams();
    if (filters?.actor_id) params.set("actor_id", String(filters.actor_id));
    if (filters?.target_user_id)
      params.set("target_user_id", String(filters.target_user_id));
    if (filters?.action) params.set("action", filters.action);
    if (filters?.since) params.set("since", filters.since);
    if (filters?.until) params.set("until", filters.until);
    if (filters?.page) params.set("page", String(filters.page));
    if (filters?.page_size) params.set("page_size", String(filters.page_size));
    const qs = params.toString();
    return request<AdminAuditLogPage>(`/api/admin/audit-logs${qs ? `?${qs}` : ""}`);
  },
};
