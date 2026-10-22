/**
 * Client des API "plateforme" : projets, scans, findings.
 *
 * Réutilise `request` de auth-api (mêmes règles : cookie de session httpOnly,
 * `credentials: "include"`, erreurs normalisées en ApiError).
 * Les types miroitent les schémas Pydantic de lecture du backend
 * (`app/schemas/project.py` et `app/schemas/read.py`).
 */

import { request } from "@/lib/auth-api";
import type { Severity, FindingSource, FindingCategory } from "@/lib/data";

// --- Types (miroir des schémas backend) ----------------------------------- #

export interface ProjectOut {
  id: number;
  name: string;
  token_prefix: string;
  created_at: string;
}

/** Renvoyé UNE seule fois à la création : contient le token en clair. */
export interface ProjectCreated extends ProjectOut {
  token: string;
}

export interface ScoreOut {
  score: number;
  grade: string;
  total_findings: number;
  by_severity: Record<string, number>;
}

export interface ProjectDetail {
  id: number;
  name: string;
  created_at: string;
  scan_count: number;
  latest_score: ScoreOut | null;
  last_scan_at: string | null;
}

/** Renvoyé UNE seule fois après rotation : contient le nouveau token en clair. */
export interface ProjectTokenRotated {
  token_prefix: string;
  token: string;
}

export interface ScanListItem {
  id: number;
  repo: string;
  branch: string | null;
  commit_sha: string | null;
  scanned_at: string;
  total_findings: number;
}

export interface ScanDetail extends ScanListItem {
  score: ScoreOut;
}

export interface FindingOut {
  id: number;
  fingerprint: string;
  source: FindingSource | string;
  category: FindingCategory | string;
  rule_id: string;
  title: string;
  severity: Severity | string;
  resource: string | null;
  file: string | null;
  line_start: number | null;
  line_end: number | null;
  remediation: string | null;
  /** Statut de triage : open, acknowledged, resolved, false_positive. */
  status: string;
  triage_note: string | null;
  /** Couvert par une exception de politique (règle ignorée du projet). */
  excepted: boolean;
}

/** Une alerte enrichie du projet auquel elle appartient (vue cross-projets). */
export interface FindingWithProject extends FindingOut {
  project_id: number;
  project_name: string;
  repo: string;
  scan_id: number;
  detected_at: string;
  commit_sha: string | null;
}

export interface FindingsPage {
  items: FindingWithProject[];
  total: number;
  page: number;
  page_size: number;
}

export interface AlertsFilters {
  project_id?: number;
  severity?: string;
  category?: string;
  status?: string;
  q?: string;
  page?: number;
  page_size?: number;
}

export interface IgnoredRuleOut {
  id: number;
  rule_id: string;
  note: string | null;
  created_at: string;
}

export interface ScanPolicyOut {
  fail_on_severity: string | null;
  ignored_rules: IgnoredRuleOut[];
}

export interface AuditLogEntryOut {
  id: number;
  project_id: number;
  project_name: string;
  finding_fingerprint: string;
  finding_title: string;
  from_status: string;
  to_status: string;
  note: string | null;
  user_email: string | null;
  created_at: string;
}

export interface AuditLogPage {
  items: AuditLogEntryOut[];
  total: number;
  page: number;
  page_size: number;
}

// --- Appels ---------------------------------------------------------------- #

export const platformApi = {
  listProjects: () => request<ProjectOut[]>("/api/projects"),

  createProject: (name: string) =>
    request<ProjectCreated>("/api/projects", {
      method: "POST",
      body: JSON.stringify({ name }),
    }),

  getProject: (id: number) => request<ProjectDetail>(`/api/projects/${id}`),

  deleteProject: (id: number) =>
    request<void>(`/api/projects/${id}`, { method: "DELETE" }),

  /** Invalide l'ancien token et en émet un nouveau (affiché une seule fois). */
  rotateToken: (id: number) =>
    request<ProjectTokenRotated>(`/api/projects/${id}/rotate-token`, {
      method: "POST",
    }),

  /** Alertes de tous les projets (vue « dernier état », paginée, filtrable). */
  listAlerts: (filters?: AlertsFilters) => {
    const params = new URLSearchParams();
    if (filters?.project_id) params.set("project_id", String(filters.project_id));
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.category) params.set("category", filters.category);
    if (filters?.status) params.set("status", filters.status);
    if (filters?.q) params.set("q", filters.q);
    if (filters?.page) params.set("page", String(filters.page));
    if (filters?.page_size) params.set("page_size", String(filters.page_size));
    const qs = params.toString();
    return request<FindingsPage>(`/api/alerts${qs ? `?${qs}` : ""}`);
  },

  listScans: (projectId: number) =>
    request<ScanListItem[]>(`/api/projects/${projectId}/scans`),

  getScan: (scanId: number) => request<ScanDetail>(`/api/scans/${scanId}`),

  listFindings: (scanId: number, filters?: { severity?: string; category?: string }) => {
    const params = new URLSearchParams();
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.category) params.set("category", filters.category);
    const qs = params.toString();
    return request<FindingOut[]>(`/api/scans/${scanId}/findings${qs ? `?${qs}` : ""}`);
  },

  /** Décision de triage sur un finding (suivie par fingerprint côté backend). */
  triageFinding: (scanId: number, findingId: number, status: string, note?: string) =>
    request<FindingOut>(`/api/scans/${scanId}/findings/${findingId}/triage`, {
      method: "PATCH",
      body: JSON.stringify({ status, note: note ?? null }),
    }),

  // --- Politique de scan (seuil de blocage + règles ignorées) --- #

  getPolicy: (projectId: number) =>
    request<ScanPolicyOut>(`/api/projects/${projectId}/policy`),

  updatePolicy: (projectId: number, failOnSeverity: string | null) =>
    request<ScanPolicyOut>(`/api/projects/${projectId}/policy`, {
      method: "PATCH",
      body: JSON.stringify({ fail_on_severity: failOnSeverity }),
    }),

  addIgnoredRule: (projectId: number, ruleId: string, note?: string) =>
    request<IgnoredRuleOut>(`/api/projects/${projectId}/ignored-rules`, {
      method: "POST",
      body: JSON.stringify({ rule_id: ruleId, note: note ?? null }),
    }),

  removeIgnoredRule: (projectId: number, ignoredRuleId: number) =>
    request<void>(`/api/projects/${projectId}/ignored-rules/${ignoredRuleId}`, {
      method: "DELETE",
    }),

  // --- Audit log --- #

  listAuditLog: (filters?: { project_id?: number; page?: number; page_size?: number }) => {
    const params = new URLSearchParams();
    if (filters?.project_id) params.set("project_id", String(filters.project_id));
    if (filters?.page) params.set("page", String(filters.page));
    if (filters?.page_size) params.set("page_size", String(filters.page_size));
    const qs = params.toString();
    return request<AuditLogPage>(`/api/audit-log${qs ? `?${qs}` : ""}`);
  },
};
