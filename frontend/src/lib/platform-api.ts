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
};
