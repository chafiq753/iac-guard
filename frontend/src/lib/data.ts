/**
 * Mock data layer for the iac-guard dashboard.
 *
 * Shapes mirror the backend read schema (`FindingOut`, `ScoreOut`) and the
 * pipeline `Finding` model: findings come from Gitleaks (secrets), Checkov
 * (misconfiguration), Conftest/OPA (policy) and Semgrep (vulnerability, SAST
 * on application code), each with a normalized severity. In a real
 * deployment these would be fetched from `/api/*`.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingSource = "gitleaks" | "checkov" | "conftest" | "semgrep";
export type FindingCategory = "secret" | "misconfiguration" | "policy" | "vulnerability";
export type AlertStatus = "open" | "acknowledged" | "resolved" | "false_positive";

export interface Alert {
  id: string;
  title: string;
  source: FindingSource;
  category: FindingCategory;
  severity: Severity;
  ruleId: string;
  resource: string;
  repo: string;
  status: AlertStatus;
  detectedAt: string; // ISO
  /** Ids réels côté API (absents des données mock). */
  findingId?: number;
  scanId?: number;
  projectId?: number;
  projectName?: string;
  remediation?: string | null;
  /**
   * Emplacement exact dans le code. Séparé de `resource` : un secret Gitleaks
   * n'a pas de ressource Terraform, seulement un fichier et une ligne — les
   * confondre faisait disparaître la ligne, la seule info utile pour corriger.
   */
  file?: string | null;
  lineStart?: number | null;
  lineEnd?: number | null;
  /** Commit de détection, pour lier vers la ligne telle qu'elle était alors. */
  commitSha?: string | null;
  /** Couvert par une exception de politique (règle ignorée). */
  excepted?: boolean;
}

export interface Kpi {
  key: string;
  label: string;
  value: string;
  delta: number; // percent change vs previous period
  hint: string;
}

export interface ActivityPoint {
  date: string; // ISO day
  critical: number;
  high: number;
  medium: number;
}

/** Compliance score, mirrors backend `ScoreOut`. */
export const complianceScore = {
  score: 82,
  grade: "B",
  total_findings: 47,
  by_severity: { critical: 3, high: 9, medium: 21, low: 11, info: 3 },
} as const;

export const kpis: Kpi[] = [
  {
    key: "score",
    label: "Compliance Score",
    value: "82 / 100",
    delta: 4.1,
    hint: "Grade B · +3 pts this week",
  },
  {
    key: "open",
    label: "Open Alerts",
    value: "47",
    delta: -12.5,
    hint: "8 resolved in last 24h",
  },
  {
    key: "critical",
    label: "Critical & High",
    value: "12",
    delta: -8.0,
    hint: "3 critical secrets exposed",
  },
  {
    key: "scans",
    label: "Scans (7d)",
    value: "134",
    delta: 22.3,
    hint: "Gitleaks · Checkov · Conftest · Semgrep",
  },
];

export const activitySeries: ActivityPoint[] = [
  { date: "2026-07-03", critical: 2, high: 6, medium: 14 },
  { date: "2026-07-04", critical: 1, high: 8, medium: 11 },
  { date: "2026-07-05", critical: 3, high: 5, medium: 18 },
  { date: "2026-07-06", critical: 2, high: 9, medium: 16 },
  { date: "2026-07-07", critical: 4, high: 7, medium: 22 },
  { date: "2026-07-08", critical: 1, high: 11, medium: 19 },
  { date: "2026-07-09", critical: 3, high: 9, medium: 21 },
];

export const alerts: Alert[] = [
  {
    id: "ALG-1043",
    title: "Command injection via subprocess with shell=True",
    source: "semgrep",
    category: "vulnerability",
    severity: "high",
    ruleId: "python.lang.security.audit.dangerous-subprocess-use",
    resource: "app/services/export.py",
    repo: "acme/checkout-web",
    status: "open",
    detectedAt: "2026-07-09T09:02:00Z",
    file: "app/services/export.py",
    lineStart: 42,
    lineEnd: 42,
  },
  {
    id: "ALG-1042",
    title: "AWS access key committed to repository",
    source: "gitleaks",
    category: "secret",
    severity: "critical",
    ruleId: "aws-access-token",
    resource: "terraform/main.tf",
    repo: "acme/payments-infra",
    status: "open",
    detectedAt: "2026-07-09T08:14:00Z",
  },
  {
    id: "ALG-1041",
    title: "S3 bucket allows public read access",
    source: "checkov",
    category: "misconfiguration",
    severity: "high",
    ruleId: "CKV_AWS_20",
    resource: "aws_s3_bucket.assets",
    repo: "acme/payments-infra",
    status: "open",
    detectedAt: "2026-07-09T07:58:00Z",
  },
  {
    id: "ALG-1040",
    title: "Data residency policy: region must be eu-*",
    source: "conftest",
    category: "policy",
    severity: "high",
    ruleId: "cndp.data_residency",
    resource: "aws_rds_cluster.core",
    repo: "acme/core-platform",
    status: "acknowledged",
    detectedAt: "2026-07-09T06:32:00Z",
  },
  {
    id: "ALG-1039",
    title: "Security group opens port 22 to 0.0.0.0/0",
    source: "checkov",
    category: "misconfiguration",
    severity: "high",
    ruleId: "CKV_AWS_24",
    resource: "aws_security_group.bastion",
    repo: "acme/core-platform",
    status: "open",
    detectedAt: "2026-07-08T22:11:00Z",
  },
  {
    id: "ALG-1038",
    title: "RDS instance not encrypted at rest",
    source: "checkov",
    category: "misconfiguration",
    severity: "medium",
    ruleId: "CKV_AWS_16",
    resource: "aws_db_instance.analytics",
    repo: "acme/data-lake",
    status: "open",
    detectedAt: "2026-07-08T18:45:00Z",
  },
  {
    id: "ALG-1037",
    title: "Stripe secret key detected in env file",
    source: "gitleaks",
    category: "secret",
    severity: "critical",
    ruleId: "stripe-access-token",
    resource: ".env.production",
    repo: "acme/checkout-web",
    status: "acknowledged",
    detectedAt: "2026-07-08T15:20:00Z",
  },
  {
    id: "ALG-1036",
    title: "IAM policy grants wildcard (*) actions",
    source: "checkov",
    category: "misconfiguration",
    severity: "high",
    ruleId: "CKV_AWS_63",
    resource: "aws_iam_policy.ci_deploy",
    repo: "acme/core-platform",
    status: "resolved",
    detectedAt: "2026-07-08T11:03:00Z",
  },
  {
    id: "ALG-1035",
    title: "Bank Al-Maghrib: audit logging must be enabled",
    source: "conftest",
    category: "policy",
    severity: "medium",
    ruleId: "bam.audit_logging",
    resource: "aws_cloudtrail.main",
    repo: "acme/payments-infra",
    status: "open",
    detectedAt: "2026-07-08T09:47:00Z",
  },
  {
    id: "ALG-1034",
    title: "EBS volume not encrypted",
    source: "checkov",
    category: "misconfiguration",
    severity: "low",
    ruleId: "CKV_AWS_3",
    resource: "aws_ebs_volume.cache",
    repo: "acme/data-lake",
    status: "resolved",
    detectedAt: "2026-07-07T20:15:00Z",
  },
  {
    id: "ALG-1033",
    title: "Generic API key found in CI config",
    source: "gitleaks",
    category: "secret",
    severity: "high",
    ruleId: "generic-api-key",
    resource: ".github/workflows/deploy.yml",
    repo: "acme/checkout-web",
    status: "open",
    detectedAt: "2026-07-07T16:40:00Z",
  },
];

/** Compliance frameworks coverage, used by the Compliance page/section. */
export const complianceFrameworks = [
  { name: "CNDP (Loi 09-08)", passed: 38, total: 45 },
  { name: "Bank Al-Maghrib", passed: 27, total: 34 },
  { name: "CIS AWS Benchmark", passed: 112, total: 140 },
  { name: "ISO 27001", passed: 61, total: 78 },
];
