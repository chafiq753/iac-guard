/**
 * Droits d'écriture par rôle — miroir des contrôles de l'API (`require_role`).
 * Sert uniquement à masquer les actions interdites : l'API reste l'autorité.
 */
const TRIAGE_ROLES = ["admin", "security_lead", "developer"];
const POLICY_ROLES = ["admin", "security_lead"];

export const canTriage = (role?: string | null): boolean =>
  !!role && TRIAGE_ROLES.includes(role);

/** Seuil de blocage + exceptions (règles ignorées). */
export const canManagePolicy = (role?: string | null): boolean =>
  !!role && POLICY_ROLES.includes(role);
