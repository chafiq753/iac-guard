"""Protection append-only des journaux d'audit, AU NIVEAU DE LA BASE.

L'application n'expose déjà aucune route de modification/suppression ; ces
triggers ajoutent une seconde barrière : même un accès SQL direct (script,
console, bug) ne peut ni modifier ni supprimer une ligne d'audit.

Installés automatiquement par `create_all` (événement `after_create`) sur une
base neuve, et par `scripts/migrate_audit.py` sur une base existante — d'où
les instructions idempotentes (OR REPLACE / IF EXISTS / IF NOT EXISTS).
"""

from __future__ import annotations

from sqlalchemy import DDL, Table, event

AUDIT_TABLES = ("triage_audit_log", "admin_audit_logs")

_PG_FUNCTION = """
CREATE OR REPLACE FUNCTION iacguard_audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING MESSAGE =
        'Journal d''audit append-only, ' || TG_OP || ' interdit sur ' || TG_TABLE_NAME;
END
$$
"""


def postgres_statements(table: str) -> list[str]:
    """Fonction + triggers (lignes ET TRUNCATE) pour une table d'audit."""
    return [
        _PG_FUNCTION,
        f"DROP TRIGGER IF EXISTS {table}_append_only ON {table}",
        f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
        "FOR EACH ROW EXECUTE FUNCTION iacguard_audit_append_only()",
        f"DROP TRIGGER IF EXISTS {table}_no_truncate ON {table}",
        f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table} "
        "FOR EACH STATEMENT EXECUTE FUNCTION iacguard_audit_append_only()",
    ]


def sqlite_statements(table: str) -> list[str]:
    return [
        f"CREATE TRIGGER IF NOT EXISTS {table}_no_{op.lower()} BEFORE {op} ON {table} "
        "BEGIN SELECT RAISE(ABORT, 'Journal d''audit append-only'); END"
        for op in ("UPDATE", "DELETE")
    ]


def install_append_only_guard(table: Table) -> None:
    """Accroche les triggers à la création de la table (PostgreSQL et SQLite)."""
    for sql in postgres_statements(table.name):
        event.listen(table, "after_create", DDL(sql).execute_if(dialect="postgresql"))
    for sql in sqlite_statements(table.name):
        event.listen(table, "after_create", DDL(sql).execute_if(dialect="sqlite"))
