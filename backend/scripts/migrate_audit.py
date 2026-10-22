"""Migration audit : rend les journaux d'audit d'une base EXISTANTE conformes.

`create_all` n'altère jamais une table déjà présente. Une base créée avant
cette version garde donc :
  - la clé étrangère `triage_audit_log.project_id -> projects.id`, qui fait
    échouer la suppression d'un projet ayant un historique de triage ;
  - des journaux d'audit modifiables par un simple UPDATE/DELETE SQL.

Ce script :
  1. supprime cette clé étrangère (le journal est dénormalisé : il garde le
     nom du projet et doit lui survivre) ;
  2. installe les triggers append-only (voir app/db/audit_guard.py) sur
     `triage_audit_log` et `admin_audit_logs` ;
  3. vérifie le résultat.

Idempotent : relancer ne casse rien.

    python scripts/migrate_audit.py            # sur settings.database_url
    python scripts/migrate_audit.py --dry-run  # montre sans écrire

Avec la stack docker compose (base = service `db`) :

    docker compose exec api python scripts/migrate_audit.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Permet de lancer le script depuis n'importe où (`python scripts/...`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import text  # noqa: E402

from app.db.audit_guard import (  # noqa: E402
    AUDIT_TABLES,
    postgres_statements,
    sqlite_statements,
)
from app.db.session import engine  # noqa: E402

# Clés étrangères de triage_audit_log pointant vers `projects` (le nom réel
# dépend de la version de PostgreSQL qui a créé la table : on le lit).
_PROJECT_FKS = text(
    """
    SELECT conname FROM pg_constraint
    WHERE contype = 'f'
      AND conrelid = 'triage_audit_log'::regclass
      AND confrelid = 'projects'::regclass
    """
)
# pg_trigger et non information_schema.triggers, qui omet les triggers TRUNCATE.
_TRIGGERS = text(
    """
    SELECT tgname AS trigger_name FROM pg_trigger
    WHERE NOT tgisinternal
      AND tgrelid IN ('triage_audit_log'::regclass, 'admin_audit_logs'::regclass)
    """
)


def migrate_postgres(conn, dry_run: bool) -> None:
    for (name,) in conn.execute(_PROJECT_FKS).all():
        print(f"- suppression de la clé étrangère {name}")
        if not dry_run:
            conn.exec_driver_sql(f'ALTER TABLE triage_audit_log DROP CONSTRAINT "{name}"')

    for table in AUDIT_TABLES:
        print(f"- triggers append-only sur {table}")
        if not dry_run:
            for sql in postgres_statements(table):
                conn.exec_driver_sql(sql)

    if dry_run:
        return
    remaining = conn.execute(_PROJECT_FKS).all()
    triggers = sorted({row.trigger_name for row in conn.execute(_TRIGGERS)})
    print(f"Vérification : clé étrangère restante = {len(remaining)}, triggers = {triggers}")
    if remaining or len(triggers) != 2 * len(AUDIT_TABLES):
        raise SystemExit("Migration incomplète.")


def migrate_sqlite(conn, dry_run: bool) -> None:
    # SQLite ne sait pas supprimer une clé étrangère sans reconstruire la
    # table ; l'application ne l'active de toute façon pas (pas de PRAGMA
    # foreign_keys hors tests). On se limite aux triggers.
    for table in AUDIT_TABLES:
        print(f"- triggers append-only sur {table}")
        if not dry_run:
            for sql in sqlite_statements(table):
                conn.exec_driver_sql(sql)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="Montre sans écrire")
    args = parser.parse_args()

    print(f"Base : {engine.url.render_as_string(hide_password=True)}")
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            migrate_postgres(conn, args.dry_run)
        elif engine.dialect.name == "sqlite":
            migrate_sqlite(conn, args.dry_run)
        else:
            raise SystemExit(f"Dialecte non géré : {engine.dialect.name}")
    print("Terminé (aucune écriture)." if args.dry_run else "Migration appliquée.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
