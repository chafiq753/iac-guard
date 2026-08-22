"""Migration RBAC : prépare une base EXISTANTE aux comptes multi-utilisateurs.

`Base.metadata.create_all` (au démarrage de l'app) crée les tables manquantes
mais n'ajoute JAMAIS de colonne à une table déjà présente. Une base créée
avant le RBAC a donc un `users` sans `org_id`/`role`/`last_login_at`, et
l'API échoue sur « no such column: users.org_id ».

Ce script comble l'écart :
  1. ajoute les colonnes manquantes sur `users` ;
  2. crée les nouvelles tables (organizations, invitations, project_access,
     admin_audit_logs) ;
  3. donne une organisation à chaque compte existant, en le passant `admin`
     (il possédait déjà ses projets : il reste maître de son périmètre) ;
  4. relâche le NOT NULL sur `users.hashed_password` (un compte invité n'a pas
     encore de mot de passe) — ce qui impose de réécrire la table sous SQLite.

Idempotent : relancer ne casse rien, les étapes déjà faites sont ignorées.

    python scripts/migrate_rbac.py            # sur settings.database_url
    python scripts/migrate_rbac.py --dry-run  # montre sans écrire

⚠️  Faites une copie de votre base avant (cp iacguard.db iacguard.db.bak).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Permet de lancer le script depuis n'importe où (`python scripts/...`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import inspect, select, text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.db.session import Base, engine  # noqa: E402

# Import des modèles : create_all doit connaître TOUTES les tables.
from app.models import (  # noqa: E402,F401
    admin_audit_log,
    audit_log,
    credential,
    finding,
    ignored_rule,
    invitation,
    organization,
    project,
    project_access,
    scan,
    triage,
    user,
)
from app.models.organization import Organization  # noqa: E402
from app.models.user import User  # noqa: E402

# Colonnes ajoutées à `users` par le RBAC. `org_id` est volontairement déclaré
# SANS NOT NULL ici : on ne peut pas remplir une colonne obligatoire sur des
# lignes existantes. L'ORM, lui, l'exige — ce qui suffit pour les écritures
# futures. (SQLite ne sait de toute façon pas ajouter une colonne NOT NULL
# sans valeur par défaut.)
def _user_columns() -> dict[str, str]:
    """DDL des colonnes RBAC, adapté au dialecte.

    `DATETIME` n'existe pas sous PostgreSQL — il lui faut `TIMESTAMPTZ`.
    """
    timestamp = "DATETIME" if engine.dialect.name == "sqlite" else "TIMESTAMPTZ"
    return {
        "org_id": "INTEGER REFERENCES organizations(id)",
        "role": "VARCHAR(20)",
        "last_login_at": timestamp,
        "created_by_id": "INTEGER REFERENCES users(id)",
    }


def _existing_columns(table: str) -> set[str]:
    inspector = inspect(engine)
    if table not in inspector.get_table_names():
        return set()
    return {c["name"] for c in inspector.get_columns(table)}


def add_missing_columns(dry_run: bool) -> list[str]:
    """Étape 1 : ALTER TABLE pour les colonnes RBAC manquantes."""
    done: list[str] = []
    present = _existing_columns("users")
    if not present:
        return done  # base neuve : create_all fera tout

    for column, ddl in _user_columns().items():
        if column in present:
            continue
        statement = f"ALTER TABLE users ADD COLUMN {column} {ddl}"
        done.append(statement)
        if not dry_run:
            with engine.begin() as conn:
                conn.execute(text(statement))

    return done


def relax_password_not_null(dry_run: bool) -> bool:
    """Étape 4 : rend `users.hashed_password` nullable (compte invité).

    Sans cette étape, inviter quelqu'un échoue sur une violation de contrainte
    NOT NULL.

    PostgreSQL sait le faire d'un simple ALTER. SQLite, non : il faut recréer
    la table et recopier les lignes — on la reconstruit alors à partir de la
    définition ORM (source de vérité) plutôt qu'en réécrivant le DDL à la main.
    """
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return False

    columns = {c["name"]: c for c in inspector.get_columns("users")}
    if columns.get("hashed_password", {}).get("nullable", True):
        return False  # déjà nullable : rien à faire

    if dry_run:
        return True

    if engine.dialect.name != "sqlite":
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE users ALTER COLUMN hashed_password DROP NOT NULL")
            )
        return True

    users_table = Base.metadata.tables["users"]
    # Colonnes présentes des DEUX côtés : une colonne ajoutée depuis n'existe
    # pas dans l'ancienne table, et inversement.
    shared = [c.name for c in users_table.columns if c.name in columns]
    col_list = ", ".join(f'"{c}"' for c in shared)
    # Un index renommé suit sa table mais GARDE son nom : sans ce DROP, la
    # recréation échouerait sur « index ix_users_email already exists ».
    old_indexes = [ix["name"] for ix in inspector.get_indexes("users") if ix.get("name")]

    with engine.begin() as conn:
        # Les FK des autres tables pointent vers `users` : on les désactive le
        # temps de l'échange, sinon le DROP casserait les références.
        conn.execute(text("PRAGMA foreign_keys=OFF"))
        conn.execute(text("ALTER TABLE users RENAME TO users_old_rbac"))
        for index_name in old_indexes:
            conn.execute(text(f'DROP INDEX IF EXISTS "{index_name}"'))

    users_table.create(bind=engine)

    with engine.begin() as conn:
        conn.execute(
            text(f"INSERT INTO users ({col_list}) SELECT {col_list} FROM users_old_rbac")
        )
        conn.execute(text("DROP TABLE users_old_rbac"))
        conn.execute(text("PRAGMA foreign_keys=ON"))
    return True


def create_new_tables(dry_run: bool) -> list[str]:
    """Étape 2 : crée organizations, invitations, project_access, admin_audit_logs."""
    inspector = inspect(engine)
    before = set(inspector.get_table_names())
    expected = set(Base.metadata.tables)
    missing = sorted(expected - before)

    if missing and not dry_run:
        Base.metadata.create_all(bind=engine)
    return missing


def backfill_organizations(dry_run: bool) -> list[str]:
    """Étape 3 : une organisation par compte existant, rôle `admin`.

    Chaque utilisateur devient l'admin de sa propre organisation : c'est le
    seul choix sûr sans connaître qui travaille avec qui. Pour regrouper deux
    comptes ensuite, un admin invite l'autre — ou l'on met le même `org_id`
    à la main.
    """
    actions: list[str] = []
    with Session(engine) as db:
        rows = db.execute(
            text("SELECT id, email, org_id, role FROM users ORDER BY id")
        ).all()

        for user_id, email, org_id, role in rows:
            if org_id is not None and role is not None:
                continue

            org_name = email.split("@", 1)[0]
            actions.append(f"user #{user_id} ({email}) -> org '{org_name}', role=admin")
            if dry_run:
                continue

            if org_id is None:
                org = Organization(name=org_name)
                db.add(org)
                db.flush()
                org_id = org.id

            db.execute(
                text("UPDATE users SET org_id = :o, role = COALESCE(role, 'admin') WHERE id = :u"),
                {"o": org_id, "u": user_id},
            )
        if not dry_run:
            db.commit()
    return actions


def verify() -> None:
    """Contrôle final : l'ORM doit pouvoir lire chaque utilisateur."""
    with Session(engine) as db:
        users = db.scalars(select(User)).all()
        print(f"\n[OK] Verification : {len(users)} compte(s) lisible(s) par l'ORM")
        for u in users:
            print(f"    #{u.id} {u.email}  org={u.org_id}  role={u.role}  statut={u.status}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Migration RBAC iac-guard")
    parser.add_argument(
        "--dry-run", action="store_true", help="montre les changements sans les écrire"
    )
    args = parser.parse_args()

    print(f"Base : {settings.database_url}")
    if args.dry_run:
        print("Mode --dry-run : AUCUNE écriture.\n")

    # Les tables d'abord : `users.org_id` référence `organizations`, que
    # PostgreSQL exige d'exister avant d'accepter la clé étrangère.
    tables = create_new_tables(args.dry_run)
    print(f"1. Tables créées : {len(tables)}")
    for t in tables:
        print(f"    {t}")

    columns = add_missing_columns(args.dry_run)
    print(f"\n2. Colonnes ajoutées à `users` : {len(columns)}")
    for c in columns:
        print(f"    {c}")

    if args.dry_run:
        print("\n3. Backfill des organisations : (dry-run, les colonnes n'existent")
        print("   pas encore — relancez sans --dry-run pour voir le détail)")
        return 0

    orgs = backfill_organizations(args.dry_run)
    print(f"\n3. Comptes rattachés à une organisation : {len(orgs)}")
    for o in orgs:
        print(f"    {o}")

    relaxed = relax_password_not_null(args.dry_run)
    how = "table réécrite" if engine.dialect.name == "sqlite" else "ALTER COLUMN"
    print(
        "\n4. `users.hashed_password` rendu nullable (invitations) : "
        + (how if relaxed else "déjà nullable, rien à faire")
    )

    verify()
    print("\nMigration terminée.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
