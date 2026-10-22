"""Captures d'écran du dashboard iac-guard pour la soutenance (Playwright).

Prérequis :
  - données de démo : scripts/seed_demo.py ;
  - API sur http://localhost:8000 (docker compose up -d) ;
  - frontend sur http://localhost:3000, de préférence en build de prod
    (cd frontend && npm run build && npm run start) : aucun overlay de dev.
    En `next dev`, l'overlay Next.js est de toute façon masqué ci-dessous ;
  - pip install playwright && python -m playwright install chromium

Usage (depuis iac-guard/) :  python scripts/capture_ui.py [--headed]

Toutes les captures : 1600x1000, deviceScaleFactor 2, thème sombre (palette
`.dark` définie par l'app dans globals.css). Rien n'est validé : le triage et
l'exception de politique sont ouverts/remplis mais jamais soumis.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from playwright.sync_api import Page, expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "ui"

FRONT = "http://localhost:3000"
API = "http://localhost:8000"
VIEWPORT = {"width": 1600, "height": 1000}

ADMIN = "demo.admin@example.com"      # sans 2FA : sert à toutes les captures
MFA_USER = "demo.secops@example.com"  # TOTP actif : écran de double authentification
PASSWORD = "Demo-IacGuard-2026!"

# Thème sombre + aucun overlay de dev, réappliqués si React réécrit <html>.
INIT_SCRIPT = """
(() => {
  const css = `nextjs-portal, [data-nextjs-toast], [data-nextjs-dev-tools-button],
    #__next-build-watcher { display: none !important; }
    *, *::before, *::after { caret-color: transparent !important; }`;
  const apply = () => {
    const html = document.documentElement;
    if (!html.classList.contains('dark')) html.classList.add('dark');
    html.style.colorScheme = 'dark';
    if (document.head && !document.getElementById('demo-capture-style')) {
      const s = document.createElement('style');
      s.id = 'demo-capture-style';
      s.textContent = css;
      document.head.appendChild(s);
    }
  };
  window.__demoTheme = apply;
  // React réécrit la classe de <html> à l'hydratation : on observe le VRAI
  // élément racine, une fois le document construit.
  document.addEventListener('DOMContentLoaded', () => {
    apply();
    new MutationObserver(apply).observe(document.documentElement,
      { attributes: true, attributeFilter: ['class'] });
  });
})();
"""


def settle(page: Page) -> None:
    """Attend la fin des requêtes, des squelettes et des animations."""
    page.wait_for_load_state("networkidle")
    expect(page.locator('[data-slot="skeleton"]')).to_have_count(0, timeout=15_000)
    page.wait_for_load_state("networkidle")
    page.evaluate("document.fonts.ready")
    page.wait_for_timeout(900)  # transitions CSS
    if page.locator(".recharts-surface").count():
        page.wait_for_timeout(2500)  # animation d'entrée des courbes Recharts


def shot(page: Page, name: str) -> None:
    path = OUT / name
    page.evaluate("window.__demoTheme && window.__demoTheme()")
    if not page.evaluate("document.documentElement.classList.contains('dark')"):
        sys.exit(f"Thème sombre non appliqué pour {name}")
    page.wait_for_timeout(200)
    data = page.screenshot()
    # Sous Windows, un aperçu ouvert (IDE, antivirus) peut verrouiller le
    # fichier un court instant : on réessaie plutôt que d'échouer.
    for attempt in range(6):
        try:
            path.write_bytes(data)
            break
        except OSError:
            if attempt == 5:
                raise
            page.wait_for_timeout(500)
    print(f"  {path.relative_to(ROOT)}")


def login(page: Page, email: str, wait_home: bool = True) -> None:
    page.goto(f"{FRONT}/login")
    page.locator("#email").fill(email)
    page.locator("#email").press("Enter")
    page.locator("#password").fill(PASSWORD)
    page.locator("#password").press("Enter")
    if wait_home:
        page.wait_for_url(f"{FRONT}/", timeout=15_000)


def project_ids(page: Page) -> dict[str, int]:
    """Ids des projets, via l'API avec le cookie de session du navigateur."""
    resp = page.context.request.get(f"{API}/api/projects")
    if not resp.ok:
        sys.exit(f"GET /api/projects -> {resp.status} : le seed a-t-il été lancé ?")
    return {p["name"]: p["id"] for p in resp.json()}


def pick(page: Page, trigger_index: int, option: str) -> None:
    """Choisit une option d'un Select (base-ui) de la page."""
    page.locator('[data-slot="select-trigger"]').nth(trigger_index).click()
    page.locator('[data-slot="select-item"]', has_text=option).first.click()
    page.wait_for_timeout(300)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--headed", action="store_true", help="Afficher le navigateur")
    args = parser.parse_args()
    OUT.mkdir(exist_ok=True)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not args.headed)

        def new_page() -> Page:
            ctx = browser.new_context(
                viewport=VIEWPORT, device_scale_factor=2, color_scheme="dark",
                locale="fr-FR", timezone_id="Africa/Casablanca",
            )
            ctx.add_init_script(INIT_SCRIPT)
            return ctx.new_page()

        page = new_page()
        login(page, ADMIN)
        ids = project_ids(page)
        missing = {"app-infra", "api-paiement", "portail-client", "data-lake"} - ids.keys()
        if missing:
            sys.exit(f"Projets de démo absents : {', '.join(sorted(missing))}")
        app_infra = ids["app-infra"]
        print("Captures :")

        # 1. Dashboard app-infra : 42 / 100, grade D, courbe d'activité.
        page.goto(f"{FRONT}/?project={app_infra}")
        expect(page.get_by_text("42 / 100")).to_be_visible(timeout=15_000)
        expect(page.locator(".recharts-surface").first).to_be_visible()
        settle(page)
        shot(page, "ui_1_dashboard.png")

        # 1b. Les 4 projets avec leur dernier score / grade.
        page.goto(f"{FRONT}/projects")
        expect(page.get_by_text("42 / 100")).to_be_visible(timeout=15_000)
        for score in ("94 / 100", "80 / 100", "64 / 100"):
            expect(page.get_by_text(score)).to_be_visible()
        settle(page)
        shot(page, "ui_1b_projects.png")

        # 2. Findings du scan feature/add-rds (5 lignes).
        page.goto(f"{FRONT}/alerts?project={app_infra}")
        rows = page.locator("tbody tr.cursor-pointer")
        expect(rows).to_have_count(5, timeout=15_000)
        settle(page)
        shot(page, "ui_2_findings.png")

        # 3. Fiche d'un finding ouverte, actions de triage visibles (non cliquées).
        rows.filter(has_text="publicly accessible").first.click()
        sheet = page.locator('[data-slot="sheet-content"]')
        expect(sheet).to_be_visible()
        expect(sheet.get_by_text("Actions")).to_be_visible()
        page.wait_for_timeout(700)  # fin de l'animation d'ouverture
        note = sheet.locator("#triage-note")
        if note.count():  # champ « Note / justification » (saisi, jamais validé)
            note.fill("Base exposée temporairement pour la migration ; "
                      "fermeture prévue avant la mise en production.")
            note.blur()
            sheet.get_by_text("Actions").scroll_into_view_if_needed()
            page.wait_for_timeout(300)
        shot(page, "ui_3_triage.png")
        page.keyboard.press("Escape")

        # 3b. Formulaire « risque accepté » avec justification, NON soumis.
        page.goto(f"{FRONT}/settings")
        page.get_by_role("tab", name="Politiques de scan").click()
        settle(page)
        pick(page, 0, "data-lake")
        settle(page)
        page.locator("#rule-id").fill("CKV_AWS_144")
        page.locator("#rule-note").fill(
            "Données rejouables (Kafka 7 j)"  # le champ de l'app est étroit (w-64)
        )
        page.locator("#rule-note").blur()
        page.wait_for_timeout(300)
        shot(page, "ui_3b_risque_accepte.png")

        # 4. Politique du projet app-infra : seuil « Élevée ou pire ».
        page.goto(f"{FRONT}/settings")
        page.get_by_role("tab", name="Politiques de scan").click()
        settle(page)
        pick(page, 0, "app-infra")
        settle(page)
        expect(page.locator('[data-slot="select-trigger"]').nth(1)).to_contain_text("Élevée")
        shot(page, "ui_4_policy.png")

        # 5. Journal d'audit des actions d'administration.
        page.goto(f"{FRONT}/admin")
        page.get_by_role("tab", name="Journal d'audit").click()
        settle(page)
        expect(page.locator("tbody tr").first).to_be_visible()
        shot(page, "ui_5_audit.png")

        # 5b. Journal d'audit des décisions de triage.
        page.goto(f"{FRONT}/settings")
        page.get_by_role("tab", name="Audit").click()
        settle(page)
        expect(page.get_by_text("data-lake").first).to_be_visible()
        shot(page, "ui_5b_audit_triage.png")

        # 6. Écran de double authentification (TOTP), sans valider le code.
        mfa = new_page()
        login(mfa, MFA_USER, wait_home=False)
        expect(mfa.locator("input[data-input-otp]")).to_be_visible(timeout=15_000)
        settle(mfa)
        shot(mfa, "ui_6_mfa.png")

        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
