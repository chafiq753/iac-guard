"""Génère le PDF de documentation à partir de DOCUMENTATION_COMPLETE.md.

Chaîne : Markdown -> HTML (mise en page d'impression) -> PDF via Chrome headless
piloté en CDP (Chrome DevTools Protocol).

Pourquoi le CDP plutôt que `chrome --print-to-pdf` : seule la commande
`Page.printToPDF` accepte un `footerTemplate`, donc une numérotation des pages.
Chromium n'implémente pas les boîtes de marge CSS (`@page { @bottom-center }`),
il n'y a pas d'autre moyen d'obtenir un numéro de page.

    python tools/build_pdf.py

Sorties : docs/iac-guard-documentation.html et docs/iac-guard-documentation.pdf
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

import markdown
import websockets

RACINE = Path(__file__).resolve().parent.parent
SOURCE = RACINE / "DOCUMENTATION_COMPLETE.md"
SORTIE_HTML = RACINE / "docs" / "iac-guard-documentation.html"
SORTIE_PDF = RACINE / "docs" / "iac-guard-documentation.pdf"

TITRE = "iac-guard"
SOUS_TITRE = "Documentation complète"
BASELINE = (
    "Fonctionnement de bout en bout, protocoles, outils, "
    "algorithmes, méthode de travail et procédures opérationnelles."
)

CHROME_CANDIDATS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]


# --------------------------------------------------------------------------- #
# Markdown -> HTML
# --------------------------------------------------------------------------- #


def decouper_source(texte: str) -> str:
    """Retire l'en-tête (titre + encadré de métadonnées) et le sommaire manuel.

    Le titre part sur la page de couverture, et le sommaire est régénéré par
    l'extension `toc` : garder le sommaire manuel produirait des ancres
    incohérentes (il vise les slugs GitHub, qui conservent les accents).
    """
    lignes = texte.split("\n")

    # 1. Tout ce qui précède le premier séparateur `---` est repris par la
    #    couverture (titre, accroche, tableau de métadonnées).
    debut = next(i for i, l in enumerate(lignes) if l.strip() == "---")
    lignes = lignes[debut + 1 :]

    # 2. Le bloc « ## Sommaire » jusqu'au séparateur suivant.
    try:
        i = next(i for i, l in enumerate(lignes) if l.strip() == "## Sommaire")
    except StopIteration:
        return "\n".join(lignes)
    j = next(j for j in range(i + 1, len(lignes)) if lignes[j].strip() == "---")
    del lignes[i : j + 1]
    return "\n".join(lignes)


def construire_html() -> str:
    corps_md = decouper_source(SOURCE.read_text(encoding="utf-8"))

    md = markdown.Markdown(
        extensions=["extra", "toc", "sane_lists"],
        extension_configs={"toc": {"toc_depth": "1-2", "anchorlink": False}},
    )
    corps = md.convert(corps_md)
    sommaire = md.toc

    return GABARIT.format(
        titre=TITRE,
        sous_titre=SOUS_TITRE,
        baseline=BASELINE,
        style=STYLE,
        sommaire=sommaire,
        corps=corps,
    )


# --------------------------------------------------------------------------- #
# HTML -> PDF (Chrome headless en CDP)
# --------------------------------------------------------------------------- #


def trouver_chrome() -> str:
    for chemin in CHROME_CANDIDATS:
        if os.path.exists(chemin):
            return chemin
    for nom in ("chrome", "chromium", "msedge"):
        trouve = shutil.which(nom)
        if trouve:
            return trouve
    raise SystemExit("Aucun navigateur Chromium trouvé.")


def port_libre() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def attendre_cible(port: int, timeout: float = 30.0) -> str:
    """Attend que Chrome expose une cible `page` et renvoie son URL WebSocket."""
    import time

    limite = time.time() + timeout
    while time.time() < limite:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/json/list", timeout=2
            ) as r:
                cibles = json.load(r)
            for c in cibles:
                if c.get("type") == "page" and c.get("webSocketDebuggerUrl"):
                    return c["webSocketDebuggerUrl"]
        except Exception:
            pass
        time.sleep(0.3)
    raise SystemExit("Chrome n'a pas exposé de cible de rendu à temps.")


async def imprimer(ws_url: str, url_fichier: str) -> bytes:
    async with websockets.connect(ws_url, max_size=200 * 1024 * 1024) as ws:
        compteur = {"n": 0}

        async def envoyer(methode: str, params: dict | None = None) -> dict:
            compteur["n"] += 1
            ident = compteur["n"]
            await ws.send(
                json.dumps({"id": ident, "method": methode, "params": params or {}})
            )
            while True:
                msg = json.loads(await ws.recv())
                if msg.get("id") == ident:
                    if "error" in msg:
                        raise SystemExit(f"{methode} : {msg['error']}")
                    return msg.get("result", {})

        async def attendre_evenement(nom: str, timeout: float = 60.0) -> None:
            async def boucle() -> None:
                while True:
                    msg = json.loads(await ws.recv())
                    if msg.get("method") == nom:
                        return

            await asyncio.wait_for(boucle(), timeout)

        await envoyer("Page.enable")
        await envoyer("Page.navigate", {"url": url_fichier})
        await attendre_evenement("Page.loadEventFired")
        # Laisse la mise en page se stabiliser (polices, calcul des sauts).
        await asyncio.sleep(1.5)

        resultat = await envoyer(
            "Page.printToPDF",
            {
                "printBackground": True,
                "paperWidth": 8.27,   # A4
                "paperHeight": 11.69,
                "marginTop": 0.72,
                "marginBottom": 0.68,
                "marginLeft": 0.67,
                "marginRight": 0.67,
                "displayHeaderFooter": True,
                "headerTemplate": "<span></span>",
                "footerTemplate": PIED_DE_PAGE,
                "preferCSSPageSize": False,
            },
        )
        return base64.b64decode(resultat["data"])


def verifier_pdf(chemin: Path) -> tuple[int, int]:
    """Contrôle d'intégrité du PDF produit.

    Un PDF peut être corrompu APRÈS génération — typiquement s'il est ouvert
    comme du texte dans un éditeur puis enregistré : l'octet de tête est
    déplacé et tous les octets ≥ 0x80 sont ré-encodés en UTF-8, ce qui gonfle
    le fichier d'environ un tiers et le rend illisible (visionneuse vide).
    Vérifier ici garantit au moins que le fichier était sain à la sortie.

    Renvoie (nombre de pages, nombre d'opérateurs de texte).
    """
    import re
    import zlib

    donnees = chemin.read_bytes()

    if not donnees.startswith(b"%PDF-"):
        raise SystemExit(
            f"PDF invalide : l'en-tête est {donnees[:12]!r} au lieu de '%PDF-'. "
            "Le fichier a probablement été réenregistré par un éditeur de texte."
        )
    if b"%%EOF" not in donnees[-2048:]:
        raise SystemExit("PDF invalide : marqueur %%EOF absent de la fin du fichier.")

    pages = len(re.findall(rb"/Type\s*/Page[^s]", donnees))
    if pages == 0:
        raise SystemExit("PDF invalide : aucune page.")

    # `endstream` contient `stream` : la garde (?<!end) évite un décalage.
    flux = re.findall(rb"(?<!end)stream\r?\n(.*?)\r?\nendstream", donnees, re.S)
    operateurs = 0
    for f in flux:
        try:
            brut = zlib.decompress(f)
        except zlib.error:
            continue
        operateurs += len(re.findall(rb"\bTj\b|\bTJ\b", brut))

    if operateurs == 0:
        raise SystemExit("PDF invalide : aucun opérateur de texte, les pages sont vides.")

    return pages, operateurs


def generer_pdf(chemin_html: Path) -> None:
    chrome = trouver_chrome()
    port = port_libre()
    profil = tempfile.mkdtemp(prefix="iacguard-pdf-")

    processus = subprocess.Popen(
        [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--run-all-compositor-stages-before-draw",
            f"--remote-debugging-port={port}",
            f"--user-data-dir={profil}",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        ws_url = attendre_cible(port)
        url = chemin_html.resolve().as_uri()
        pdf = asyncio.run(imprimer(ws_url, url))
        SORTIE_PDF.write_bytes(pdf)
    finally:
        processus.terminate()
        try:
            processus.wait(timeout=10)
        except subprocess.TimeoutExpired:
            processus.kill()
        shutil.rmtree(profil, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Gabarit et styles
# --------------------------------------------------------------------------- #

PIED_DE_PAGE = """
<div style="width:100%;font-family:'Segoe UI',Arial,sans-serif;font-size:7pt;
            color:#8b9aa8;padding:0 17mm;display:flex;justify-content:space-between;
            -webkit-print-color-adjust:exact;">
  <span>iac-guard &middot; Documentation compl&egrave;te</span>
  <span class="pageNumber"></span>
</div>
"""

STYLE = """
@page { size: A4; }

* { box-sizing: border-box; }

html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }

body {
  margin: 0;
  font-family: "Segoe UI", "Inter", system-ui, -apple-system, Arial, sans-serif;
  font-size: 10pt;
  line-height: 1.55;
  color: #26323f;
  font-feature-settings: "kern" 1, "liga" 1;
}

/* --- Couverture -------------------------------------------------------- */

.couverture {
  min-height: 238mm;
  background: linear-gradient(160deg, #0d1b26 0%, #123243 62%, #0b5d7a 100%);
  color: #ffffff;
  padding: 26mm 20mm 18mm 20mm;
  display: flex;
  flex-direction: column;
  page-break-after: always;
}

.couverture .marque {
  font-size: 8.5pt;
  letter-spacing: 0.26em;
  text-transform: uppercase;
  color: #74c2dd;
  margin-bottom: auto;
}

.couverture h1 {
  font-size: 40pt;
  line-height: 1.02;
  font-weight: 700;
  letter-spacing: -0.02em;
  margin: 0 0 2mm 0;
  padding: 0;
  border: 0;
  color: #ffffff;
  page-break-before: auto;
}

.couverture .sous-titre {
  font-size: 17pt;
  font-weight: 300;
  color: #9fd2e5;
  margin: 0 0 8mm 0;
}

.couverture .filet {
  width: 54mm;
  height: 3px;
  background: #f0a04b;
  margin: 0 0 8mm 0;
}

.couverture .baseline {
  font-size: 11pt;
  line-height: 1.6;
  color: #cfe3ec;
  max-width: 120mm;
  margin: 0 0 14mm 0;
}

.couverture .meta {
  border-top: 1px solid rgba(255,255,255,0.18);
  padding-top: 6mm;
  font-size: 8.8pt;
  color: #b7d2de;
}
.couverture .meta table { width: 100%; border-collapse: collapse; }
.couverture .meta td {
  border: 0;
  padding: 1.6mm 0;
  vertical-align: top;
  background: none;
}
.couverture .meta td:first-child {
  width: 42mm;
  color: #7fb4c9;
  text-transform: uppercase;
  letter-spacing: 0.09em;
  font-size: 7.4pt;
  padding-top: 2.1mm;
}
.couverture .meta strong { color: #ffffff; font-weight: 600; }

/* --- Sommaire ---------------------------------------------------------- */

.sommaire { page-break-after: always; }

.sommaire > h2 {
  font-size: 15pt;
  color: #0d1b26;
  border-bottom: 2px solid #0b5d7a;
  padding-bottom: 3mm;
  margin: 0 0 7mm 0;
}

.sommaire .toc > ul { list-style: none; margin: 0; padding: 0; }

.sommaire .toc > ul > li {
  margin: 0 0 1.5mm 0;
  padding: 2.2mm 0 2.2mm 0;
  border-bottom: 1px solid #eef2f5;
}

.sommaire .toc > ul > li > a {
  font-size: 11pt;
  font-weight: 600;
  color: #0d1b26;
  text-decoration: none;
}

.sommaire .toc ul ul {
  list-style: none;
  margin: 1.6mm 0 0 0;
  padding: 0 0 0 6mm;
  column-count: 2;
  column-gap: 8mm;
}

.sommaire .toc ul ul li { margin: 0 0 0.9mm 0; break-inside: avoid; }

.sommaire .toc ul ul a {
  font-size: 8.6pt;
  color: #5f7183;
  text-decoration: none;
}

.sommaire .toc ul ul ul { display: none; }

/* --- Corps ------------------------------------------------------------- */

.corps { padding-top: 0; }

h1 {
  font-size: 21pt;
  line-height: 1.15;
  font-weight: 700;
  letter-spacing: -0.015em;
  color: #0d1b26;
  margin: 0 0 6mm 0;
  padding-top: 6mm;
  border-top: 3px solid #0b5d7a;
  page-break-before: always;
  break-after: avoid;
}

.corps > h2:first-child, .corps > h1:first-child { page-break-before: avoid; }

h2 {
  font-size: 13pt;
  font-weight: 650;
  color: #0d1b26;
  margin: 9mm 0 3.5mm 0;
  padding-bottom: 1.6mm;
  border-bottom: 1px solid #dde5eb;
  break-after: avoid;
}

h3 {
  font-size: 10.6pt;
  font-weight: 650;
  color: #0b5d7a;
  margin: 6mm 0 2mm 0;
  break-after: avoid;
}

h4 {
  font-size: 10pt;
  font-weight: 650;
  color: #26323f;
  margin: 4mm 0 1.5mm 0;
  break-after: avoid;
}

p { margin: 0 0 3mm 0; orphans: 3; widows: 3; }

strong { font-weight: 650; color: #16232f; }

a { color: #0b5d7a; text-decoration: none; }

ul, ol { margin: 0 0 3.5mm 0; padding-left: 6mm; }
li { margin-bottom: 1.2mm; }

/* Les séparateurs `---` ne servent qu'à structurer la source : les sauts de
   page des titres suffisent, un filet en bas de page ferait accident. */
hr { display: none; }

/* --- Tableaux ---------------------------------------------------------- */

table {
  width: 100%;
  border-collapse: collapse;
  margin: 3mm 0 5mm 0;
  font-size: 8.8pt;
  line-height: 1.42;
}

thead { display: table-header-group; }

th {
  background: #eef4f7;
  color: #0d1b26;
  text-align: left;
  font-weight: 650;
  font-size: 7.8pt;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  padding: 2.2mm 2.6mm;
  border-bottom: 1.5px solid #b9d2dd;
}

td {
  padding: 2mm 2.6mm;
  border-bottom: 1px solid #e8edf1;
  vertical-align: top;
}

tbody tr:nth-child(even) td { background: #fafcfd; }

tr { break-inside: avoid; }

/* --- Code -------------------------------------------------------------- */

pre {
  background: #f6f9fb;
  border-left: 3px solid #0b5d7a;
  border-radius: 0 3px 3px 0;
  padding: 3mm 4mm;
  margin: 3mm 0 5mm 0;
  overflow: hidden;
  break-inside: avoid;
}

pre code {
  font-family: Consolas, "Cascadia Mono", "SFMono-Regular", monospace;
  font-size: 7.8pt;
  line-height: 1.4;
  color: #1d2b38;
  white-space: pre;
  background: none;
  padding: 0;
  border: 0;
}

code {
  font-family: Consolas, "Cascadia Mono", "SFMono-Regular", monospace;
  font-size: 8.6pt;
  background: #eef2f6;
  color: #0f3b4d;
  padding: 0.3mm 1.1mm;
  border-radius: 2px;
}

th code, td code { font-size: 7.9pt; }

/* --- Citations --------------------------------------------------------- */

blockquote {
  margin: 3mm 0 4mm 0;
  padding: 0.5mm 0 0.5mm 5mm;
  border-left: 3px solid #cbd9e2;
  color: #55677a;
  font-style: italic;
}

blockquote p { margin-bottom: 1.5mm; }
blockquote strong { color: #26323f; }
"""

GABARIT = """<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>{titre} — {sous_titre}</title>
<style>{style}</style>
</head>
<body>

<section class="couverture">
  <div class="marque">Sécurité de l'Infrastructure as Code</div>
  <h1>{titre}</h1>
  <div class="sous-titre">{sous_titre}</div>
  <div class="filet"></div>
  <p class="baseline">{baseline}</p>
  <div class="meta">
    <table>
      <tr><td>Dépôt</td><td><strong>ZenithSoft / iac-guard</strong> — branche <strong>main</strong></td></tr>
      <tr><td>État décrit</td><td>commit <strong>a2854f1</strong> — « Refuser le démarrage en production avec une configuration dangereuse »</td></tr>
      <tr><td>Date</td><td><strong>15 septembre 2026</strong></td></tr>
      <tr><td>Vérification</td><td>Chiffres relus dans le code &middot; suite de tests exécutée : <strong>151 cas passants, 0 échec</strong></td></tr>
    </table>
  </div>
</section>

<section class="sommaire">
  <h2>Sommaire</h2>
  {sommaire}
</section>

<section class="corps">
{corps}
</section>

</body>
</html>
"""


def main() -> int:
    if not SOURCE.exists():
        raise SystemExit(f"Source introuvable : {SOURCE}")

    SORTIE_HTML.parent.mkdir(parents=True, exist_ok=True)
    SORTIE_HTML.write_text(construire_html(), encoding="utf-8")
    print(f"HTML  -> {SORTIE_HTML}  ({SORTIE_HTML.stat().st_size // 1024} Ko)")

    generer_pdf(SORTIE_HTML)
    pages, operateurs = verifier_pdf(SORTIE_PDF)
    print(f"PDF   -> {SORTIE_PDF}  ({SORTIE_PDF.stat().st_size // 1024} Ko)")
    print(f"Vérif -> {pages} pages, {operateurs} opérateurs de texte, en-tête et EOF valides")
    return 0


if __name__ == "__main__":
    sys.exit(main())
