"""`python -m iacguard ...` : même chose que la commande `iacguard`.

Pratique sous Windows si le dossier Scripts du venv n'est pas dans le PATH.
"""

from iacguard.cli import app

app(prog_name="iacguard")
