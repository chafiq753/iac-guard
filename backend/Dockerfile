# Image API iac-guard (FastAPI + Uvicorn).
FROM python:3.12-slim

# - PYTHONDONTWRITEBYTECODE : pas de .pyc dans le conteneur
# - PYTHONUNBUFFERED : logs Python envoyés directement (utiles avec Docker)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Installer les dépendances d'abord (meilleur cache Docker si le code change).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code de l'application.
COPY . .

EXPOSE 8000

# Uvicorn écoute sur toutes les interfaces pour être joignable hors du conteneur.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
