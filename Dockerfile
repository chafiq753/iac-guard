# =============================================================================
#  Image iac-guard : l'outil + Checkov + Gitleaks + Semgrep, rien à installer.
#
#    docker run --rm -v "${PWD}:/src" ghcr.io/chafiq753/iacguard scan
#
#  Le code à scanner est monté dans /src (lecture seule conseillée : :ro).
#  (Le Dockerfile du dashboard est dans backend/, celui-ci ne concerne que
#   l'outil en ligne de commande.)
# =============================================================================
FROM python:3.12-slim

ARG GITLEAKS_VERSION=8.21.2
# Fourni par `docker buildx` (amd64 ou arm64 : Mac M1/M2, serveurs ARM)
ARG TARGETARCH=amd64

LABEL org.opencontainers.image.title="iac-guard" \
      org.opencontainers.image.description="Scanner de sécurité IaC : Gitleaks, Checkov, Semgrep" \
      org.opencontainers.image.source="https://github.com/chafiq753/iac-guard" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    # Couleurs et tableau lisibles même sans terminal détecté (docker run sans -t)
    COLUMNS=160

# git : Gitleaks lit l'historique. curl/ca-certificates : téléchargement de Gitleaks.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
      amd64) GL_ARCH=x64 ;; \
      arm64) GL_ARCH=arm64 ;; \
      *) echo "Architecture non supportée : ${TARGETARCH}" && exit 1 ;; \
    esac \
 && curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks \
 && gitleaks version

# Scanners d'abord (couche lourde, rarement modifiée), l'outil ensuite.
RUN pip install checkov semgrep

COPY pyproject.toml README.md LICENSE /build/
COPY iacguard /build/iacguard
RUN pip install /build && rm -rf /build

# Le dossier monté appartient à l'utilisateur de la machine, pas à celui du
# conteneur : sans ça, git refuse de lire le dépôt (« dubious ownership »)
# et Gitleaks ne verrait pas l'historique.
RUN git config --system --add safe.directory '*'

# Pas de root dans le conteneur.
RUN useradd --create-home --uid 10001 scanner
USER scanner
# HOME dans /tmp : toujours inscriptible, même lancé avec --user $(id -u)
# (Linux, pour écrire le rapport dans le dossier monté). Semgrep et le cache
# de `iacguard show` y écrivent.
ENV HOME=/tmp

WORKDIR /src
ENTRYPOINT ["iacguard"]
CMD ["scan", "/src"]
