# Talos: the report API (`talos serve`) with the trace visualiser built in.
#
# Build from the repository root (the compose stack does this):
#   docker build -f deploy/docker/Dockerfile -t talos .
#
# Talos resolves config/, data/samples/, ui/dist/ and .env from the repository root
# (talos.core.settings.repository_root), so the image is the repository tree at /app with an
# editable install -- the same shape `make setup` produces. A plain `pip install .` would put the
# package in site-packages, the root would resolve to /usr/local/lib/python3.12, and every YAML
# file would be skipped in favour of the model defaults without a word.

# --- the browser face: ui/dist -------------------------------------------------------------
FROM node:22-slim AS ui
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# --- the service ----------------------------------------------------------------------------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ src/
RUN pip install -e .

COPY config/ config/
COPY db/ db/
COPY data/ data/
COPY scripts/ scripts/
COPY --from=ui /ui/dist ui/dist

RUN useradd --system --uid 10001 --no-create-home talos
USER talos

EXPOSE 8000
# /healthz round-trips the database, so "healthy" means incidents can actually be recorded.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

# Inside a container the loopback default is unreachable from the host, so bind every
# interface; the compose stack publishes the port on the host's loopback only.
CMD ["talos", "serve", "--host", "0.0.0.0"]
