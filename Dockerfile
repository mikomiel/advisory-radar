# Multi-stage, rootless-friendly image for advisory-radar.
# Build:  docker build -t ghcr.io/mikomiel/advisory-radar:latest .
# Run:    docker run -v $PWD/config:/config:ro -v advisory-radar-data:/data -p 127.0.0.1:8080:8080 \
#           -e ADVISORY_RADAR_AUTH_TOKEN=... ghcr.io/mikomiel/advisory-radar:latest
# A bind-mounted data directory must be writable by uid 10001 (docs/deployment.md).
#
# The virtualenv is created at its *final* path (/app/.venv): a venv is not relocatable - its console
# scripts carry an absolute interpreter path - and the project is installed non-editably so the runtime
# stage does not need the build tree.

FROM ghcr.io/astral-sh/uv:0.9-python3.13-bookworm-slim AS builder
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
# The postgres extra installs psycopg so the image can use the PostgreSQL state store.
RUN uv sync --frozen --no-dev --no-install-project --extra postgres
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable --extra postgres

FROM python:3.13-slim-bookworm
RUN useradd --system --uid 10001 --home /data radar
# /data must exist, owned by the runtime user, before it is declared a VOLUME: a new named volume copies the owner and
# mode of the image's mount point, and WORKDIR alone creates it as root, which uid 10001 cannot write.
RUN install -d -o radar -g radar -m 0750 /data
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    ADVISORY_RADAR_CONFIG=/config/config.yml \
    PYTHONUNBUFFERED=1
WORKDIR /data
USER radar
VOLUME ["/data", "/config"]
EXPOSE 8080
# /healthz is unauthenticated by design (container probe). The probe is a subcommand, not inline Python: the compose
# file and the Podman quadlet run the same command, and none of the three has a string to quote.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["advisory-radar", "healthcheck"]
# No --config here: the command reads ADVISORY_RADAR_CONFIG (set above), and a flag would always win over it.
ENTRYPOINT ["advisory-radar"]
CMD ["run"]
