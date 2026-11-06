# Multi-stage, rootless-friendly image for advisory-radar.
# Build:  docker build -t ghcr.io/mikomiel/advisory-radar:latest .
# Run:    docker run -v $PWD/config:/config:ro -v $PWD/data:/data -p 8080:8080 \
#           -e ADVISORY_RADAR_AUTH_TOKEN=... ghcr.io/mikomiel/advisory-radar:latest
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
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13-slim-bookworm
RUN useradd --system --uid 10001 --home /data radar
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    ADVISORY_RADAR_CONFIG=/config/config.yml \
    PYTHONUNBUFFERED=1
WORKDIR /data
USER radar
VOLUME ["/data", "/config"]
EXPOSE 8080
# /healthz is unauthenticated by design (container probe)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"
ENTRYPOINT ["advisory-radar", "--config", "/config/config.yml"]
CMD ["run"]
