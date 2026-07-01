# Minimal Python stdlib-only image
# Digest-pinned for reproducible builds; Dependabot (docker ecosystem) bumps it.
FROM python:3.14-alpine@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92

# Install Docker CLI for optional CrowdSec integration via 'docker exec crowdsec cscli ...'
RUN apk add --no-cache docker-cli

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Operational defaults — PANGOLIN_URL, PANGOLIN_TOKEN, ORG_ID, and RESOURCE_IDS
# are not set here; they must always be injected at runtime via your orchestrator
# (Portainer, compose, etc.)
ENV RETENTION_MINUTES="1440" \
    LISTEN_PORT="8080" \
    STATE_FILE="/data/state.json" \
    CLEANUP_INTERVAL_MINUTES="60" \
    RULE_PRIORITY="0" \
    RULES_CACHE_TTL_SECONDS="3600"

WORKDIR /app
# Copy all application modules (after refactor we have multiple .py files)
COPY *.py /app/
COPY templates/ /app/templates/

# Run as a non-root user; create the data directory first so the volume mount
# inherits the correct ownership when the container starts.
RUN addgroup -S appgroup && adduser -S appuser -G appgroup \
    && mkdir -p /data && chown appuser:appgroup /data

USER appuser

EXPOSE 8080

# Probe the HTTP liveness route so a hung server is detected, not just a live process.
HEALTHCHECK --interval=60s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -q -O - "http://127.0.0.1:${LISTEN_PORT}/healthz" || exit 1

CMD ["python", "/app/app.py"]