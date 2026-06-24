# Minimal Python stdlib-only image
FROM python:3.14-alpine

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

HEALTHCHECK --interval=60s --timeout=5s --start-period=15s --retries=3 \
    CMD pgrep -f app.py || exit 1

CMD ["python", "/app/app.py"]