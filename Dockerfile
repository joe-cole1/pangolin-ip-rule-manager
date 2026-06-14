# Minimal Python stdlib-only image
FROM crowdsecurity/crowdsec AS crowdsec

FROM python:3.14-alpine

# docker-cli: supports CrowdSec Mode B (docker exec). cscli: supports Mode A (LAPI).
# Both are inert unless the corresponding env vars are set at runtime.
RUN apk add --no-cache docker-cli
COPY --from=crowdsec /usr/local/bin/cscli /usr/local/bin/cscli

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

EXPOSE 8080

CMD ["python", "/app/app.py"]