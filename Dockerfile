# Minimal Python stdlib-only image
FROM python:3.12-alpine

# Install Docker CLI for optional CrowdSec integration via 'docker exec crowdsec cscli ...'
RUN apk add --no-cache docker-cli

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Default configuration can be overridden via env at runtime
ENV PANGOLIN_URL="https://api.url.of.your.pangolin.instance" \
    PANGOLIN_TOKEN="your_pangolin_token" \
    ORG_ID="your_org_id" \
    RESOURCE_IDS="2,7,12" \
    RETENTION_MINUTES="1440" \
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
