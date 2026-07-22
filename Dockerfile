# syntax=docker/dockerfile:1

# Start from the current patched Python 3.14 Alpine image. The digest is
# multi-architecture and Dependabot keeps it current.
FROM python:3.14.6-alpine3.24@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92 AS runtime-root

# Keep the existing 100:101 identity stable so upgrades can read and write named
# volumes created by earlier images. New named volumes inherit /data's ownership
# and mode automatically; no host-side chown or chmod is needed.
RUN apk add --no-cache docker-cli \
    && addgroup -S -g 101 appgroup \
    && adduser -S -D -H -h /nonexistent -s /sbin/nologin \
        -u 100 -G appgroup appuser \
    && mkdir -p /app/templates /data \
    && chmod 0755 /app /app/templates \
    && chown appuser:appgroup /data \
    && chmod 0700 /data \
    && rm -rf \
        /usr/local/bin/idle* \
        /usr/local/bin/pip* \
        /usr/local/bin/pydoc* \
        /usr/local/bin/python*-config \
        /usr/local/include \
        /usr/local/lib/pkgconfig \
        /usr/local/lib/python3.14/config-* \
        /usr/local/lib/python3.14/ensurepip \
        /usr/local/lib/python3.14/idlelib \
        /usr/local/lib/python3.14/site-packages \
        /usr/local/lib/python3.14/tkinter \
        /usr/local/lib/python3.14/turtledemo \
        /usr/local/lib/python3.14/venv \
        /usr/local/share/man

# Flatten the prepared runtime into a clean final layer so removed Python
# package-management and development files do not remain in lower image layers.
FROM scratch
COPY --from=runtime-root / /

ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

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
# Application code is immutable at runtime and does not need write permission.
COPY --chown=0:0 --chmod=0444 *.py /app/
COPY --chown=0:0 --chmod=0444 templates/*.html /app/templates/
COPY --chown=0:0 --chmod=0555 docker-entrypoint.sh /usr/local/bin/

USER appuser:appgroup

EXPOSE 8080

# Probe the HTTP liveness route so a hung server is detected, not just a live process.
HEALTHCHECK --interval=60s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -q -O - "http://127.0.0.1:${LISTEN_PORT}/healthz" || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["python3", "/app/app.py"]
