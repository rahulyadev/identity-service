FROM python:3.14.7-slim-bookworm@sha256:416f0db2a2b561945630cef9877a7ea0581b27449eb9fd9df42f03e1b74b5b63 AS runtime-dependencies

ENV VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN python -m venv "$VIRTUAL_ENV"
COPY requirements.lock /tmp/requirements.lock
RUN pip install --require-hashes --no-deps -r /tmp/requirements.lock

FROM python:3.14.7-slim-bookworm@sha256:416f0db2a2b561945630cef9877a7ea0581b27449eb9fd9df42f03e1b74b5b63 AS runtime

ENV VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Official Bookworm-security package; hashes bind the reviewed signed Debian metadata.
RUN set -eu; \
    test "$(dpkg-query -W -f='${Version}' libpcre2-8-0)" = '10.42-1'; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) checksum=81c5502941118a24d47af69a17b8b0b9548d75cc6d72b3eb3fe01047b46fa10e ;; \
        arm64) checksum=d178d33697eef877c2c27733141b7f8520fee66a329ae5809e8c8eae3709efa3 ;; \
        *) exit 1 ;; \
    esac; \
    python -c 'import hashlib, pathlib, sys, urllib.request; arch, expected = sys.argv[1:]; url = "https://security.debian.org/debian-security/pool/updates/main/p/pcre2/libpcre2-8-0_10.42-1+deb12u1_" + arch + ".deb"; data = urllib.request.urlopen(url, timeout=60).read(); assert hashlib.sha256(data).hexdigest() == expected; pathlib.Path("/tmp/libpcre2-8-0.deb").write_bytes(data)' "$arch" "$checksum"; \
    dpkg --install /tmp/libpcre2-8-0.deb; \
    test "$(dpkg-query -W -f='${Version}' libpcre2-8-0)" = '10.42-1+deb12u1'; \
    rm /tmp/libpcre2-8-0.deb

RUN groupadd --gid 10001 identity \
    && useradd --uid 10001 --gid identity --no-create-home --shell /usr/sbin/nologin identity \
    && rm -rf /usr/local/lib/python3.14/site-packages/pip* /usr/local/bin/pip*

WORKDIR /app
COPY --from=runtime-dependencies /opt/venv /opt/venv
RUN rm -rf /opt/venv/lib/python3.14/site-packages/pip* /opt/venv/bin/pip*
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
COPY scripts/migrate_local.py ./scripts/migrate_local.py
COPY scripts/healthcheck.py ./scripts/healthcheck.py

USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD ["python", "scripts/healthcheck.py"]
CMD ["python", "-m", "identity_service.server"]

FROM runtime-dependencies AS test

ENV PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements-dev.lock /tmp/requirements-dev.lock
RUN pip install --require-hashes --no-deps -r /tmp/requirements-dev.lock
COPY . .
CMD ["python", "-m", "pytest", "-q"]
