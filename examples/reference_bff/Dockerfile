FROM python:3.14.7-slim-bookworm@sha256:416f0db2a2b561945630cef9877a7ea0581b27449eb9fd9df42f03e1b74b5b63 AS runtime-dependencies

ENV VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN python -m venv "$VIRTUAL_ENV"
COPY examples/reference_bff/requirements.lock /tmp/requirements.lock
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

RUN groupadd --gid 10002 reference-bff \
    && useradd --uid 10002 --gid reference-bff --no-create-home --shell /usr/sbin/nologin reference-bff \
    && rm -rf \
        /usr/local/lib/python3.14/ensurepip \
        /usr/local/lib/python3.14/site-packages/pip* \
        /usr/local/bin/pip* \
        /usr/bin/apt \
        /usr/bin/apt-* \
        /usr/lib/apt \
        /etc/apt \
        /var/cache/apt \
        /var/lib/apt \
        /usr/bin/dpkg \
        /usr/bin/dpkg-* \
        /usr/sbin/dpkg-* \
        /usr/lib/dpkg \
        /usr/share/dpkg

WORKDIR /app
COPY --from=runtime-dependencies /opt/venv /opt/venv
RUN rm -rf /opt/venv/lib/python3.14/site-packages/pip* /opt/venv/bin/pip*
COPY examples/reference_bff/src ./src
COPY examples/reference_bff/scripts/healthcheck.py ./scripts/healthcheck.py

USER 10002:10002
EXPOSE 8081
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD ["python", "scripts/healthcheck.py"]
CMD ["python", "-m", "reference_bff.server"]
