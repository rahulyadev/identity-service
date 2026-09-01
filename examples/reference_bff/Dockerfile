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
