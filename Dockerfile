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
