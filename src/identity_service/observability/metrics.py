"""Prometheus metrics with a fixed, low-cardinality label set."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from sqlalchemy import Engine


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry(auto_describe=True)
        self.http_requests = Counter(
            "identity_service_http_requests_total",
            "Completed HTTP requests",
            ("method", "route", "status"),
            registry=self.registry,
        )
        self.http_duration = Histogram(
            "identity_service_http_request_duration_seconds",
            "HTTP request duration",
            ("method", "route", "status"),
            registry=self.registry,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
        )
        self.readiness = Gauge(
            "identity_service_readiness",
            "Current PostgreSQL and migration readiness state",
            registry=self.registry,
        )
        self.database_errors = Counter(
            "identity_service_database_errors_total",
            "Database errors by bounded operation",
            ("operation",),
            registry=self.registry,
        )
        self.pool_checked_out = Gauge(
            "identity_service_database_pool_checked_out",
            "Checked-out SQLAlchemy pool connections",
            registry=self.registry,
        )
        self.pool_size = Gauge(
            "identity_service_database_pool_size",
            "Configured SQLAlchemy pool size",
            registry=self.registry,
        )
        self.bootstrap_outcomes = Counter(
            "identity_service_bootstrap_outcomes_total",
            "Internal identity bootstrap outcomes",
            ("outcome",),
            registry=self.registry,
        )
        self.profile_update_outcomes = Counter(
            "identity_service_profile_update_outcomes_total",
            "Internal display-name update outcomes",
            ("outcome",),
            registry=self.registry,
        )

    def record_http(self, method: str, route: str, status: int, duration_seconds: float) -> None:
        labels = (method, route, str(status))
        self.http_requests.labels(*labels).inc()
        self.http_duration.labels(*labels).observe(duration_seconds)

    def set_readiness(self, ready: bool) -> None:
        self.readiness.set(1 if ready else 0)

    def record_database_error(self, operation: str) -> None:
        self.database_errors.labels(operation).inc()

    def record_bootstrap(self, outcome: str) -> None:
        self.bootstrap_outcomes.labels(outcome).inc()

    def record_profile_update(self, outcome: str) -> None:
        self.profile_update_outcomes.labels(outcome).inc()

    def render(self, engine: Engine) -> bytes:
        checked_out = getattr(engine.pool, "checkedout", None)
        size = getattr(engine.pool, "size", None)
        if callable(checked_out):
            self.pool_checked_out.set(checked_out())
        if callable(size):
            self.pool_size.set(size())
        return generate_latest(self.registry)
