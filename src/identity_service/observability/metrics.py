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
            "Current PostgreSQL, migration, and JWKS readiness state",
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
        self.jwt_validation = Counter(
            "identity_service_jwt_validation_total",
            "Access-token validation outcomes",
            ("outcome",),
            registry=self.registry,
        )
        self.jwks_fetch = Counter(
            "identity_service_jwks_fetch_total",
            "JWKS fetch outcomes",
            ("outcome",),
            registry=self.registry,
        )
        self.jwks_cache_age = Gauge(
            "identity_service_jwks_cache_age_seconds",
            "Monotonic age of the active JWKS snapshot",
            registry=self.registry,
        )
        self.jwks_cache_state = Gauge(
            "identity_service_jwks_cache_state",
            "One-hot bounded JWKS cache state",
            ("state",),
            registry=self.registry,
        )
        self.userinfo_requests = Counter(
            "identity_service_userinfo_requests_total",
            "Cognito UserInfo request outcomes",
            ("outcome",),
            registry=self.registry,
        )
        for state in ("fresh", "degraded", "unavailable"):
            self.jwks_cache_state.labels(state).set(0)

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

    def record_jwt_validation(self, outcome: str) -> None:
        allowed = {
            "valid",
            "malformed",
            "bad_signature",
            "wrong_issuer",
            "wrong_audience",
            "wrong_client",
            "wrong_token_use",
            "expired",
            "not_yet_valid",
            "insufficient_scope",
            "unknown_key",
            "dependency_unavailable",
        }
        if outcome not in allowed:
            raise ValueError("unbounded JWT metric outcome")
        self.jwt_validation.labels(outcome).inc()

    def record_jwks_fetch(self, outcome: str) -> None:
        if outcome not in {"success", "timeout", "network_error", "oversized", "malformed"}:
            raise ValueError("unbounded JWKS metric outcome")
        self.jwks_fetch.labels(outcome).inc()

    def set_jwks_cache(self, state: str, age_seconds: float) -> None:
        states = ("fresh", "degraded", "unavailable")
        if state not in states:
            raise ValueError("unbounded JWKS cache state")
        self.jwks_cache_age.set(max(0.0, age_seconds))
        for candidate in states:
            self.jwks_cache_state.labels(candidate).set(1 if candidate == state else 0)

    def record_userinfo_request(self, outcome: str) -> None:
        if outcome not in {
            "success",
            "token_rejected",
            "rate_limited",
            "server_error",
            "timeout",
            "network_error",
            "malformed",
        }:
            raise ValueError("unbounded UserInfo metric outcome")
        self.userinfo_requests.labels(outcome).inc()

    def render(self, engine: Engine) -> bytes:
        checked_out = getattr(engine.pool, "checkedout", None)
        size = getattr(engine.pool, "size", None)
        if callable(checked_out):
            self.pool_checked_out.set(checked_out())
        if callable(size):
            self.pool_size.set(size())
        return generate_latest(self.registry)
