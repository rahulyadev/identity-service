from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from identity_service.config import AppEnvironment, Settings


@pytest.fixture
def settings_factory() -> Callable[..., Settings]:
    def factory(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "app_env": AppEnvironment.TEST,
            "service_version": "0.1.0",
            "identity_origin": "http://localhost:8080",
            "allowed_hosts": ["testserver", "localhost", "127.0.0.1"],
            "trusted_proxy_cidrs": [],
            "database_url": "postgresql+psycopg://app:local@127.0.0.1:1/identity_test",  # pragma: allowlist secret (synthetic test credential)  # noqa: E501
            "enable_interactive_docs": False,
            "metrics_enabled": True,
            "db_pool_timeout_seconds": 1,
            "db_connect_timeout_seconds": 1,
            "db_statement_timeout_ms": 500,
        }
        values.update(overrides)
        return Settings(**values)

    return factory
