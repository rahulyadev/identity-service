from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from reference_bff.config import BffEnvironment, Settings


@pytest.fixture
def bff_settings_factory() -> Callable[..., Settings]:
    def factory(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "app_env": BffEnvironment.TEST,
            "service_version": "0.1.0",
            "port": 8081,
            "bff_origin": "http://localhost:8081",
            "allowed_hosts": ["localhost", "testserver", "127.0.0.1"],
            "trusted_proxy_networks": [],
            "log_level": "INFO",
            "log_format": "console",
            "enable_interactive_docs": False,
            "authorization_endpoint": "http://127.0.0.1:9000/oauth2/authorize",
            "client_id": "synthetic-reference-client",
            "client_secret": "synthetic-reference-secret",  # pragma: allowlist secret
            "requested_scopes": [
                "openid",
                "identity-service://api/profile.read",
                "identity-service://api/profile.write",
            ],
            "redis_url": "redis://127.0.0.1:56379/15",
            "redis_key_namespace": "reference-bff:test:pytest",
            "oauth_transaction_ttl_seconds": 300,
            "redis_connect_timeout_seconds": 1,
            "redis_operation_timeout_seconds": 1,
        }
        values.update(overrides)
        return Settings(**values)

    return factory
