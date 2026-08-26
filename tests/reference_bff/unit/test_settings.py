from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError
from reference_bff.config import BffEnvironment, Settings

AUTH_USER = "user"
AUTH_CREDENTIAL = "secret"
CREDENTIAL_AUTH_ENDPOINT = (
    f"https://{AUTH_USER}:{AUTH_CREDENTIAL}@auth.example.invalid/oauth2/authorize"
)


def test_settings_are_typed_derived_and_secret_safe(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    sentinel = "never-render-client-secret"  # pragma: allowlist secret
    redis_password = "never-render-redis-password"  # pragma: allowlist secret
    settings = bff_settings_factory(
        client_secret=sentinel,
        redis_url=f"redis://user:{redis_password}@127.0.0.1:56379/15",
    )

    assert settings.port == 8081
    assert settings.callback_uri == "http://localhost:8081/auth/callback"
    assert settings.managed_login_origin == "http://127.0.0.1:9000"
    assert settings.revocation_endpoint == "http://127.0.0.1:9000/oauth2/revoke"
    assert settings.logout_endpoint == "http://127.0.0.1:9000/logout"
    assert settings.signed_out_uri == "http://localhost:8081/auth/signed-out"
    assert settings.logout_redirect_uri == (
        "http://127.0.0.1:9000/logout?client_id=synthetic-reference-client&"
        "logout_uri=http%3A%2F%2Flocalhost%3A8081%2Fauth%2Fsigned-out"
    )
    assert settings.oauth_transaction_ttl_seconds == 300
    assert settings.session_refresh_window_seconds == 120
    assert settings.refresh_lock_lease_seconds == 10
    assert settings.refresh_wait_timeout_ms == 1500
    assert settings.refresh_poll_interval_ms == 25
    assert sentinel not in repr(settings)
    assert redis_password not in repr(settings)
    assert sentinel not in str(settings)
    assert redis_password not in str(settings)
    assert "client_secret" not in settings.safe_summary()
    assert "redis_url" not in settings.safe_summary()
    assert settings.safe_summary()["signed_out_uri"] == settings.signed_out_uri
    assert settings.client_id not in str(settings.safe_summary())


def test_valid_deployed_settings_require_secure_explicit_boundaries(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory(
        app_env=BffEnvironment.PRODUCTION,
        bff_origin="https://bff.example.invalid",
        allowed_hosts=["bff.example.invalid"],
        trusted_proxy_networks=["10.0.0.0/24"],
        log_format="json",
        enable_interactive_docs=False,
        authorization_endpoint="https://auth.example.invalid/oauth2/authorize",
        token_endpoint="https://auth.example.invalid/oauth2/token",
        cognito_issuer="https://cognito-idp.ap-south-1.amazonaws.com/ap-south-1_testpool",
        cognito_jwks_url=(
            "https://cognito-idp.ap-south-1.amazonaws.com/ap-south-1_testpool/.well-known/jwks.json"
        ),
        identity_api_origin="https://identity.example.invalid",
        redis_url="rediss://cache.example.invalid:6380/0",
        redis_key_namespace="reference-bff:production:oauth",
    )

    assert settings.app_env.deployed
    assert settings.callback_uri == "https://bff.example.invalid/auth/callback"
    assert settings.enable_interactive_docs is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"bff_origin": "http://bff.example.invalid", "allowed_hosts": ["bff.example.invalid"]},
        {"authorization_endpoint": "http://auth.example.invalid/oauth2/authorize"},
        {"redis_url": "redis://cache.example.invalid/0"},
        {"redis_url": "rediss://127.0.0.1/0"},
        {"allowed_hosts": ["*"]},
        {"trusted_proxy_networks": ["0.0.0.0/0"]},
        {"enable_interactive_docs": True},
        {"log_level": "DEBUG"},
        {"log_format": "console"},
    ],
)
def test_deployed_settings_reject_unsafe_boundaries(
    bff_settings_factory: Callable[..., Settings], overrides: dict[str, object]
) -> None:
    values: dict[str, object] = {
        "app_env": BffEnvironment.PRODUCTION,
        "bff_origin": "https://bff.example.invalid",
        "allowed_hosts": ["bff.example.invalid"],
        "log_format": "json",
        "enable_interactive_docs": False,
        "authorization_endpoint": "https://auth.example.invalid/oauth2/authorize",
        "token_endpoint": "https://auth.example.invalid/oauth2/token",
        "cognito_issuer": ("https://cognito-idp.ap-south-1.amazonaws.com/ap-south-1_testpool"),
        "cognito_jwks_url": (
            "https://cognito-idp.ap-south-1.amazonaws.com/ap-south-1_testpool/.well-known/jwks.json"
        ),
        "identity_api_origin": "https://identity.example.invalid",
        "redis_url": "rediss://cache.example.invalid/0",
        "redis_key_namespace": "reference-bff:production:oauth",
    }
    values.update(overrides)
    with pytest.raises(ValidationError):
        bff_settings_factory(**values)


@pytest.mark.parametrize(
    "overrides",
    [
        {"bff_origin": "https://user:secret@bff.example.invalid"},  # pragma: allowlist secret
        {"authorization_endpoint": CREDENTIAL_AUTH_ENDPOINT},
        {"token_endpoint": "https://other.invalid/oauth2/token"},
        {"token_endpoint": "http://127.0.0.1:9000/not-token"},
        {"cognito_jwks_url": "http://127.0.0.1:9000/other/.well-known/jwks.json"},
        {"identity_api_origin": "http://127.0.0.1:9001/path"},
        {"oauth_resource": "other://resource"},
        {"authorization_endpoint": "https://auth.example.invalid/oauth2/authorize#fragment"},
        {"bff_origin": "http://example.invalid", "allowed_hosts": ["example.invalid"]},
        {"authorization_endpoint": "http://example.invalid/oauth2/authorize"},
        {"redis_url": "redis://127.0.0.1/16"},
        {"redis_key_namespace": "wrong:test:oauth"},
        {"oauth_transaction_ttl_seconds": 601},
        {"requested_scopes": ["openid", "identity-service://api/profile.read"]},
        {
            "requested_scopes": [
                "openid",
                "identity-service://api/profile.read",
                "identity-service://api/profile.write",
                "wildcard:*",
            ]
        },
        {
            "requested_scopes": [
                "openid",
                "openid",
                "identity-service://api/profile.read",
                "identity-service://api/profile.write",
            ]
        },
    ],
)
def test_settings_reject_invalid_local_and_oauth_values(
    bff_settings_factory: Callable[..., Settings], overrides: dict[str, object]
) -> None:
    with pytest.raises(ValidationError):
        bff_settings_factory(**overrides)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("port", " 8081"),
        ("enable_interactive_docs", "TRUE"),
        ("oauth_transaction_ttl_seconds", True),
        ("redis_connect_timeout_seconds", "2.0"),
    ],
)
def test_settings_reject_permissive_scalar_coercion(
    bff_settings_factory: Callable[..., Settings], field: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        bff_settings_factory(**{field: value})


def test_strict_scalar_string_forms_are_accepted(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory(port="8081", enable_interactive_docs="false")
    assert settings.port == 8081
    assert settings.enable_interactive_docs is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"service_version": "contains whitespace"},
        {"allowed_hosts": ["localhost", "localhost"]},
        {"allowed_hosts": ["localhost", "bad..host"]},
        {"allowed_hosts": ["localhost", "nonascii-é.invalid"]},
        {"trusted_proxy_networks": ["10.0.0.0/24", "10.0.0.0/24"]},
        {"client_id": "invalid client"},
        {"client_secret": "short"},  # pragma: allowlist secret
        {"bff_origin": "http://localhost:8081/path"},
        {"bff_origin": "http://localhost:99999"},
        {"authorization_endpoint": "http://127.0.0.1:9000"},
        {"authorization_endpoint": " http://127.0.0.1:9000/oauth2/authorize"},
        {"redis_url": "redis://127.0.0.1:99999/0"},
        {"redis_url": " redis://127.0.0.1/0"},
        {"bff_origin": "http://127.0.0.1:8081", "allowed_hosts": ["localhost"]},
        {"jwks_cache_max_age_seconds": 301, "jwks_stale_if_error_seconds": 300},
        {"session_idle_seconds": 7200, "session_absolute_seconds": 3600},
        {"session_idle_seconds": 300, "session_refresh_window_seconds": 300},
        {"refresh_wait_timeout_ms": 100, "refresh_poll_interval_ms": 100},
        {"refresh_lock_lease_seconds": 3, "refresh_wait_timeout_ms": 3000},
    ],
)
def test_additional_strict_configuration_branches_reject(
    bff_settings_factory: Callable[..., Settings], overrides: dict[str, object]
) -> None:
    with pytest.raises(ValidationError):
        bff_settings_factory(**overrides)


def test_invalid_environment_input_is_hidden_during_startup() -> None:
    sentinel = "startup-secret-sentinel"  # pragma: allowlist secret
    environment = os.environ.copy()
    environment.update(
        {
            "APP_ENV": "test",
            "BFF_ORIGIN": "http://localhost:8081",
            "ALLOWED_HOSTS": '["localhost"]',
            "AUTHORIZATION_ENDPOINT": "http://127.0.0.1:9000/oauth2/authorize",
            "TOKEN_ENDPOINT": "http://127.0.0.1:9000/oauth2/token",
            "COGNITO_ISSUER": "http://127.0.0.1:9000/test-pool",
            "COGNITO_JWKS_URL": ("http://127.0.0.1:9000/test-pool/.well-known/jwks.json"),
            "IDENTITY_API_ORIGIN": "http://127.0.0.1:9001",
            "BFF_CLIENT_ID": "synthetic-reference-client",
            "BFF_CLIENT_SECRET": sentinel,
            "REDIS_URL": f"redis://user:{sentinel}@127.0.0.1:56379/15",
            "REDIS_KEY_NAMESPACE": "invalid namespace",
            "ENABLE_INTERACTIVE_DOCS": "false",
        }
    )
    result = subprocess.run(
        [sys.executable, "-m", "reference_bff.server"],
        cwd=Path(__file__).resolve().parents[3],
        check=False,
        capture_output=True,
        env=environment,
        shell=False,
        text=True,
        timeout=5,
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert sentinel not in output
    assert "REDIS_KEY_NAMESPACE" in output
