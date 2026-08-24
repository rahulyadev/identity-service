from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from identity_service.config import AppEnvironment, Settings

DEPLOYED = (
    AppEnvironment.DEVELOPMENT,
    AppEnvironment.STAGING,
    AppEnvironment.PRODUCTION,
)
ISSUER = "https://cognito-idp.us-test-1.amazonaws.com/us-test-1_TestPool"
JWKS = ISSUER + "/.well-known/jwks.json"
USERINFO = "https://auth.example.invalid/oauth2/userInfo"


def _deployed(environment: AppEnvironment) -> dict[str, object]:
    return {
        "app_env": environment,
        "identity_origin": "https://identity.invalid",
        "allowed_hosts": ["identity.invalid"],
        "enable_interactive_docs": False,
        "log_format": "json",
        "database_url": "postgresql+psycopg://db.invalid/identity?sslmode=verify-full",
        "cognito_issuer": ISSUER,
        "cognito_jwks_url": JWKS,
        "cognito_userinfo_url": USERINFO,
        "cognito_allowed_client_ids": ["client-one", "client-two"],
    }


@pytest.mark.parametrize("environment", DEPLOYED)
def test_deployed_cognito_contract_accepts_exact_https_endpoints(
    settings_factory: Callable[..., Settings], environment: AppEnvironment
) -> None:
    settings = settings_factory(**_deployed(environment))
    assert settings.cognito_issuer == ISSUER
    assert settings.cognito_jwks_url == JWKS
    assert settings.cognito_userinfo_url == USERINFO


def test_test_environment_explicitly_accepts_http_fixture(
    settings_factory: Callable[..., Settings], fake_cognito: object
) -> None:
    overrides = fake_cognito.settings_overrides()  # type: ignore[attr-defined]
    settings = settings_factory(**overrides)
    assert settings.relaxed_local_environment
    assert settings.cognito_issuer.startswith("http://")


@pytest.mark.parametrize("environment", DEPLOYED)
@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("cognito_issuer", "http://cognito.test/test-pool", "HTTPS"),
        (
            "cognito_jwks_url",
            "http://cognito.test/test-pool/.well-known/jwks.json",
            "JWKS",
        ),
        ("cognito_userinfo_url", "http://auth.test/oauth2/userInfo", "HTTPS"),
        (
            "cognito_issuer",
            "https://user:credential@cognito-idp.us-test-1.amazonaws.com/us-test-1_TestPool",  # pragma: allowlist secret (synthetic rejection fixture)  # noqa: E501
            "COGNITO_ISSUER",
        ),
        ("cognito_userinfo_url", "https://auth.invalid/oauth2/userInfo?x=1", "USERINFO"),
        ("cognito_userinfo_url", "https://auth.invalid/oauth2/userInfo#x", "USERINFO"),
        ("cognito_userinfo_url", "https://127.0.0.1/oauth2/userInfo", "loopback"),
        ("cognito_userinfo_url", "https://localhost/oauth2/userInfo", "loopback"),
        ("cognito_issuer", "https://issuer.invalid/us-test-1_TestPool", "regional"),
        (
            "cognito_issuer",
            "https://cognito-idp.us-test-1.amazonaws.com/not-a-pool",
            "User Pool",
        ),
    ],
)
def test_deployed_cognito_rejects_unsafe_endpoint_forms(
    settings_factory: Callable[..., Settings],
    environment: AppEnvironment,
    field: str,
    value: str,
    reason: str,
) -> None:
    values = _deployed(environment)
    values[field] = value
    if field == "cognito_issuer":
        values["cognito_jwks_url"] = value.rstrip("/") + "/.well-known/jwks.json"
    with pytest.raises(ValidationError) as captured:
        settings_factory(**values)
    assert reason.casefold() in str(captured.value).casefold()


@pytest.mark.parametrize(
    "overrides",
    [
        {"cognito_jwks_url": ISSUER + "/wrong"},
        {"cognito_userinfo_url": "https://auth.example.invalid/userInfo"},
        {"cognito_allowed_client_ids": []},
        {"cognito_allowed_client_ids": ["duplicate", "duplicate"]},
        {"cognito_allowed_client_ids": ["contains whitespace"]},
        {"cognito_allowed_client_ids": ["x" * 257]},
        {"oauth_resource": ""},
        {"oauth_profile_read_scope": "contains whitespace"},
        {"oauth_profile_read_scope": "identity-service://api"},
        {"oauth_profile_write_scope": "identity-service://api/profile.read"},
        {"jwks_stale_if_error_seconds": 299, "jwks_cache_max_age_seconds": 300},
    ],
)
def test_cognito_configuration_rejects_ambiguous_values(
    settings_factory: Callable[..., Settings], overrides: dict[str, object]
) -> None:
    with pytest.raises(ValidationError):
        settings_factory(**overrides)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("jwt_clock_skew_seconds", 301),
        ("jwt_max_token_bytes", 255),
        ("jwks_cache_max_age_seconds", 0),
        ("jwks_stale_if_error_seconds", 86_401),
        ("jwks_refresh_min_interval_seconds", 0),
        ("jwks_negative_kid_cache_seconds", 301),
        ("jwks_max_keys", 65),
        ("upstream_connect_timeout_seconds", 0),
        ("upstream_read_timeout_seconds", 31),
        ("upstream_write_timeout_seconds", 31),
        ("upstream_pool_timeout_seconds", 0),
        ("upstream_max_response_bytes", 1023),
        ("upstream_max_response_bytes", 1024 * 1024 + 1),
    ],
)
def test_security_limits_are_bounded(
    settings_factory: Callable[..., Settings], field: str, value: int
) -> None:
    with pytest.raises(ValidationError):
        settings_factory(**{field: value})


def test_provider_configuration_is_not_rendered_in_settings_repr(
    settings_factory: Callable[..., Settings],
) -> None:
    sentinel = "configuration-redaction-sentinel"
    settings = settings_factory(
        cognito_allowed_client_ids=[sentinel],
        cognito_userinfo_url=f"https://{sentinel}.invalid/oauth2/userInfo",
    )
    rendered = repr(settings)
    assert sentinel not in rendered
    assert "cognito_userinfo_url" not in settings.safe_summary()


def test_invalid_provider_url_input_is_hidden(settings_factory: Callable[..., Settings]) -> None:
    sentinel = "provider-url-redaction-sentinel"
    with pytest.raises(ValidationError) as captured:
        settings_factory(cognito_userinfo_url=f"https://user:{sentinel}@auth.invalid/path")
    assert sentinel not in str(captured.value)
