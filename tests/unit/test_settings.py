from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

from identity_service.config import AppEnvironment, Settings

ENVIRONMENT_KEYS = (
    "APP_ENV",
    "SERVICE_VERSION",
    "PORT",
    "IDENTITY_ORIGIN",
    "ALLOWED_HOSTS",
    "TRUSTED_PROXY_CIDRS",
    "MAX_REQUEST_BODY_BYTES",
    "LOG_LEVEL",
    "LOG_FORMAT",
    "METRICS_ENABLED",
    "DATABASE_URL",
    "DB_POOL_SIZE",
    "DB_MAX_OVERFLOW",
    "DB_POOL_TIMEOUT_SECONDS",
    "DB_POOL_RECYCLE_SECONDS",
    "DB_STATEMENT_TIMEOUT_MS",
    "DB_CONNECT_TIMEOUT_SECONDS",
    "GRACEFUL_SHUTDOWN_SECONDS",
    "ENABLE_INTERACTIVE_DOCS",
)
DEPLOYED_ENVIRONMENTS = (
    AppEnvironment.DEVELOPMENT,
    AppEnvironment.STAGING,
    AppEnvironment.PRODUCTION,
)


def _deployed_values(environment: AppEnvironment, database_url: str) -> dict[str, object]:
    return {
        "app_env": environment,
        "identity_origin": "https://identity.invalid",
        "allowed_hosts": ["identity.invalid"],
        "enable_interactive_docs": False,
        "log_level": "INFO",
        "log_format": "json",
        "database_url": database_url,
    }


def test_settings_parse_documented_environment_encoding(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ENVIRONMENT_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("PORT", "8080")
    monkeypatch.setenv("ALLOWED_HOSTS", '["localhost","testserver"]')
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", '["127.0.0.0/8","2001:db8::/32"]')
    monkeypatch.setenv("METRICS_ENABLED", "false")
    monkeypatch.setenv("ENABLE_INTERACTIVE_DOCS", "true")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://app:local@localhost/identity")  # fmt: skip  # pragma: allowlist secret (synthetic test credential)  # noqa: E501

    settings = Settings()  # type: ignore[call-arg]

    assert settings.port == 8080
    assert settings.allowed_hosts == ["localhost", "testserver"]
    assert [str(network) for network in settings.trusted_proxy_cidrs] == [
        "127.0.0.0/8",
        "2001:db8::/32",
    ]
    assert settings.metrics_enabled is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("metrics_enabled", "yes"),
        ("enable_interactive_docs", "TRUE"),
        ("port", " 8080"),
        ("db_pool_size", True),
    ],
)
def test_settings_reject_permissive_scalar_coercion(
    settings_factory: Callable[..., Settings], field: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        settings_factory(**{field: value})


def test_database_url_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ENVIRONMENT_KEYS:
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(ValidationError):
        Settings()  # type: ignore[call-arg]


@pytest.mark.parametrize("service_version", ["", "x" * 65, "contains whitespace"])
def test_service_version_is_a_bounded_release_identifier(
    settings_factory: Callable[..., Settings], service_version: str
) -> None:
    with pytest.raises(ValidationError):
        settings_factory(service_version=service_version)


def test_malformed_database_url_is_rejected_without_parser_detail(
    settings_factory: Callable[..., Settings],
) -> None:
    with pytest.raises(ValidationError) as captured:
        settings_factory(database_url="://")
    assert "must be a valid SQLAlchemy URL" in str(captured.value)


def test_database_url_is_redacted_in_representations(
    settings_factory: Callable[..., Settings],
) -> None:
    secret = (
        "do-not-render-this-password"  # pragma: allowlist secret (synthetic redaction sentinel)
    )
    settings = settings_factory(
        database_url=f"postgresql+psycopg://app:{secret}@localhost/identity"
    )
    assert secret not in repr(settings)
    assert secret not in str(settings)
    assert "database_url" not in settings.safe_summary()


@pytest.mark.parametrize(
    "case",
    [
        "credential_origin",
        "origin_path_query",
        "credential_database_url",
        "list_value",
    ],
)
def test_invalid_configuration_representations_hide_input_values(
    settings_factory: Callable[..., Settings], case: str
) -> None:
    sentinel = f"validation-input-redaction-{case}"
    overrides: dict[str, object]
    if case == "credential_origin":
        overrides = {
            "identity_origin": f"https://user:{sentinel}@identity.invalid",
            "allowed_hosts": ["identity.invalid"],
        }
    elif case == "origin_path_query":
        overrides = {
            "identity_origin": f"https://identity.invalid/path?value={sentinel}",
            "allowed_hosts": ["identity.invalid"],
        }
    elif case == "credential_database_url":
        overrides = {
            "database_url": f"mysql://user:{sentinel}@identity.invalid/identity",
        }
    else:
        overrides = {"allowed_hosts": ["localhost", f"invalid {sentinel}"]}

    with pytest.raises(ValidationError) as captured:
        settings_factory(**overrides)

    assert sentinel not in str(captured.value)
    assert sentinel not in repr(captured.value)


@pytest.mark.parametrize(
    ("case", "expected_field"),
    [
        ("credential_origin", "IDENTITY_ORIGIN"),
        ("origin_path_query", "IDENTITY_ORIGIN"),
        ("credential_database_url", "DATABASE_URL"),
        ("list_value", "ALLOWED_HOSTS"),
    ],
)
def test_process_startup_errors_hide_invalid_environment_values(
    case: str, expected_field: str
) -> None:
    sentinel = f"startup-input-redaction-{case}"
    environment = os.environ.copy()
    for key in ENVIRONMENT_KEYS:
        environment.pop(key, None)
    environment.update(
        {
            "APP_ENV": "test",
            "IDENTITY_ORIGIN": "http://localhost:8080",
            "ALLOWED_HOSTS": '["localhost"]',
            "DATABASE_URL": "postgresql+psycopg://app:local@localhost/identity",  # pragma: allowlist secret (synthetic subprocess credential)  # noqa: E501
            "ENABLE_INTERACTIVE_DOCS": "false",
        }
    )
    if case == "credential_origin":
        environment["IDENTITY_ORIGIN"] = f"https://user:{sentinel}@identity.invalid"
        environment["ALLOWED_HOSTS"] = '["identity.invalid"]'
    elif case == "origin_path_query":
        environment["IDENTITY_ORIGIN"] = f"https://identity.invalid/path?value={sentinel}"
        environment["ALLOWED_HOSTS"] = '["identity.invalid"]'
    elif case == "credential_database_url":
        environment["DATABASE_URL"] = f"mysql://user:{sentinel}@identity.invalid/identity"
    else:
        environment["ALLOWED_HOSTS"] = f'["localhost","invalid {sentinel}"]'

    result = subprocess.run(
        [sys.executable, "-m", "identity_service.server"],
        cwd=Path(__file__).resolve().parents[2],
        check=False,
        capture_output=True,
        env=environment,
        shell=False,
        text=True,
        timeout=5,
    )
    startup_output = result.stdout + result.stderr
    assert result.returncode != 0
    assert sentinel not in startup_output
    assert expected_field in startup_output


@pytest.mark.parametrize(
    "overrides",
    [
        {"identity_origin": "http://identity.invalid"},
        {"enable_interactive_docs": True},
        {"log_level": "DEBUG"},
        {"log_format": "console"},
        {
            "database_url": "postgresql+psycopg://app:local@db/identity?sslmode=require",  # pragma: allowlist secret (synthetic test credential)  # noqa: E501
        },
    ],
)
@pytest.mark.parametrize(
    "environment",
    DEPLOYED_ENVIRONMENTS,
)
def test_every_deployed_environment_rejects_unsafe_boundary(
    settings_factory: Callable[..., Settings],
    overrides: dict[str, object],
    environment: AppEnvironment,
) -> None:
    deployed: dict[str, object] = {
        "app_env": environment,
        "identity_origin": "https://identity.invalid",
        "allowed_hosts": ["identity.invalid"],
        "enable_interactive_docs": False,
        "log_level": "INFO",
        "log_format": "json",
        "database_url": (
            "postgresql+psycopg://app:local@db/identity?sslmode=verify-full&sslrootcert=system"  # pragma: allowlist secret (synthetic test credential)  # noqa: E501
        ),
    }
    deployed.update(overrides)
    with pytest.raises(ValidationError):
        settings_factory(**deployed)


@pytest.mark.parametrize(
    "environment",
    DEPLOYED_ENVIRONMENTS,
)
def test_deployed_configuration_accepts_verified_tls(
    settings_factory: Callable[..., Settings], environment: AppEnvironment
) -> None:
    settings = settings_factory(
        app_env=environment,
        identity_origin="https://identity.invalid",
        allowed_hosts=["identity.invalid"],
        enable_interactive_docs=False,
        log_format="json",
        database_url=(
            "postgresql+psycopg://app:local@db/identity?sslmode=verify-full&sslrootcert=system"  # pragma: allowlist secret (synthetic test credential)  # noqa: E501
        ),
    )
    assert settings.deployed_environment
    assert not settings.relaxed_local_environment


@pytest.mark.parametrize(
    ("category", "database_url"),
    [
        ("missing_authority_host", "postgresql+psycopg:///identity?sslmode=verify-full"),
        (
            "unix_socket_query_host",
            "postgresql+psycopg://user:synthetic@/identity"  # pragma: allowlist secret (synthetic rejection fixture)  # noqa: E501
            "?host=/var/run/postgresql&sslmode=verify-full",
        ),
        (
            "percent_encoded_unix_socket_host",
            "postgresql+psycopg://%2Fvar%2Frun%2Fpostgresql/identity?sslmode=verify-full",
        ),
        (
            "query_host_override",
            "postgresql+psycopg://db.invalid/identity?host=other.invalid&sslmode=verify-full",
        ),
        (
            "query_hostaddr_override",
            "postgresql+psycopg://db.invalid/identity?hostaddr=192.0.2.10&sslmode=verify-full",
        ),
        (
            "query_port_override",
            "postgresql+psycopg://db.invalid/identity?port=5432&sslmode=verify-full",
        ),
        (
            "service_routing",
            "postgresql+psycopg://db.invalid/identity?service=production&sslmode=verify-full",
        ),
        (
            "servicefile_routing",
            "postgresql+psycopg://db.invalid/identity?servicefile=/tmp/service&sslmode=verify-full",
        ),
        ("missing_sslmode", "postgresql+psycopg://db.invalid/identity"),
        (
            "duplicate_sslmode",
            "postgresql+psycopg://db.invalid/identity?sslmode=verify-full&sslmode=verify-full",
        ),
        (
            "weaker_sslmode",
            "postgresql+psycopg://db.invalid/identity?sslmode=require",
        ),
        (
            "invalid_zero_port",
            "postgresql+psycopg://db.invalid:0/identity?sslmode=verify-full",
        ),
        (
            "invalid_high_port",
            "postgresql+psycopg://db.invalid:65536/identity?sslmode=verify-full",
        ),
        (
            "empty_database",
            "postgresql+psycopg://db.invalid/?sslmode=verify-full",
        ),
        (
            "multiple_authority_hosts",
            "postgresql+psycopg://db1.invalid,db2.invalid/identity?sslmode=verify-full",
        ),
    ],
)
@pytest.mark.parametrize("environment", DEPLOYED_ENVIRONMENTS)
def test_every_deployed_environment_rejects_ambiguous_database_destination(
    settings_factory: Callable[..., Settings],
    category: str,
    database_url: str,
    environment: AppEnvironment,
) -> None:
    del category
    with pytest.raises(ValidationError) as captured:
        settings_factory(**_deployed_values(environment, database_url))
    rendered = str(captured.value)
    assert "DATABASE_URL" in rendered
    assert database_url not in rendered


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql+psycopg://db.example.invalid/identity?sslmode=verify-full",
        "postgresql+psycopg://192.0.2.10/identity?sslmode=verify-full",
        "postgresql+psycopg://[2001:db8::10]/identity?sslmode=verify-full",
        "postgresql+psycopg://db.example.invalid:5432/identity?sslmode=verify-full",
        "postgresql+psycopg://db.example.invalid/identity"
        "?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca-certificates.crt",
    ],
)
@pytest.mark.parametrize("environment", DEPLOYED_ENVIRONMENTS)
def test_deployed_database_accepts_one_explicit_tcp_destination(
    settings_factory: Callable[..., Settings],
    database_url: str,
    environment: AppEnvironment,
) -> None:
    settings = settings_factory(**_deployed_values(environment, database_url))
    assert settings.deployed_environment


@pytest.mark.parametrize("environment", [AppEnvironment.LOCAL, AppEnvironment.TEST])
@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql+psycopg:///identity_local",
        "postgresql+psycopg:///identity_local?host=/var/run/postgresql",
    ],
)
def test_local_and_test_may_deliberately_use_unix_domain_sockets(
    settings_factory: Callable[..., Settings],
    database_url: str,
    environment: AppEnvironment,
) -> None:
    settings = settings_factory(app_env=environment, database_url=database_url)
    assert settings.relaxed_local_environment


@pytest.mark.parametrize("category", ["hostless", "unix_socket_override"])
def test_deployed_process_startup_rejects_non_tcp_database_urls_without_disclosure(
    category: str,
) -> None:
    sentinel = "deployed-database-startup-sentinel"
    username_marker = "synthetic_database_username"
    socket_marker = "synthetic_socket_path"
    environment = os.environ.copy()
    for key in ENVIRONMENT_KEYS:
        environment.pop(key, None)
    environment.update(
        {
            "APP_ENV": "development",
            "IDENTITY_ORIGIN": "https://identity.invalid",
            "ALLOWED_HOSTS": '["identity.invalid"]',
            "DATABASE_URL": "postgresql+psycopg:///identity?sslmode=verify-full",
            "ENABLE_INTERACTIVE_DOCS": "false",
            "LOG_LEVEL": "INFO",
            "LOG_FORMAT": "json",
        }
    )
    if category == "unix_socket_override":
        environment["DATABASE_URL"] = (
            f"postgresql+psycopg://{username_marker}:{sentinel}@/identity"
            f"?host=%2Ftmp%2F{socket_marker}&sslmode=verify-full"
        )
    rejected_url = environment["DATABASE_URL"]

    result = subprocess.run(
        [sys.executable, "-m", "identity_service.server"],
        cwd=Path(__file__).resolve().parents[2],
        check=False,
        capture_output=True,
        env=environment,
        shell=False,
        text=True,
        timeout=5,
    )
    startup_output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "DATABASE_URL" in startup_output
    assert rejected_url not in startup_output
    for prohibited in (sentinel, username_marker, socket_marker, "/tmp/"):
        assert prohibited not in startup_output


@pytest.mark.parametrize("hosts", [[], ["*"], ["example.com", "EXAMPLE.COM"], ["host:8080"]])
def test_allowed_hosts_are_nonempty_explicit_and_unique(
    settings_factory: Callable[..., Settings], hosts: list[str]
) -> None:
    with pytest.raises(ValidationError):
        settings_factory(allowed_hosts=hosts)


def test_database_driver_must_be_synchronous_psycopg(
    settings_factory: Callable[..., Settings],
) -> None:
    with pytest.raises(ValidationError):
        settings_factory(database_url="sqlite:///identity.db")


def test_valid_local_origin_contains_only_scheme_host_and_port(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(
        identity_origin="http://localhost:9000",
        allowed_hosts=["localhost"],
    )
    assert settings.identity_origin.host == "localhost"
    assert settings.identity_origin.port == 9000
    assert settings.relaxed_local_environment


def test_valid_deployed_https_origin_matches_explicit_host(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(
        app_env=AppEnvironment.DEVELOPMENT,
        identity_origin="https://identity.example.invalid:8443",
        allowed_hosts=["identity.example.invalid"],
        enable_interactive_docs=False,
        log_format="json",
        database_url=(
            "postgresql+psycopg://app:local@db/identity?sslmode=verify-full"  # pragma: allowlist secret (synthetic test credential)  # noqa: E501
        ),
    )
    assert settings.identity_origin.port == 8443


@pytest.mark.parametrize(
    "origin",
    [
        "https://user@identity.invalid",
        "https://user:password@identity.invalid",  # pragma: allowlist secret (synthetic URL)
        "https://identity.invalid/path",
        "https://identity.invalid?query=value",
        "https://identity.invalid#fragment",
        "http:///missing-host",
        "ftp://identity.invalid",
        "https://identity.invalid\\@attacker.invalid",
    ],
)
def test_origin_rejects_non_origin_or_ambiguous_structure(
    settings_factory: Callable[..., Settings], origin: str
) -> None:
    with pytest.raises(ValidationError):
        settings_factory(identity_origin=origin, allowed_hosts=["identity.invalid"])


def test_origin_host_must_be_allowed(settings_factory: Callable[..., Settings]) -> None:
    with pytest.raises(ValidationError, match="must be accepted by ALLOWED_HOSTS"):
        settings_factory(
            identity_origin="http://canonical.invalid",
            allowed_hosts=["different.invalid"],
        )


def test_origin_host_matches_wildcard_subdomain_only(
    settings_factory: Callable[..., Settings],
) -> None:
    matched = settings_factory(
        identity_origin="http://api.example.invalid",
        allowed_hosts=["*.example.invalid"],
    )
    assert matched.allowed_hosts == ["*.example.invalid"]
    with pytest.raises(ValidationError):
        settings_factory(
            identity_origin="http://example.invalid",
            allowed_hosts=["*.example.invalid"],
        )


@pytest.mark.parametrize("network", ["0.0.0.0/0", "::/0"])
@pytest.mark.parametrize(
    "environment",
    DEPLOYED_ENVIRONMENTS,
)
def test_deployed_environment_rejects_trust_all_proxy_networks(
    settings_factory: Callable[..., Settings], network: str, environment: AppEnvironment
) -> None:
    with pytest.raises(ValidationError):
        settings_factory(
            app_env=environment,
            identity_origin="https://identity.invalid",
            allowed_hosts=["identity.invalid"],
            trusted_proxy_cidrs=[network],
            enable_interactive_docs=False,
            log_format="json",
            database_url=(
                "postgresql+psycopg://app:local@db/identity?sslmode=verify-full"  # pragma: allowlist secret (synthetic test credential)  # noqa: E501
            ),
        )
