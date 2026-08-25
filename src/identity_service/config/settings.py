"""Strict environment-backed application settings."""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum
from typing import Annotated, Any, Literal
from urllib.parse import SplitResult, urlsplit

from pydantic import (
    AnyHttpUrl,
    BeforeValidator,
    Field,
    SecretStr,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError

from identity_service.config.hosts import host_allowed, normalize_allowed_host


class AppEnvironment(StrEnum):
    LOCAL = "local"
    TEST = "test"
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

    @property
    def deployed_environment(self) -> bool:
        return self in {self.DEVELOPMENT, self.STAGING, self.PRODUCTION}

    @property
    def relaxed_local_environment(self) -> bool:
        return self in {self.LOCAL, self.TEST}


def _strict_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError("must be the lowercase literal true or false")


def _strict_int(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value):
        return int(value)
    raise ValueError("must be an unsigned base-10 integer without whitespace")


EnvBool = Annotated[bool, BeforeValidator(_strict_bool)]
EnvInt = Annotated[int, BeforeValidator(_strict_int)]
Network = ipaddress.IPv4Network | ipaddress.IPv6Network
DATABASE_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
DATABASE_DESTINATION_QUERY_PARAMETERS = frozenset(
    {"host", "hostaddr", "port", "service", "servicefile"}
)
COGNITO_REGIONAL_HOST = re.compile(
    r"cognito-idp\.(?P<region>[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"\.amazonaws\.com(?:\.cn)?"
)
COGNITO_USER_POOL_PATH = re.compile(r"/[A-Za-z0-9-]+_[A-Za-z0-9]+")
OPAQUE_CONFIGURATION_VALUE = re.compile(r"[^\x00-\x20\x7f]{1,256}")


def _split_provider_url(value: str, field_name: str) -> SplitResult:
    if not value or any(character.isspace() for character in value) or "\\" in value:
        raise ValueError(f"{field_name} must be an unambiguous HTTP URL")
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        raise ValueError(f"{field_name} must be a valid HTTP URL") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{field_name} must be an absolute credential-free HTTP URL")
    return parsed


def _is_loopback_host(host: str) -> bool:
    if host.casefold() in {"localhost", "localhost."} or host.casefold().endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_opaque_configuration_value(value: str, field_name: str) -> str:
    if OPAQUE_CONFIGURATION_VALUE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be nonempty, bounded, and contain no whitespace")
    return value


def _is_explicit_tcp_host(host: str | None) -> bool:
    if (
        not host
        or any(character.isspace() for character in host)
        or any(marker in host for marker in ("/", "\\", "%", ",", "\x00"))
    ):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        candidate = host[:-1] if host.endswith(".") else host
        try:
            candidate = candidate.encode("idna").decode("ascii")
        except UnicodeError:
            return False
        labels = candidate.split(".")
        return (
            bool(candidate)
            and len(candidate) <= 253
            and all(DATABASE_DNS_LABEL.fullmatch(label) for label in labels)
        )
    return True


def _validate_deployed_database_destination(parsed: URL) -> None:
    if not _is_explicit_tcp_host(parsed.host):
        raise ValueError("deployed DATABASE_URL requires one explicit PostgreSQL TCP host")

    try:
        port = parsed.port
    except ValueError:
        raise ValueError("deployed DATABASE_URL contains an invalid TCP port") from None
    if port is not None and not 1 <= port <= 65_535:
        raise ValueError("deployed DATABASE_URL contains an invalid TCP port")

    query = parsed.query
    if any(key.casefold() in DATABASE_DESTINATION_QUERY_PARAMETERS for key in query):
        raise ValueError(
            "deployed DATABASE_URL cannot override its destination in query parameters"
        )

    sslmode_entries = [(key, value) for key, value in query.items() if key.casefold() == "sslmode"]
    if (
        len(sslmode_entries) != 1
        or sslmode_entries[0][0] != "sslmode"
        or not isinstance(sslmode_entries[0][1], str)
        or sslmode_entries[0][1] != "verify-full"
    ):
        raise ValueError("deployed DATABASE_URL requires exactly one sslmode=verify-full value")


class Settings(BaseSettings):
    """Validated settings loaded only from explicit environment variables."""

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=None,
        extra="forbid",
        hide_input_in_errors=True,
        populate_by_name=True,
        validate_default=True,
    )

    app_env: AppEnvironment = Field(default=AppEnvironment.LOCAL, validation_alias="APP_ENV")
    service_version: str = Field(default="0.1.0", validation_alias="SERVICE_VERSION")
    port: EnvInt = Field(default=8080, ge=1, le=65535, validation_alias="PORT")
    identity_origin: AnyHttpUrl = Field(
        default=AnyHttpUrl("http://localhost:8080"), validation_alias="IDENTITY_ORIGIN"
    )

    allowed_hosts: list[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "testserver"],
        validation_alias="ALLOWED_HOSTS",
    )
    trusted_proxy_cidrs: list[Network] = Field(
        default_factory=list, validation_alias="TRUSTED_PROXY_CIDRS"
    )
    max_request_body_bytes: EnvInt = Field(
        default=16 * 1024, ge=1, le=1024 * 1024, validation_alias="MAX_REQUEST_BODY_BYTES"
    )

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO", validation_alias="LOG_LEVEL"
    )
    log_format: Literal["json", "console"] = Field(default="console", validation_alias="LOG_FORMAT")
    metrics_enabled: EnvBool = Field(default=True, validation_alias="METRICS_ENABLED")

    cognito_issuer: str = Field(
        default="http://127.0.0.1:9000/test-pool",
        validation_alias="COGNITO_ISSUER",
        repr=False,
    )
    cognito_jwks_url: str = Field(
        default="http://127.0.0.1:9000/test-pool/.well-known/jwks.json",
        validation_alias="COGNITO_JWKS_URL",
        repr=False,
    )
    cognito_userinfo_url: str = Field(
        default="http://127.0.0.1:9000/oauth2/userInfo",
        validation_alias="COGNITO_USERINFO_URL",
        repr=False,
    )
    cognito_allowed_client_ids: list[str] = Field(
        default_factory=lambda: ["test-client"],
        validation_alias="COGNITO_ALLOWED_CLIENT_IDS",
        repr=False,
    )
    oauth_resource: str = Field(default="identity-service://api", validation_alias="OAUTH_RESOURCE")
    oauth_profile_read_scope: str = Field(
        default="identity-service://api/profile.read",
        validation_alias="OAUTH_PROFILE_READ_SCOPE",
    )
    oauth_profile_write_scope: str = Field(
        default="identity-service://api/profile.write",
        validation_alias="OAUTH_PROFILE_WRITE_SCOPE",
    )
    jwt_clock_skew_seconds: EnvInt = Field(
        default=60, ge=0, le=300, validation_alias="JWT_CLOCK_SKEW_SECONDS"
    )
    jwt_max_token_bytes: EnvInt = Field(
        default=16_384, ge=256, le=65_536, validation_alias="JWT_MAX_TOKEN_BYTES"
    )
    jwks_cache_max_age_seconds: EnvInt = Field(
        default=300, ge=1, le=86_400, validation_alias="JWKS_CACHE_MAX_AGE_SECONDS"
    )
    jwks_stale_if_error_seconds: EnvInt = Field(
        default=1800, ge=1, le=86_400, validation_alias="JWKS_STALE_IF_ERROR_SECONDS"
    )
    jwks_refresh_min_interval_seconds: EnvInt = Field(
        default=10, ge=1, le=300, validation_alias="JWKS_REFRESH_MIN_INTERVAL_SECONDS"
    )
    jwks_negative_kid_cache_seconds: EnvInt = Field(
        default=10, ge=1, le=300, validation_alias="JWKS_NEGATIVE_KID_CACHE_SECONDS"
    )
    jwks_max_keys: EnvInt = Field(default=16, ge=1, le=64, validation_alias="JWKS_MAX_KEYS")
    upstream_connect_timeout_seconds: EnvInt = Field(
        default=2, ge=1, le=30, validation_alias="UPSTREAM_CONNECT_TIMEOUT_SECONDS"
    )
    upstream_read_timeout_seconds: EnvInt = Field(
        default=3, ge=1, le=30, validation_alias="UPSTREAM_READ_TIMEOUT_SECONDS"
    )
    upstream_write_timeout_seconds: EnvInt = Field(
        default=3, ge=1, le=30, validation_alias="UPSTREAM_WRITE_TIMEOUT_SECONDS"
    )
    upstream_pool_timeout_seconds: EnvInt = Field(
        default=2, ge=1, le=30, validation_alias="UPSTREAM_POOL_TIMEOUT_SECONDS"
    )
    upstream_max_response_bytes: EnvInt = Field(
        default=65_536,
        ge=1024,
        le=1024 * 1024,
        validation_alias="UPSTREAM_MAX_RESPONSE_BYTES",
    )

    database_url: SecretStr = Field(validation_alias="DATABASE_URL", repr=True)
    db_pool_size: EnvInt = Field(default=5, ge=1, le=100, validation_alias="DB_POOL_SIZE")
    db_max_overflow: EnvInt = Field(default=10, ge=0, le=100, validation_alias="DB_MAX_OVERFLOW")
    db_pool_timeout_seconds: EnvInt = Field(
        default=5, ge=1, le=60, validation_alias="DB_POOL_TIMEOUT_SECONDS"
    )
    db_pool_recycle_seconds: EnvInt = Field(
        default=1800, ge=30, le=86_400, validation_alias="DB_POOL_RECYCLE_SECONDS"
    )
    db_statement_timeout_ms: EnvInt = Field(
        default=2000, ge=100, le=60_000, validation_alias="DB_STATEMENT_TIMEOUT_MS"
    )
    db_connect_timeout_seconds: EnvInt = Field(
        default=3, ge=1, le=30, validation_alias="DB_CONNECT_TIMEOUT_SECONDS"
    )

    graceful_shutdown_seconds: EnvInt = Field(
        default=15, ge=1, le=300, validation_alias="GRACEFUL_SHUTDOWN_SECONDS"
    )
    enable_interactive_docs: EnvBool = Field(
        default=True, validation_alias="ENABLE_INTERACTIVE_DOCS"
    )

    @field_validator("service_version")
    @classmethod
    def validate_service_version(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}", value):
            raise ValueError("must be a bounded release identifier")
        return value

    @field_validator("allowed_hosts")
    @classmethod
    def validate_allowed_hosts(cls, values: list[str]) -> list[str]:
        normalized = [normalize_allowed_host(value) for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("hosts must not contain duplicates")
        return normalized

    @field_validator("identity_origin", mode="before")
    @classmethod
    def reject_ambiguous_origin_text(cls, value: Any) -> Any:
        raw = str(value)
        if not raw or any(character.isspace() for character in raw) or "\\" in raw:
            raise ValueError("IDENTITY_ORIGIN must be an unambiguous HTTP origin")
        return value

    @field_validator("identity_origin")
    @classmethod
    def validate_identity_origin(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        if (
            value.scheme not in {"http", "https"}
            or not value.host
            or value.username is not None
            or value.password is not None
            or value.path not in {"", "/"}
            or value.query is not None
            or value.fragment is not None
        ):
            raise ValueError("IDENTITY_ORIGIN must contain only scheme, host, and optional port")
        return value

    @field_validator("trusted_proxy_cidrs", mode="before")
    @classmethod
    def parse_proxy_networks(cls, value: Any) -> Any:
        if isinstance(value, list):
            return [ipaddress.ip_network(item, strict=True) for item in value]
        return value

    @field_validator("cognito_issuer", "cognito_jwks_url", "cognito_userinfo_url")
    @classmethod
    def validate_provider_url_syntax(cls, value: str, info: ValidationInfo) -> str:
        _split_provider_url(value, (info.field_name or "provider_url").upper())
        return value

    @field_validator("cognito_allowed_client_ids")
    @classmethod
    def validate_cognito_allowed_client_ids(cls, values: list[str]) -> list[str]:
        if not 1 <= len(values) <= 16:
            raise ValueError("COGNITO_ALLOWED_CLIENT_IDS must contain between 1 and 16 values")
        normalized = [
            _validate_opaque_configuration_value(value, "COGNITO_ALLOWED_CLIENT_IDS")
            for value in values
        ]
        if len(set(normalized)) != len(normalized):
            raise ValueError("COGNITO_ALLOWED_CLIENT_IDS must not contain duplicates")
        return normalized

    @field_validator("oauth_resource", "oauth_profile_read_scope", "oauth_profile_write_scope")
    @classmethod
    def validate_oauth_value(cls, value: str, info: ValidationInfo) -> str:
        return _validate_opaque_configuration_value(
            value, (info.field_name or "oauth_value").upper()
        )

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: SecretStr, info: ValidationInfo) -> SecretStr:
        raw = value.get_secret_value()
        try:
            parsed = make_url(raw)
            _ = parsed.port
        except ArgumentError, ValueError:
            raise ValueError("DATABASE_URL must be a valid SQLAlchemy URL") from None
        if parsed.drivername != "postgresql+psycopg" or not parsed.database:
            raise ValueError("DATABASE_URL must use postgresql+psycopg and name a database")
        app_env = info.data.get("app_env", AppEnvironment.LOCAL)
        if app_env.deployed_environment:
            _validate_deployed_database_destination(parsed)
        return value

    @model_validator(mode="after")
    def validate_environment_boundary(self) -> Settings:
        if not self.allowed_hosts:
            raise ValueError("ALLOWED_HOSTS must contain at least one explicit host")
        origin_host = self.identity_origin.host
        if not host_allowed(origin_host, self.allowed_hosts):
            raise ValueError("IDENTITY_ORIGIN host must be accepted by ALLOWED_HOSTS")
        issuer = _split_provider_url(self.cognito_issuer, "COGNITO_ISSUER")
        jwks = _split_provider_url(self.cognito_jwks_url, "COGNITO_JWKS_URL")
        userinfo = _split_provider_url(self.cognito_userinfo_url, "COGNITO_USERINFO_URL")
        expected_jwks = self.cognito_issuer.rstrip("/") + "/.well-known/jwks.json"
        if self.cognito_jwks_url != expected_jwks:
            raise ValueError("COGNITO_JWKS_URL must exactly match the configured issuer JWKS path")
        if userinfo.path != "/oauth2/userInfo":
            raise ValueError("COGNITO_USERINFO_URL must use the exact /oauth2/userInfo path")
        if (
            self.oauth_resource
            in {
                self.oauth_profile_read_scope,
                self.oauth_profile_write_scope,
            }
            or self.oauth_profile_read_scope == self.oauth_profile_write_scope
        ):
            raise ValueError("OAuth resource and profile scopes must be distinct")
        required_scope_prefix = self.oauth_resource.rstrip("/") + "/"
        if not all(
            scope.startswith(required_scope_prefix)
            for scope in (self.oauth_profile_read_scope, self.oauth_profile_write_scope)
        ):
            raise ValueError("profile scopes must be namespaced beneath OAUTH_RESOURCE")
        if self.jwks_stale_if_error_seconds < self.jwks_cache_max_age_seconds:
            raise ValueError(
                "JWKS_STALE_IF_ERROR_SECONDS must be at least JWKS_CACHE_MAX_AGE_SECONDS"
            )
        if self.app_env.deployed_environment:
            if self.identity_origin.scheme != "https":
                raise ValueError("deployed IDENTITY_ORIGIN must use HTTPS")
            if self.enable_interactive_docs:
                raise ValueError(
                    "interactive API documentation must be disabled in deployed environments"
                )
            if self.log_level == "DEBUG":
                raise ValueError("debug logging is forbidden in deployed environments")
            if self.log_format != "json":
                raise ValueError("JSON logging is required in deployed environments")
            if any(network.prefixlen == 0 for network in self.trusted_proxy_cidrs):
                raise ValueError("deployed proxy trust must not include every network peer")
            if issuer.scheme != "https" or jwks.scheme != "https" or userinfo.scheme != "https":
                raise ValueError("deployed Cognito endpoints must use HTTPS")
            if any(_is_loopback_host(parsed.hostname or "") for parsed in (issuer, jwks, userinfo)):
                raise ValueError("deployed Cognito endpoints must not use loopback hosts")
            if (
                COGNITO_REGIONAL_HOST.fullmatch(issuer.hostname or "") is None
                or COGNITO_USER_POOL_PATH.fullmatch(issuer.path) is None
            ):
                raise ValueError("COGNITO_ISSUER must identify one regional Cognito User Pool")
        return self

    @property
    def deployed_environment(self) -> bool:
        return self.app_env.deployed_environment

    @property
    def relaxed_local_environment(self) -> bool:
        return self.app_env.relaxed_local_environment

    def safe_summary(self) -> dict[str, str | int | bool]:
        """Return a bounded, credential-free operational summary."""

        return {
            "environment": self.app_env.value,
            "service_version": self.service_version,
            "port": self.port,
            "log_level": self.log_level,
            "log_format": self.log_format,
            "metrics_enabled": self.metrics_enabled,
        }
