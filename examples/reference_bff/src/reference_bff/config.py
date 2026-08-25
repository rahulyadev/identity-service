"""Strict, secret-safe configuration for the standalone reference BFF."""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum
from typing import Annotated, Any, Literal, Self
from urllib.parse import SplitResult, urlsplit

from pydantic import BeforeValidator, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REQUIRED_SCOPES = frozenset(
    {
        "openid",
        "identity-service://api/profile.read",
        "identity-service://api/profile.write",
    }
)
SCOPE_VALUE = re.compile(r"[^\x00-\x20\x7f*]{1,256}")
OPAQUE_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~:-]{0,255}")
NAMESPACE_VALUE = re.compile(r"[a-z0-9][a-z0-9:_-]{2,95}")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
COGNITO_REGIONAL_HOST = re.compile(r"cognito-idp\.[a-z0-9-]+\.amazonaws\.com")
COGNITO_USER_POOL_PATH = re.compile(r"/[A-Za-z0-9_-]{1,128}")


class BffEnvironment(StrEnum):
    LOCAL = "local"
    TEST = "test"
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

    @property
    def deployed(self) -> bool:
        return self in {self.DEVELOPMENT, self.STAGING, self.PRODUCTION}


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


def _is_loopback(host: str) -> bool:
    normalized = host.casefold().rstrip(".")
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _validate_host(value: str) -> str:
    if value != value.strip() or not value or value == "*" or len(value) > 253:
        raise ValueError("hosts must be explicit, bounded, and contain no whitespace")
    candidate = value.casefold().rstrip(".")
    if any(character.isspace() or ord(character) > 127 for character in candidate):
        raise ValueError("hosts must use canonical ASCII DNS or IP syntax")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        if any(not DNS_LABEL.fullmatch(label) for label in candidate.split(".")):
            raise ValueError("hosts must use canonical ASCII DNS or IP syntax") from None
    return candidate


def _split_http_url(value: str, field_name: str, *, origin: bool) -> SplitResult:
    if (
        not value
        or value != value.strip()
        or "\\" in value
        or any(character.isspace() for character in value)
    ):
        raise ValueError(f"{field_name} must be an unambiguous HTTP URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError(f"{field_name} must be a valid HTTP URL") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise ValueError(f"{field_name} must be an absolute credential-free HTTP URL")
    _validate_host(parsed.hostname)
    if origin:
        if parsed.path:
            raise ValueError(f"{field_name} must contain only scheme and authority")
    elif not parsed.path.startswith("/") or parsed.path.startswith("//"):
        raise ValueError(f"{field_name} must contain one canonical absolute path")
    return parsed


def _split_redis_url(value: str) -> SplitResult:
    if (
        not value
        or value != value.strip()
        or "\\" in value
        or any(character.isspace() for character in value)
    ):
        raise ValueError("REDIS_URL must be an unambiguous Redis URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("REDIS_URL must be a valid Redis URL") from None
    if (
        parsed.scheme not in {"redis", "rediss"}
        or not parsed.hostname
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65_535)
        or not re.fullmatch(r"/(?:[0-9]|1[0-5])", parsed.path)
    ):
        raise ValueError("REDIS_URL must select one bounded TCP Redis database")
    _validate_host(parsed.hostname)
    return parsed


class Settings(BaseSettings):
    """Environment-only settings with strict parsing and hidden invalid inputs."""

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=None,
        extra="forbid",
        hide_input_in_errors=True,
        populate_by_name=True,
        validate_default=True,
    )

    app_env: BffEnvironment = Field(default=BffEnvironment.LOCAL, validation_alias="APP_ENV")
    service_version: str = Field(default="0.1.0", validation_alias="SERVICE_VERSION")
    port: EnvInt = Field(default=8081, ge=1, le=65_535, validation_alias="PORT")
    bff_origin: str = Field(default="http://localhost:8081", validation_alias="BFF_ORIGIN")
    allowed_hosts: list[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "testserver"],
        validation_alias="ALLOWED_HOSTS",
    )
    trusted_proxy_networks: list[Network] = Field(
        default_factory=list, validation_alias="TRUSTED_PROXY_NETWORKS"
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO", validation_alias="LOG_LEVEL"
    )
    log_format: Literal["json", "console"] = Field(default="console", validation_alias="LOG_FORMAT")
    enable_interactive_docs: EnvBool = Field(
        default=True, validation_alias="ENABLE_INTERACTIVE_DOCS"
    )
    graceful_shutdown_seconds: EnvInt = Field(
        default=15, ge=1, le=60, validation_alias="GRACEFUL_SHUTDOWN_SECONDS"
    )
    redis_connect_timeout_seconds: EnvInt = Field(
        default=2, ge=1, le=10, validation_alias="REDIS_CONNECT_TIMEOUT_SECONDS"
    )
    redis_operation_timeout_seconds: EnvInt = Field(
        default=2, ge=1, le=10, validation_alias="REDIS_OPERATION_TIMEOUT_SECONDS"
    )

    authorization_endpoint: str = Field(validation_alias="AUTHORIZATION_ENDPOINT")
    token_endpoint: str = Field(validation_alias="TOKEN_ENDPOINT", repr=False)
    cognito_issuer: str = Field(validation_alias="COGNITO_ISSUER", repr=False)
    cognito_jwks_url: str = Field(validation_alias="COGNITO_JWKS_URL", repr=False)
    identity_api_origin: str = Field(validation_alias="IDENTITY_API_ORIGIN", repr=False)
    oauth_resource: str = Field(default="identity-service://api", validation_alias="OAUTH_RESOURCE")
    client_id: str = Field(validation_alias="BFF_CLIENT_ID", repr=False)
    client_secret: SecretStr = Field(validation_alias="BFF_CLIENT_SECRET", repr=True)
    requested_scopes: list[str] = Field(
        default_factory=lambda: sorted(REQUIRED_SCOPES), validation_alias="REQUESTED_SCOPES"
    )
    redis_url: SecretStr = Field(validation_alias="REDIS_URL", repr=True)
    redis_key_namespace: str = Field(validation_alias="REDIS_KEY_NAMESPACE")
    oauth_transaction_ttl_seconds: EnvInt = Field(
        default=300, ge=60, le=600, validation_alias="OAUTH_TRANSACTION_TTL_SECONDS"
    )
    max_return_to_bytes: EnvInt = Field(
        default=2048, ge=128, le=4096, validation_alias="MAX_RETURN_TO_BYTES"
    )
    max_transaction_bytes: EnvInt = Field(
        default=8192, ge=1024, le=16_384, validation_alias="MAX_TRANSACTION_BYTES"
    )
    max_callback_query_bytes: EnvInt = Field(
        default=8192, ge=512, le=16_384, validation_alias="MAX_CALLBACK_QUERY_BYTES"
    )
    max_oauth_code_bytes: EnvInt = Field(
        default=4096, ge=128, le=8192, validation_alias="MAX_OAUTH_CODE_BYTES"
    )
    max_provider_error_bytes: EnvInt = Field(
        default=128, ge=32, le=256, validation_alias="MAX_PROVIDER_ERROR_BYTES"
    )
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
    session_idle_seconds: EnvInt = Field(
        default=43_200, ge=300, le=86_400, validation_alias="SESSION_IDLE_SECONDS"
    )
    session_absolute_seconds: EnvInt = Field(
        default=604_800, ge=3600, le=2_419_200, validation_alias="SESSION_ABSOLUTE_SECONDS"
    )
    max_session_bytes: EnvInt = Field(
        default=65_536, ge=4096, le=262_144, validation_alias="MAX_SESSION_BYTES"
    )

    @field_validator("service_version")
    @classmethod
    def validate_service_version(cls, value: str) -> str:
        if re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}", value) is None:
            raise ValueError("must be a bounded release identifier")
        return value

    @field_validator("bff_origin")
    @classmethod
    def validate_bff_origin(cls, value: str) -> str:
        _split_http_url(value, "BFF_ORIGIN", origin=True)
        return value

    @field_validator(
        "authorization_endpoint",
        "token_endpoint",
        "cognito_issuer",
        "cognito_jwks_url",
    )
    @classmethod
    def validate_provider_endpoint(cls, value: str, info: Any) -> str:
        _split_http_url(value, (info.field_name or "provider_endpoint").upper(), origin=False)
        return value

    @field_validator("identity_api_origin")
    @classmethod
    def validate_identity_api_origin(cls, value: str) -> str:
        _split_http_url(value, "IDENTITY_API_ORIGIN", origin=True)
        return value

    @field_validator("oauth_resource")
    @classmethod
    def validate_oauth_resource(cls, value: str) -> str:
        if value != "identity-service://api":
            raise ValueError("OAUTH_RESOURCE must use the fixed Identity resource identifier")
        return value

    @field_validator("allowed_hosts")
    @classmethod
    def validate_allowed_hosts(cls, values: list[str]) -> list[str]:
        normalized = [_validate_host(value) for value in values]
        if not normalized or len(normalized) > 16 or len(set(normalized)) != len(normalized):
            raise ValueError("ALLOWED_HOSTS must contain 1 to 16 unique explicit hosts")
        return normalized

    @field_validator("trusted_proxy_networks")
    @classmethod
    def validate_trusted_proxy_networks(cls, values: list[Network]) -> list[Network]:
        if len(values) > 16 or len({str(value) for value in values}) != len(values):
            raise ValueError("TRUSTED_PROXY_NETWORKS must contain at most 16 unique networks")
        if any(
            value.prefixlen == 0 or value.is_multicast or value.is_unspecified for value in values
        ):
            raise ValueError("TRUSTED_PROXY_NETWORKS cannot contain permissive networks")
        return values

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, value: str) -> str:
        if OPAQUE_VALUE.fullmatch(value) is None:
            raise ValueError("BFF_CLIENT_ID must be a bounded opaque identifier")
        return value

    @field_validator("client_secret")
    @classmethod
    def validate_client_secret(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if (
            len(secret) < 16
            or len(secret) > 4096
            or any(ord(character) < 33 for character in secret)
        ):
            raise ValueError("BFF_CLIENT_SECRET must be a bounded non-whitespace secret")
        return value

    @field_validator("requested_scopes")
    @classmethod
    def validate_requested_scopes(cls, values: list[str]) -> list[str]:
        if not 3 <= len(values) <= 16 or len(set(values)) != len(values):
            raise ValueError("REQUESTED_SCOPES must contain 3 to 16 unique values")
        if any(SCOPE_VALUE.fullmatch(value) is None for value in values):
            raise ValueError("REQUESTED_SCOPES contains an invalid or wildcard value")
        if not set(values) >= REQUIRED_SCOPES:
            raise ValueError("REQUESTED_SCOPES omits a required scope")
        return values

    @field_validator("redis_url")
    @classmethod
    def validate_redis_url(cls, value: SecretStr) -> SecretStr:
        _split_redis_url(value.get_secret_value())
        return value

    @field_validator("redis_key_namespace")
    @classmethod
    def validate_redis_key_namespace(cls, value: str) -> str:
        if NAMESPACE_VALUE.fullmatch(value) is None:
            raise ValueError("REDIS_KEY_NAMESPACE must be a bounded application namespace")
        return value

    @model_validator(mode="after")
    def validate_environment_boundary(self) -> Self:
        origin = _split_http_url(self.bff_origin, "BFF_ORIGIN", origin=True)
        provider = _split_http_url(
            self.authorization_endpoint, "AUTHORIZATION_ENDPOINT", origin=False
        )
        token = _split_http_url(self.token_endpoint, "TOKEN_ENDPOINT", origin=False)
        issuer = _split_http_url(self.cognito_issuer, "COGNITO_ISSUER", origin=False)
        jwks = _split_http_url(self.cognito_jwks_url, "COGNITO_JWKS_URL", origin=False)
        identity_api = _split_http_url(self.identity_api_origin, "IDENTITY_API_ORIGIN", origin=True)
        redis = _split_redis_url(self.redis_url.get_secret_value())
        if _validate_host(origin.hostname or "") not in self.allowed_hosts:
            raise ValueError("BFF_ORIGIN host must be explicitly allowed")
        required_namespace = f"reference-bff:{self.app_env.value}:"
        if not self.redis_key_namespace.startswith(required_namespace):
            raise ValueError("REDIS_KEY_NAMESPACE must identify this application and environment")
        provider_authority = (provider.scheme, provider.hostname, provider.port)
        if (
            provider.path != "/oauth2/authorize"
            or (
                token.scheme,
                token.hostname,
                token.port,
            )
            != provider_authority
            or token.path != "/oauth2/token"
        ):
            raise ValueError(
                "managed-login endpoints must share one authority and exact OAuth paths"
            )
        if self.cognito_jwks_url != self.cognito_issuer.rstrip("/") + "/.well-known/jwks.json":
            raise ValueError("COGNITO_JWKS_URL must exactly match the configured issuer")
        if self.jwks_stale_if_error_seconds < self.jwks_cache_max_age_seconds:
            raise ValueError("JWKS_STALE_IF_ERROR_SECONDS must include the fresh-cache lifetime")
        if self.session_absolute_seconds < self.session_idle_seconds:
            raise ValueError("SESSION_ABSOLUTE_SECONDS must not be shorter than the idle lifetime")
        if self.app_env.deployed:
            if origin.scheme != "https" or _is_loopback(origin.hostname or ""):
                raise ValueError("deployed BFF_ORIGIN requires non-loopback HTTPS")
            provider_urls = (provider, token, issuer, jwks, identity_api)
            if any(
                parsed.scheme != "https" or _is_loopback(parsed.hostname or "")
                for parsed in provider_urls
            ):
                raise ValueError("deployed upstream endpoints require non-loopback HTTPS")
            if (
                COGNITO_REGIONAL_HOST.fullmatch(issuer.hostname or "") is None
                or COGNITO_USER_POOL_PATH.fullmatch(issuer.path) is None
            ):
                raise ValueError("COGNITO_ISSUER must identify one regional Cognito User Pool")
            if redis.scheme != "rediss" or _is_loopback(redis.hostname or ""):
                raise ValueError("deployed REDIS_URL requires non-loopback TLS transport")
            if (
                self.enable_interactive_docs
                or self.log_level == "DEBUG"
                or self.log_format != "json"
            ):
                raise ValueError("deployed logging and documentation settings are unsafe")
        else:
            if origin.scheme == "http" and not _is_loopback(origin.hostname or ""):
                raise ValueError("plain HTTP BFF_ORIGIN is limited to loopback fixtures")
            if any(
                parsed.scheme == "http" and not _is_loopback(parsed.hostname or "")
                for parsed in (provider, token, issuer, jwks, identity_api)
            ):
                raise ValueError("plain HTTP upstream endpoints are limited to loopback fixtures")
        return self

    @property
    def callback_uri(self) -> str:
        return f"{self.bff_origin}/auth/callback"

    def safe_summary(self) -> dict[str, object]:
        return {
            "environment": self.app_env.value,
            "version": self.service_version,
            "port": self.port,
            "bff_origin": self.bff_origin,
            "allowed_hosts": list(self.allowed_hosts),
            "trusted_proxy_networks": [str(network) for network in self.trusted_proxy_networks],
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "cognito_issuer": self.cognito_issuer,
            "cognito_jwks_url": self.cognito_jwks_url,
            "identity_api_origin": self.identity_api_origin,
            "oauth_resource": self.oauth_resource,
            "callback_uri": self.callback_uri,
            "requested_scopes": list(self.requested_scopes),
            "redis_key_namespace": self.redis_key_namespace,
            "oauth_transaction_ttl_seconds": self.oauth_transaction_ttl_seconds,
            "session_idle_seconds": self.session_idle_seconds,
            "session_absolute_seconds": self.session_absolute_seconds,
        }
