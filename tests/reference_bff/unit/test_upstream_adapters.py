from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any, cast

import httpx2
import pytest
from reference_bff.config import Settings
from reference_bff.exchange import (
    AuthorizationCodeClient,
    CodeExchangeUnavailableError,
    InvalidRefreshResponseError,
    RefreshRejectedError,
    RefreshUnavailableError,
)
from reference_bff.http import AsyncUpstreamClient
from reference_bff.identity import (
    IdentityBootstrapClient,
    IdentityBootstrapUnavailableError,
    IdentityProfileClient,
    IdentityProfileUnavailableError,
    IdentitySessionRejectedError,
)
from reference_bff.transactions import new_transaction

from tests.reference_bff.provider import SyntheticProvider


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def configured(
    bff_settings_factory: Callable[..., Settings],
) -> tuple[Settings, SyntheticProvider, AsyncUpstreamClient]:
    settings = bff_settings_factory()
    provider = SyntheticProvider(settings)
    transaction = new_transaction(
        return_to="/",
        callback_uri=settings.callback_uri,
        ttl_seconds=settings.oauth_transaction_ttl_seconds,
    )
    provider.configure(transaction)
    transport = cast(httpx2.AsyncBaseTransport, httpx2.MockTransport(provider.handle))
    return settings, provider, AsyncUpstreamClient(settings, transport=transport)


def test_code_exchange_uses_exact_confidential_pkce_request_and_redacted_result(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings, provider, upstream = configured(bff_settings_factory)
    assert provider.transaction is not None
    exchange = AuthorizationCodeClient(settings, upstream)

    async def scenario() -> None:
        result = await exchange.exchange(provider.code, provider.transaction)
        assert result.access_token == provider.access_token
        assert result.id_token == provider.id_token
        assert result.refresh_token == provider.refresh_token
        rendered = repr(result)
        assert provider.access_token not in rendered
        assert provider.id_token not in rendered
        assert provider.refresh_token not in rendered
        await upstream.close()

    run(scenario())
    assert provider.events == ["token"]


@pytest.mark.parametrize(
    ("mode", "value"),
    [
        ("status", 503),
        ("media", "text/plain"),
        ("missing", None),
        ("expires", True),
        ("type", "DPoP"),
        ("scope", "bad\nvalue"),
    ],
)
def test_code_exchange_rejects_status_media_shape_numeric_and_token_type_abuse(
    bff_settings_factory: Callable[..., Settings], mode: str, value: object
) -> None:
    settings, provider, upstream = configured(bff_settings_factory)
    assert provider.transaction is not None
    if mode == "status":
        provider.token_status = int(value)  # type: ignore[arg-type]
    elif mode == "media":
        provider.token_content_type = str(value)
    else:
        document = {
            "access_token": provider.access_token,
            "id_token": provider.id_token,
            "refresh_token": provider.refresh_token,
            "token_type": "Bearer",
            "expires_in": 900,
        }
        if mode == "missing":
            document.pop("id_token")
        elif mode == "expires":
            document["expires_in"] = value
        elif mode == "type":
            document["token_type"] = value
        else:
            document["scope"] = value
        provider.token_document = document
    exchange = AuthorizationCodeClient(settings, upstream)

    async def scenario() -> None:
        with pytest.raises(CodeExchangeUnavailableError) as captured:
            await exchange.exchange(provider.code, provider.transaction)
        assert provider.code not in str(captured.value)
        assert settings.client_secret.get_secret_value() not in str(captured.value)
        await upstream.close()

    run(scenario())


def test_refresh_uses_exact_confidential_grant_and_requires_three_rotated_tokens(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings, provider, upstream = configured(bff_settings_factory)
    exchange = AuthorizationCodeClient(settings, upstream)

    async def scenario() -> None:
        result = await exchange.refresh(provider.refresh_token)
        assert result.access_token == provider.rotated_access_token
        assert result.id_token == provider.rotated_id_token
        assert result.refresh_token == provider.rotated_refresh_token
        assert all(
            value not in repr(result)
            for value in (
                provider.rotated_access_token,
                provider.rotated_id_token,
                provider.rotated_refresh_token,
            )
        )
        assert repr(result) == "TokenResponse(<redacted>)"
        await upstream.close()

    run(scenario())
    assert provider.events == ["refresh"]
    assert provider.refresh_requests == 1


@pytest.mark.parametrize("mode", ["rejected", "unavailable", "missing", "not-rotated"])
def test_refresh_classifies_rejection_outage_and_invalid_rotation_without_values(
    bff_settings_factory: Callable[..., Settings], mode: str
) -> None:
    settings, provider, upstream = configured(bff_settings_factory)
    if mode == "rejected":
        provider.refresh_status = 400
        expected: type[Exception] = RefreshRejectedError
    elif mode == "unavailable":
        provider.refresh_status = 503
        expected = RefreshUnavailableError
    else:
        provider.refresh_document = {
            "access_token": provider.rotated_access_token,
            "id_token": provider.rotated_id_token,
            "refresh_token": provider.rotated_refresh_token,
            "token_type": "Bearer",
            "expires_in": 900,
        }
        if mode == "missing":
            provider.refresh_document.pop("id_token")
        else:
            provider.refresh_document["refresh_token"] = provider.refresh_token
        expected = InvalidRefreshResponseError
    exchange = AuthorizationCodeClient(settings, upstream)

    async def scenario() -> None:
        with pytest.raises(expected) as captured:
            await exchange.refresh(provider.refresh_token)
        assert provider.refresh_token not in str(captured.value)
        await upstream.close()

    run(scenario())


@pytest.mark.parametrize("status", [200, 201])
def test_identity_bootstrap_accepts_only_existing_minimal_profile(
    status: int, bff_settings_factory: Callable[..., Settings]
) -> None:
    settings, provider, upstream = configured(bff_settings_factory)
    provider.identity_status = status
    identity = IdentityBootstrapClient(settings, upstream)

    async def scenario() -> None:
        profile = await identity.bootstrap(provider.access_token)
        assert profile.user_id == "1526af3c-c76a-4e01-a507-347205fb3c93"
        assert profile.created is (status == 201)
        await upstream.close()

    run(scenario())
    assert provider.events == ["identity"]


@pytest.mark.parametrize("mode", ["status", "media", "uuid", "extra", "version", "timestamp"])
def test_identity_bootstrap_rejects_unsafe_status_media_and_profile_shapes(
    bff_settings_factory: Callable[..., Settings], mode: str
) -> None:
    settings, provider, upstream = configured(bff_settings_factory)
    if mode == "status":
        provider.identity_status = 503
    elif mode == "media":
        provider.identity_content_type = "text/plain"
    else:
        now = "2026-08-25T00:00:00+00:00"
        document: dict[str, Any] = {
            "user_id": "1526af3c-c76a-4e01-a507-347205fb3c93",
            "email": None,
            "email_verified": False,
            "display_name": None,
            "avatar_url": None,
            "version": 1,
            "created_at": now,
            "updated_at": now,
        }
        if mode == "uuid":
            document["user_id"] = "not-a-uuid"
        elif mode == "extra":
            document["subject"] = "forbidden"
        elif mode == "version":
            document["version"] = True
        else:
            document["created_at"] = "not-a-time"
        provider.identity_document = document
    identity = IdentityBootstrapClient(settings, upstream)

    async def scenario() -> None:
        with pytest.raises(IdentityBootstrapUnavailableError) as captured:
            await identity.bootstrap(provider.access_token)
        assert provider.access_token not in str(captured.value)
        await upstream.close()

    run(scenario())


def test_identity_profile_read_accepts_only_exact_profile_and_matching_strong_etag(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings, provider, upstream = configured(bff_settings_factory)
    identity = IdentityProfileClient(settings, upstream)

    async def scenario() -> None:
        profile = await identity.read(
            provider.access_token,
            expected_user_id="1526af3c-c76a-4e01-a507-347205fb3c93",
        )
        assert profile.etag == '"v1"'
        assert set(profile.document) == {
            "user_id",
            "email",
            "email_verified",
            "display_name",
            "avatar_url",
            "version",
            "created_at",
            "updated_at",
        }
        assert provider.access_token not in repr(profile)
        await upstream.close()

    run(scenario())
    assert provider.events == ["profile"]


@pytest.mark.parametrize(
    ("mode", "exception"),
    [
        ("rejected", IdentitySessionRejectedError),
        ("status", IdentityProfileUnavailableError),
        ("media", IdentityProfileUnavailableError),
        ("etag", IdentityProfileUnavailableError),
        ("version", IdentityProfileUnavailableError),
        ("uuid", IdentityProfileUnavailableError),
        ("timestamp", IdentityProfileUnavailableError),
        ("extra", IdentityProfileUnavailableError),
        ("binding", IdentityProfileUnavailableError),
    ],
)
def test_identity_profile_read_has_fixed_rejection_and_unsafe_response_classes(
    bff_settings_factory: Callable[..., Settings],
    mode: str,
    exception: type[Exception],
) -> None:
    settings, provider, upstream = configured(bff_settings_factory)
    if mode == "rejected":
        provider.profile_status = 401
    elif mode == "status":
        provider.profile_status = 503
    elif mode == "media":
        provider.identity_content_type = "text/plain"
    elif mode == "etag":
        provider.identity_etag = 'W/"v1"'
    else:
        now = "2026-08-25T00:00:00+00:00"
        provider.identity_document = {
            "user_id": "1526af3c-c76a-4e01-a507-347205fb3c93",
            "email": None,
            "email_verified": False,
            "display_name": None,
            "avatar_url": None,
            "version": 1,
            "created_at": now,
            "updated_at": now,
        }
        if mode == "version":
            provider.identity_etag = '"v2"'
        elif mode == "uuid":
            provider.identity_document["user_id"] = "not-a-uuid"
        elif mode == "timestamp":
            provider.identity_document["created_at"] = "2026-08-25 00:00:00+00:00"
        elif mode == "extra":
            provider.identity_document["subject"] = "forbidden"
    identity = IdentityProfileClient(settings, upstream)

    async def scenario() -> None:
        with pytest.raises(exception) as captured:
            await identity.read(
                provider.access_token,
                expected_user_id=(
                    "6fcd1ec3-f96b-47d1-b22c-b06195ec7c2a"
                    if mode == "binding"
                    else "1526af3c-c76a-4e01-a507-347205fb3c93"
                ),
            )
        assert provider.access_token not in str(captured.value)
        await upstream.close()

    run(scenario())
