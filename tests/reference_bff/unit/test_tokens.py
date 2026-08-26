from __future__ import annotations

import asyncio
import base64
import json
import time
from collections.abc import Callable
from typing import Any, cast

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from reference_bff.config import Settings
from reference_bff.http import AsyncUpstreamClient
from reference_bff.jwks import AsyncJwksCache
from reference_bff.tokens import (
    CognitoTokenVerifier,
    InvalidProviderTokenError,
    TokenVerificationUnavailableError,
)
from reference_bff.transactions import new_transaction

from tests.reference_bff.provider import SyntheticProvider


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def stack(
    settings: Settings, provider: SyntheticProvider
) -> tuple[AsyncUpstreamClient, CognitoTokenVerifier]:
    transport = cast(httpx2.AsyncBaseTransport, httpx2.MockTransport(provider.handle))
    upstream = AsyncUpstreamClient(settings, transport=transport)
    return upstream, CognitoTokenVerifier(settings, AsyncJwksCache(settings, upstream))


def claims(token: str) -> dict[str, Any]:
    value = jwt.decode(
        token,
        options={"verify_signature": False, "verify_aud": False},
        algorithms=["RS256"],
    )
    assert isinstance(value, dict)
    return value


def resign(
    token: str,
    key: rsa.RSAPrivateKey,
    *,
    update: dict[str, Any] | None = None,
    headers: dict[str, Any] | None = None,
) -> str:
    document = claims(token)
    if update:
        document.update(update)
    protected = jwt.get_unverified_header(token)
    if headers:
        protected.update(headers)
    return jwt.encode(document, key, algorithm="RS256", headers=protected)


def configured(
    bff_settings_factory: Callable[..., Settings],
) -> tuple[Settings, SyntheticProvider, str]:
    settings = bff_settings_factory()
    transaction = new_transaction(
        return_to="/profile",
        callback_uri=settings.callback_uri,
        ttl_seconds=settings.oauth_transaction_ttl_seconds,
    )
    provider = SyntheticProvider(settings)
    provider.configure(transaction)
    return settings, provider, transaction.nonce


def test_id_and_access_tokens_validate_independently_with_at_hash(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings, provider, nonce = configured(bff_settings_factory)
    upstream, verifier = stack(settings, provider)

    async def scenario() -> None:
        verified = await verifier.verify(
            id_token=provider.id_token,
            access_token=provider.access_token,
            refresh_token=provider.refresh_token,
            expected_nonce=nonce,
        )
        assert verified.issuer == settings.cognito_issuer
        assert verified.client_id == settings.client_id
        assert verified.subject == provider.subject
        assert verified.access_expires_at > int(time.time())
        assert provider.access_token not in repr(verified)
        assert provider.refresh_token not in repr(verified)
        await upstream.close()

    run(scenario())
    assert provider.events == ["jwks"]


@pytest.mark.parametrize(
    ("target", "update"),
    [
        ("id", {"iss": "https://wrong.invalid/pool"}),
        ("id", {"aud": "wrong-client"}),
        ("id", {"token_use": "access"}),
        ("id", {"nonce": "B" * 43}),
        ("id", {"exp": 1}),
        ("id", {"iat": 4_000_000_000}),
        ("access", {"iss": "https://wrong.invalid/pool"}),
        ("access", {"aud": "other://resource"}),
        ("access", {"client_id": "other-client"}),
        ("access", {"token_use": "id"}),
        ("access", {"sub": "different-subject"}),
        ("access", {"scope": "openid identity-service://api/profile.read"}),
        ("access", {"nbf": 4_000_000_000}),
    ],
)
def test_wrong_claim_bindings_and_times_fail_closed(
    bff_settings_factory: Callable[..., Settings],
    target: str,
    update: dict[str, Any],
) -> None:
    settings, provider, nonce = configured(bff_settings_factory)
    id_token = provider.id_token
    access_token = provider.access_token
    if target == "id":
        id_token = resign(id_token, provider.private_key, update=update)
    else:
        access_token = resign(access_token, provider.private_key, update=update)
    upstream, verifier = stack(settings, provider)

    async def scenario() -> None:
        with pytest.raises(InvalidProviderTokenError):
            await verifier.verify(
                id_token=id_token,
                access_token=access_token,
                refresh_token=provider.refresh_token,
                expected_nonce=nonce,
            )
        await upstream.close()

    run(scenario())


def test_at_hash_signature_unknown_key_and_refresh_token_fail_closed(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings, provider, nonce = configured(bff_settings_factory)
    cases = [
        (
            resign(provider.id_token, provider.private_key, update={"at_hash": "wrong"}),
            provider.access_token,
            provider.refresh_token,
        ),
        (
            provider.id_token,
            resign(
                provider.access_token,
                rsa.generate_private_key(65537, 2048),
            ),
            provider.refresh_token,
        ),
        (
            resign(provider.id_token, provider.private_key, headers={"kid": "unknown-key"}),
            provider.access_token,
            provider.refresh_token,
        ),
        (provider.id_token, provider.access_token, "short"),
    ]

    async def scenario() -> None:
        for id_token, access_token, refresh_token in cases:
            upstream, verifier = stack(settings, provider)
            with pytest.raises(InvalidProviderTokenError):
                await verifier.verify(
                    id_token=id_token,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    expected_nonce=nonce,
                )
            await upstream.close()

    run(scenario())


def test_header_confusion_duplicate_json_and_excessive_nesting_are_rejected_pre_jwks(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings, provider, nonce = configured(bff_settings_factory)
    payload = base64.urlsafe_b64encode(b'{"sub":"one","sub":"two"}').rstrip(b"=").decode()
    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "kid": provider.key_id}).encode())
        .rstrip(b"=")
        .decode()
    )
    duplicate = f"{header}.{payload}.signature"
    nested_payload = (
        base64.urlsafe_b64encode(b'{"value":' + b"[" * 40 + b"0" + b"]" * 40 + b"}")
        .rstrip(b"=")
        .decode()
    )
    nested = f"{header}.{nested_payload}.signature"
    noncanonical_signature = provider.id_token + "="
    unsafe_header = resign(
        provider.id_token,
        provider.private_key,
        headers={"jku": "https://evil.invalid/jwks"},
    )
    algorithm_confusion = jwt.encode(
        claims(provider.id_token),
        "synthetic-hmac-key-that-is-forty-bytes-long",  # pragma: allowlist secret
        algorithm="HS256",
        headers={"kid": provider.key_id},
    )
    upstream, verifier = stack(settings, provider)

    async def scenario() -> None:
        for invalid_id in (
            duplicate,
            nested,
            noncanonical_signature,
            unsafe_header,
            algorithm_confusion,
        ):
            with pytest.raises(InvalidProviderTokenError):
                await verifier.verify(
                    id_token=invalid_id,
                    access_token=provider.access_token,
                    refresh_token=provider.refresh_token,
                    expected_nonce=nonce,
                )
        await upstream.close()

    run(scenario())
    assert provider.events == []


def test_jwks_outage_is_dependency_unavailable_not_token_acceptance(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings, provider, nonce = configured(bff_settings_factory)

    def unavailable(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("synthetic outage", request=request)

    transport = cast(httpx2.AsyncBaseTransport, httpx2.MockTransport(unavailable))
    upstream = AsyncUpstreamClient(settings, transport=transport)
    verifier = CognitoTokenVerifier(settings, AsyncJwksCache(settings, upstream))

    async def scenario() -> None:
        with pytest.raises(TokenVerificationUnavailableError):
            await verifier.verify(
                id_token=provider.id_token,
                access_token=provider.access_token,
                refresh_token=provider.refresh_token,
                expected_nonce=nonce,
            )
        await upstream.close()

    run(scenario())
