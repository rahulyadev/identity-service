"""Synthetic cases exercise the existing rejecting stage, including library ambiguity."""

from __future__ import annotations

import asyncio
import base64
import time
from collections.abc import Callable
from typing import Any, cast

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from reference_bff.auth_diagnostics import TokenFailureCategory as Category
from reference_bff.config import Settings
from reference_bff.tokens import InvalidProviderTokenError

from tests.reference_bff.provider import SyntheticProvider
from tests.reference_bff.unit.test_tokens import claims, configured, resign, stack

# ID/access context must not come from token_use, even when that claim is wrong.
TOKEN_CASES = [
    (side, case, getattr(Category, f"{side.upper()}_{stage}"))
    for side in ("id", "access")
    for case, stage in (
        ("shape", "FORMAT"),
        ("duplicate-json", "FORMAT"),
        ("deep-json", "FORMAT"),
        ("non-finite-json", "FORMAT"),
        ("noncanonical", "FORMAT"),
        ("header", "HEADER"),
        ("kid-type", "HEADER"),
        ("typ", "HEADER"),
        ("unknown-key", "SIGNING_KEY"),
        ("signature", "SIGNATURE"),
        ("missing", "REQUIRED_CLAIM"),
        ("issuer", "ISSUER"),
        ("audience", "AUDIENCE"),
        ("audience-list", "AUDIENCE"),
        ("use", "USE"),
        ("expired", "TIME"),
        ("future-iat", "TIME"),
        ("future-nbf", "TIME"),
        ("iat-string", "TIME"),
        ("date-bool", "TIME"),
        ("time-order", "TIME"),
        ("auth-time", "TIME"),
        ("subject-type", "SUBJECT"),
        ("subject-empty", "SUBJECT"),
        ("family-missing", "FAMILY"),
        ("family-format", "FAMILY"),
        ("jti-type", "FAMILY"),
        ("jti-missing", "FAMILY"),
        # PyJWT raises generic DecodeError/TypeError for these. Never guess a date category.
        ("ambiguous-exp", "VERIFICATION"),
        ("ambiguous-iat", "VERIFICATION"),
    )
]
PAIR_CASES = [
    ("id", "nonce", Category.ID_NONCE),
    ("access", "client", Category.ACCESS_CLIENT),
    ("access", "scope", Category.ACCESS_SCOPE),
    ("access", "scope-format", Category.ACCESS_SCOPE),
    ("access", "subject-continuity", Category.SUBJECT_CONTINUITY),
    ("access", "family-continuity", Category.FAMILY_CONTINUITY),
    ("id", "at-hash", Category.ID_AT_HASH),
    ("refresh", "refresh-format", Category.REFRESH_FORMAT),
]
REJECTION_CASES = TOKEN_CASES + PAIR_CASES


def independent_provider(settings: Settings) -> SyntheticProvider:
    return SyntheticProvider(settings, access_private_key=rsa.generate_private_key(65537, 2048))


def mutate(provider: SyntheticProvider, side: str, case: str) -> None:
    """Change synthetic signed material without changing the verifier under test."""
    if case == "refresh-format":
        provider.refresh_token = "R" * (provider.settings.jwt_max_token_bytes + 1)
        return
    original = provider.id_token if side == "id" else provider.access_token
    key = provider.private_key if side == "id" else provider.access_private_key
    assert key is not None
    now = int(time.time())
    updates: dict[str, dict[str, Any]] = {
        "missing": {"auth_time": None},
        "issuer": {"iss": "https://wrong.invalid/pool"},
        "audience": {"aud": "wrong-audience"},
        "audience-list": {"aud": [claims(original)["aud"]]},
        "use": {"token_use": "access" if side == "id" else "id"},
        "expired": {"exp": 1},
        "future-iat": {"iat": now + 3600},
        "future-nbf": {"nbf": now + 3600},
        "iat-string": {"iat": "invalid"},
        "date-bool": {"iat": True},
        "time-order": {"iat": now, "exp": now},
        "auth-time": {"auth_time": now + 3600},
        "subject-type": {"sub": 7},
        "subject-empty": {"sub": ""},
        "family-missing": {"origin_jti": None},
        "family-format": {"origin_jti": "bad family"},
        "jti-type": {"jti": 7},
        "ambiguous-exp": {"exp": "invalid"},
        "ambiguous-iat": {"iat": []},
        "nonce": {"nonce": "wrong-nonce"},
        "client": {"client_id": "wrong-client"},
        "scope": {"scope": "openid"},
        "scope-format": {"scope": "openid  openid"},
        "subject-continuity": {"sub": "other-subject"},
        "family-continuity": {"origin_jti": "other-family"},
        "at-hash": {"at_hash": "wrong-hash"},
    }
    if case in updates:
        token = resign(original, key, update=updates[case])
    elif case == "jti-missing":
        document = claims(original)
        del document["jti"]
        token = jwt.encode(
            document, key, algorithm="RS256", headers=jwt.get_unverified_header(original)
        )
    elif case == "shape":
        token = "malformed-provider-token"
    elif case == "noncanonical":
        token = original + "="
    elif case in {"duplicate-json", "deep-json", "non-finite-json"}:
        payload = {
            "duplicate-json": b'{"sub":1,"sub":2}',
            "deep-json": b'{"x":' + b"[" * 40 + b"0" + b"]" * 40 + b"}",
            "non-finite-json": b'{"x":NaN}',
        }[case]
        encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
        header, _, signature = original.split(".")
        token = f"{header}.{encoded}.{signature}"
    elif case == "signature":
        token = resign(original, rsa.generate_private_key(65537, 2048))
    else:
        headers = {
            "header": {"jku": "https://untrusted.invalid/jwks"},
            "kid-type": {"kid": ""},
            "typ": {"typ": "unsafe"},
            "unknown-key": {"kid": "unknown-signing-key"},
        }[case]
        token = resign(original, key, headers=headers)
    if side == "id":
        provider.id_token = token
    else:
        provider.access_token = token


@pytest.mark.parametrize(("side", "case", "category"), REJECTION_CASES)
def test_actual_verifier_reports_first_rejecting_stage(
    bff_settings_factory: Callable[..., Settings], side: str, case: str, category: Category
) -> None:
    settings, original, nonce = configured(bff_settings_factory)
    provider = independent_provider(settings)
    assert original.transaction is not None
    provider.configure(original.transaction)
    mutate(provider, side, case)
    upstream, verifier = stack(settings, provider)

    async def scenario() -> None:
        try:
            with pytest.raises(InvalidProviderTokenError) as error:
                await verifier.verify(
                    id_token=provider.id_token,
                    access_token=provider.access_token,
                    refresh_token=provider.refresh_token,
                    expected_nonce=nonce,
                )
            assert error.value.category is category
            assert str(error.value) == category.value
        finally:
            await upstream.close()

    asyncio.run(scenario())


def test_distinct_signing_keys_and_federated_shaped_claims_pass(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings, original, nonce = configured(bff_settings_factory)
    provider = independent_provider(settings)
    assert original.transaction is not None
    provider.configure(original.transaction)
    provider.id_token = resign(
        provider.id_token,
        provider.private_key,
        update={
            "identities": [
                {
                    "userId": "synthetic-provider-subject",
                    "providerName": "Google",
                    "providerType": "Google",
                    "issuer": None,
                    "primary": "true",
                    "dateCreated": "1234567890000",
                }
            ],
            "email": "synthetic@example.invalid",
            "email_verified": True,
            "cognito:username": "Google_synthetic",
            "name": "Synthetic Person",
            "picture": "https://example.invalid/avatar",
        },
    )
    assert (
        jwt.get_unverified_header(provider.id_token)["kid"]
        != jwt.get_unverified_header(provider.access_token)["kid"]
    )
    assert provider.public_jwk()["n"] != provider.public_jwk(access=True)["n"]
    upstream, verifier = stack(settings, provider)

    async def scenario() -> None:
        try:
            result = await verifier.verify(
                id_token=provider.id_token,
                access_token=provider.access_token,
                refresh_token=provider.refresh_token,
                expected_nonce=nonce,
            )
            assert result.subject == provider.subject
        finally:
            await upstream.close()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "error",
    [
        jwt.DecodeError("hostile-message"),
        ValueError("hostile-message"),
        jwt.MissingRequiredClaimError("hostile-claim"),
    ],
)
def test_unknown_library_specificity_uses_fixed_fallback(
    bff_settings_factory: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    settings, provider, nonce = configured(bff_settings_factory)
    upstream, verifier = stack(settings, provider)

    def reject(*args: Any, **kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr(jwt, "decode", reject)

    async def scenario() -> None:
        try:
            with pytest.raises(InvalidProviderTokenError) as caught:
                await verifier.verify(
                    id_token=provider.id_token,
                    access_token=provider.access_token,
                    refresh_token=provider.refresh_token,
                    expected_nonce=nonce,
                )
            assert caught.value.category is Category.ID_VERIFICATION
            assert "hostile" not in str(caught.value)
        finally:
            await upstream.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("invalid", [None, "id_nonce", "sentinel@example.invalid\r\n", {}, [], 7])
def test_malformed_category_is_closed_and_value_free(invalid: object) -> None:
    error = InvalidProviderTokenError(cast(Category, invalid))
    assert error.category is Category.VERIFICATION
    assert str(error) == "verification"
    assert repr(error) == "InvalidProviderTokenError('verification')"


@pytest.mark.parametrize(
    "side,missing",
    [
        (side, name)
        for side in ("id", "access")
        for name in ("iss", "sub", "aud", "token_use", "exp", "iat", "auth_time")
    ]
    + [("id", "nonce"), ("access", "client_id"), ("access", "scope")],
)
def test_required_claim_category_precedes_later_claim_checks(bff_settings_factory, side, missing):
    settings, original, nonce = configured(bff_settings_factory)
    provider = independent_provider(settings)
    provider.configure(original.transaction)
    token = getattr(provider, side + "_token")
    key = provider.private_key if side == "id" else provider.access_private_key
    document = claims(token)
    del document[missing]
    document["exp"] = 1 if missing != "exp" else None
    setattr(
        provider,
        side + "_token",
        jwt.encode(document, key, algorithm="RS256", headers=jwt.get_unverified_header(token)),
    )
    upstream, verifier = stack(settings, provider)

    async def scenario():
        try:
            with pytest.raises(InvalidProviderTokenError) as caught:
                await verifier.verify(
                    id_token=provider.id_token,
                    access_token=provider.access_token,
                    refresh_token=provider.refresh_token,
                    expected_nonce=nonce,
                )
            assert caught.value.category is (
                Category.ID_REQUIRED_CLAIM if side == "id" else Category.ACCESS_REQUIRED_CLAIM
            )
        finally:
            await upstream.close()

    asyncio.run(scenario())


def test_access_signature_rejects_before_pair_nonce_binding(bff_settings_factory):
    settings, original, nonce = configured(bff_settings_factory)
    provider = independent_provider(settings)
    provider.configure(original.transaction)
    mutate(provider, "id", "nonce")
    mutate(provider, "access", "signature")
    upstream, verifier = stack(settings, provider)

    async def scenario():
        try:
            with pytest.raises(InvalidProviderTokenError) as caught:
                await verifier.verify(
                    id_token=provider.id_token,
                    access_token=provider.access_token,
                    refresh_token=provider.refresh_token,
                    expected_nonce=nonce,
                )
            assert caught.value.category is Category.ACCESS_SIGNATURE
        finally:
            await upstream.close()

    asyncio.run(scenario())
