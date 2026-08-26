from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest
from reference_bff.config import Settings
from reference_bff.logout import LogoutRequestError, RawLogoutRequest, validate_logout_request
from reference_bff.session_flow import SessionReadError
from reference_bff.sessions import StoredSession, new_csrf_token, opaque_session_id

from tests.reference_bff.fakes import FakeTransactionStore
from tests.reference_bff.unit.test_session_flow import stack


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


def logout_request(
    settings: Settings,
    csrf_token: str,
    *,
    headers: tuple[tuple[bytes, bytes], ...] = (),
    query_string: bytes = b"",
    body_present: bool = False,
    body_complete: bool = True,
) -> RawLogoutRequest:
    return RawLogoutRequest(
        headers=(
            (b"origin", settings.bff_origin.encode()),
            (b"x-csrf-token", csrf_token.encode()),
            (b"sec-fetch-site", b"same-origin"),
            (b"content-length", b"0"),
            *headers,
        ),
        query_string=query_string,
        body_present=body_present,
        body_complete=body_complete,
    )


def test_logout_deletes_exact_session_before_one_confidential_revocation(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    flow, store, provider, _upstream, session_id = stack(
        settings, now=now, access_lifetime=settings.session_refresh_window_seconds
    )
    assert store.stored is not None
    original = store.stored.record

    async def scenario() -> None:
        await flow.logout(session_id, logout_request(settings, original.csrf_token))
        await flow.close()

    run(scenario())
    assert store.stored is None
    assert store.cas_calls == 0
    assert store.invalidate_calls == 1
    assert provider.refresh_requests == 0
    assert provider.events == ["revoke"]
    assert provider.revoke_requests == 1
    assert provider.revoke_requests_seen == [
        {
            "authorization": provider.revoke_requests_seen[0]["authorization"],
            "content_type": "application/x-www-form-urlencoded",
            "form": {"token": [original.refresh_token]},
            "cookie": None,
        }
    ]
    assert str(provider.revoke_requests_seen[0]["authorization"]).startswith("Basic ")
    assert settings.client_id not in provider.revoke_requests_seen[0]["form"]


@pytest.mark.parametrize(
    ("mutation", "status", "code"),
    [
        ("wrong-token", 403, "csrf_failed"),
        ("wrong-origin", 403, "csrf_failed"),
        ("cross-site", 403, "csrf_failed"),
        ("query", 400, "bad_request"),
        ("body", 400, "bad_request"),
        ("authorization", 400, "bad_request"),
        ("content-type", 400, "bad_request"),
        ("length", 400, "bad_request"),
    ],
)
def test_logout_denials_precede_touch_refresh_invalidation_and_upstream(
    bff_settings_factory: Callable[..., Settings],
    mutation: str,
    status: int,
    code: str,
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    flow, store, provider, _upstream, session_id = stack(
        settings, now=now, access_lifetime=settings.session_refresh_window_seconds
    )
    assert store.stored is not None
    original = store.stored.serialized
    token = store.stored.record.csrf_token
    extra_headers = {
        "wrong-origin": ((b"origin", b"http://attacker.invalid"),),
        "cross-site": ((b"sec-fetch-site", b"cross-site"),),
        "authorization": ((b"authorization", b"Bearer unsafe"),),
        "content-type": ((b"content-type", b"application/json"),),
        "length": ((b"content-length", b"1"),),
    }.get(mutation, ())
    raw = logout_request(
        settings,
        opaque_session_id() if mutation == "wrong-token" else token,
        headers=extra_headers,
        query_string=b"unsafe=1" if mutation == "query" else b"",
        body_present=mutation == "body",
    )

    async def scenario() -> None:
        with pytest.raises(SessionReadError) as captured:
            await flow.logout(session_id, raw)
        assert (captured.value.status, captured.value.code) == (status, code)
        assert captured.value.clear_cookie is False
        await flow.close()

    run(scenario())
    assert store.stored is not None and store.stored.serialized == original
    assert store.cas_calls == 0
    assert store.invalidate_calls == 0
    assert provider.events == []
    assert provider.refresh_requests == 0
    assert provider.revoke_requests == 0


def test_cross_session_csrf_cannot_delete_either_independently_stored_session(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    class CountingStore(FakeTransactionStore):
        def __init__(self, settings: Settings) -> None:
            super().__init__(settings)
            self.load_calls: list[str] = []
            self.invalidate_calls = 0

        async def load_session(self, session_id: str) -> StoredSession | None:
            self.load_calls.append(session_id)
            return await super().load_session(session_id)

        async def invalidate_session(self, session_id: str, expected: StoredSession) -> bool:
            self.invalidate_calls += 1
            return await super().invalidate_session(session_id, expected)

    now = int(time.time())
    settings = bff_settings_factory()
    flow, original_store, provider, _upstream, _unused = stack(
        settings, now=now, access_lifetime=900
    )
    assert original_store.stored is not None
    session_a_id = opaque_session_id()
    session_b_id = opaque_session_id()
    session_a = original_store.stored
    session_b = StoredSession.from_record(
        replace(
            session_a.record,
            nonce=opaque_session_id(),
            csrf_token=new_csrf_token(),
        )
    )
    store = CountingStore(settings)
    store.stored_sessions = {session_a_id: session_a, session_b_id: session_b}
    flow._store = store

    async def scenario() -> None:
        with pytest.raises(SessionReadError) as captured:
            await flow.logout(
                session_a_id,
                logout_request(settings, session_b.record.csrf_token),
            )
        assert (captured.value.status, captured.value.code) == (403, "csrf_failed")
        await flow.close()

    run(scenario())
    assert store.load_calls == [session_a_id]
    assert store.invalidate_calls == 0
    assert store.stored_sessions == {session_a_id: session_a, session_b_id: session_b}
    assert provider.events == []


def test_fifty_concurrent_logouts_have_one_delete_and_one_revocation(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    flow, store, provider, _upstream, session_id = stack(settings, now=now, access_lifetime=900)
    assert store.stored is not None
    raw = logout_request(settings, store.stored.record.csrf_token)

    async def scenario() -> list[str]:
        async def invoke() -> str:
            try:
                await flow.logout(session_id, raw)
            except SessionReadError as error:
                assert (error.status, error.code, error.clear_cookie) == (
                    401,
                    "session_required",
                    True,
                )
                return "missing"
            return "deleted"

        outcomes = await asyncio.gather(*(invoke() for _ in range(50)))
        await flow.close()
        return outcomes

    outcomes = run(scenario())
    assert outcomes.count("deleted") == 1
    assert outcomes.count("missing") == 49
    assert store.stored is None
    assert store.invalidate_calls == 1
    assert provider.revoke_requests == 1
    assert provider.events == ["revoke"]


def test_logout_reloads_one_newer_refresh_version_with_preserved_csrf_before_delete(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    flow, store, provider, _upstream, session_id = stack(settings, now=now, access_lifetime=900)
    assert store.stored is not None
    original = store.stored
    newer = StoredSession.from_record(
        replace(
            original.record,
            access_token=provider.rotated_access_token,
            id_token=provider.rotated_id_token,
            refresh_token=provider.rotated_refresh_token,
            access_expires_at=now + 1800,
            refresh_version=original.record.refresh_version + 1,
        )
    )
    original_invalidate = store.invalidate_session
    injected = False

    async def invalidate(session: str, expected: StoredSession) -> bool:
        nonlocal injected
        if not injected:
            injected = True
            store.invalidate_calls += 1
            store.stored = newer
            return False
        return await original_invalidate(session, expected)

    store.invalidate_session = invalidate  # type: ignore[method-assign]
    provider.refresh_token = provider.rotated_refresh_token

    async def scenario() -> None:
        await flow.logout(
            session_id,
            logout_request(settings, original.record.csrf_token),
        )
        await flow.close()

    run(scenario())
    assert store.stored is None
    assert store.invalidate_calls == 2
    assert provider.revoke_requests == 1
    assert provider.revoke_requests_seen[0]["form"] == {"token": [provider.rotated_refresh_token]}


def test_redis_and_provider_outages_preserve_local_logout_authority(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    flow, store, provider, _upstream, session_id = stack(settings, now=now, access_lifetime=900)
    assert store.stored is not None
    raw = logout_request(settings, store.stored.record.csrf_token)
    original = store.stored.serialized
    store.unavailable = True

    async def redis_outage() -> None:
        with pytest.raises(SessionReadError) as captured:
            await flow.logout(session_id, raw)
        assert (captured.value.status, captured.value.code, captured.value.clear_cookie) == (
            503,
            "session_unavailable",
            True,
        )

    run(redis_outage())
    assert store.stored is not None and store.stored.serialized == original
    assert provider.events == []

    store.unavailable = False
    provider.revoke_status = 503
    provider.revoke_body = b'{"unsafe":"provider-body"}'

    async def provider_outage() -> None:
        await flow.logout(session_id, raw)
        await flow.close()

    run(provider_outage())
    assert store.stored is None
    assert provider.revoke_requests == 1


@pytest.mark.parametrize(
    "raw",
    [
        RawLogoutRequest((), b"x=1", False, True),
        RawLogoutRequest(((b"content-length", b"00"),), b"", False, True),
        RawLogoutRequest(((b"content-length", b"0"), (b"content-length", b"0")), b"", False, True),
        RawLogoutRequest((), b"", True, True),
        RawLogoutRequest((), b"", False, False),
    ],
)
def test_raw_logout_validation_has_one_fixed_bad_request(raw: RawLogoutRequest) -> None:
    with pytest.raises(LogoutRequestError) as captured:
        validate_logout_request(raw)
    assert (captured.value.status, captured.value.code) == (400, "bad_request")
