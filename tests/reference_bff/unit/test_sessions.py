from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from reference_bff.config import Settings
from reference_bff.sessions import (
    InvalidSessionCookieError,
    InvalidSessionRecordError,
    SessionHandle,
    SessionRecord,
    is_canonical_session_id,
    opaque_session_id,
    parse_session_cookie,
    parse_session_record,
)

NOW = 1_900_000_000


def record(settings: Settings) -> SessionRecord:
    created = NOW - 10
    return SessionRecord(
        issuer=settings.cognito_issuer,
        subject="synthetic-provider-subject",
        client_id=settings.client_id,
        user_id="1526af3c-c76a-4e01-a507-347205fb3c93",
        nonce="A" * 43,
        token_family_id="synthetic-token-family",
        access_token="header.payload.signature",
        id_token="header.payload.signature",
        refresh_token="synthetic-refresh-token",
        access_expires_at=NOW + 900,
        created_at=created,
        last_activity_at=NOW - 1,
        absolute_expires_at=created + settings.session_absolute_seconds,
        refresh_version=3,
    )


def test_session_cookie_requires_one_canonical_256_bit_value() -> None:
    session_id = opaque_session_id()
    assert len(session_id) == 43
    assert is_canonical_session_id(session_id)
    assert (
        parse_session_cookie([(b"cookie", f"a=1; __Host-session={session_id}".encode())])
        == session_id
    )

    invalid_headers = [
        [],
        [(b"cookie", b"a=1")],
        [(b"cookie", f"__Host-session={session_id}=".encode())],
        [(b"cookie", b"__Host-session=" + b"A" * 42 + b"B")],
        [(b"cookie", f'__Host-session="{session_id}"'.encode())],
        [(b"cookie", f"__Host-session={session_id}; __Host-session={session_id}".encode())],
        [(b"cookie", b"a=1; a=2"), (b"cookie", f"__Host-session={session_id}".encode())],
        [(b"cookie", f"__Host-session={session_id};  a=1".encode())],
        [(b"cookie", b"__Host-session=\xff")],
    ]
    for headers in invalid_headers:
        with pytest.raises(InvalidSessionCookieError):
            parse_session_cookie(headers)
    handle = SessionHandle(session_id=session_id, max_age=43_200)
    assert repr(handle) == "SessionHandle(<redacted>)"
    assert session_id not in repr(handle)


def test_strict_session_round_trip_has_value_free_representations(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    original = record(settings)
    parsed = parse_session_record(original.as_json_bytes(), settings, now=NOW)

    assert parsed.record == original
    rendered = repr(parsed) + repr(parsed.record)
    for secret in (
        original.subject,
        original.nonce,
        original.token_family_id,
        original.access_token,
        original.id_token,
        original.refresh_token,
    ):
        assert secret is not None
        assert secret not in rendered
    assert original.issuer not in rendered
    assert original.client_id not in rendered
    assert original.user_id not in rendered
    assert repr(parsed) == "StoredSession(<redacted>)"
    assert repr(parsed.record) == "SessionRecord(<redacted>)"


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("version", 1),
        ("issuer", "http://127.0.0.1:9000/other-pool"),
        ("client_id", "other-client"),
        ("subject", ""),
        ("user_id", "1526AF3C-C76A-4E01-A507-347205FB3C93"),
        ("nonce", "N" * 42),
        ("nonce", "N" * 43),
        ("token_family_id", None),
        ("token_family_id", "bad\nfamily"),
        ("access_token", "not-a-jwt-token"),
        ("id_token", "not-a-jwt-token"),
        ("refresh_token", "short"),
        ("refresh_version", -1),
        ("refresh_version", True),
        ("created_at", True),
    ],
)
def test_session_parser_rejects_binding_type_schema_and_token_abuse(
    bff_settings_factory: Callable[..., Settings], field_name: str, value: object
) -> None:
    settings = bff_settings_factory()
    document = json.loads(record(settings).as_json_bytes())
    document[field_name] = value
    with pytest.raises(InvalidSessionRecordError):
        parse_session_record(json.dumps(document).encode(), settings, now=NOW)


def test_session_parser_rejects_duplicates_extra_fields_and_bounded_lifetime(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    raw = record(settings).as_json_bytes()
    duplicate = raw.replace(b'"version":2', b'"version":2,"version":2')
    extra = json.loads(raw)
    extra["provider_subject"] = "forbidden"
    idle = json.loads(raw)
    idle["last_activity_at"] = NOW - settings.session_idle_seconds
    absolute = json.loads(raw)
    absolute["absolute_expires_at"] = NOW
    incoherent = json.loads(raw)
    incoherent["last_activity_at"] = incoherent["created_at"] - 1
    oversized = b"x" * (settings.max_session_bytes + 1)

    for payload in (
        duplicate,
        json.dumps(extra).encode(),
        json.dumps(idle).encode(),
        json.dumps(absolute).encode(),
        json.dumps(incoherent).encode(),
        oversized,
        b"[]",
        b"\xff",
    ):
        with pytest.raises(InvalidSessionRecordError):
            parse_session_record(payload, settings, now=NOW)
