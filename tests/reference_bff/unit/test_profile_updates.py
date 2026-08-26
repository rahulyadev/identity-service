from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from reference_bff.config import Settings
from reference_bff.profile_updates import (
    ProfilePatchFailure,
    RawProfilePatch,
    require_csrf,
    validate_profile_patch,
)
from reference_bff.sessions import opaque_session_id


def raw_patch(
    settings: Settings,
    token: str,
    *,
    body: bytes = b'{"display_name":"  Cafe\xcc\x81  "}',
    extra_headers: tuple[tuple[bytes, bytes], ...] = (),
    replace_headers: tuple[tuple[bytes, bytes], ...] | None = None,
    query: bytes = b"",
    complete: bool = True,
    oversized: bool = False,
) -> RawProfilePatch:
    headers = (
        (
            (b"origin", settings.bff_origin.encode()),
            (b"x-csrf-token", token.encode()),
            (b"sec-fetch-site", b"same-origin"),
            (b"if-match", b'"v1"'),
            (b"content-type", b"application/merge-patch+json; charset=UTF-8"),
            (b"content-length", str(len(body)).encode()),
        )
        if replace_headers is None
        else replace_headers
    )
    return RawProfilePatch(
        headers=(*headers, *extra_headers),
        query_string=query,
        body=body,
        body_complete=complete,
        body_oversized=oversized,
    )


def test_profile_patch_is_value_free_and_canonicalizes_one_member(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    settings = bff_settings_factory()
    token = opaque_session_id()
    raw = raw_patch(settings, token)

    require_csrf(raw, expected_origin=settings.bff_origin, expected_token=token)
    parsed = validate_profile_patch(raw)

    assert parsed.if_match == '"v1"'
    assert parsed.body == '{"display_name":"Caf\u00e9"}'.encode()
    assert token not in repr(raw)
    assert token not in repr(parsed)
    cleared = raw_patch(settings, token, body=b'{"display_name":null}')
    require_csrf(cleared, expected_origin=settings.bff_origin, expected_token=token)
    assert validate_profile_patch(cleared).body == b'{"display_name":null}'


@pytest.mark.parametrize(
    "headers",
    [
        (),
        ((b"origin", b"http://attacker.invalid"),),
        ((b"origin", b"http://localhost:8081"), (b"origin", b"http://localhost:8081")),
        ((b"origin", b"http://localhost:8081"), (b"x-csrf-token", b"short")),
        (
            (b"origin", b"http://localhost:8081"),
            (b"x-csrf-token", opaque_session_id().encode()),
        ),
        (
            (b"origin", b"http://localhost:8081"),
            (b"x-csrf-token", b"\xff"),
        ),
        (
            (b"origin", b"http://localhost:8081"),
            (b"x-csrf-token", b"Q" * 43),
            (b"x-csrf-token", b"Q" * 43),
        ),
        (
            (b"origin", b"http://localhost:8081"),
            (b"x-csrf-token", b"Q" * 43),
            (b"sec-fetch-site", b"cross-site"),
        ),
        (
            (b"origin", b"http://localhost:8081"),
            (b"x-csrf-token", b"Q" * 43),
            (b"sec-fetch-site", b"same-origin"),
            (b"sec-fetch-site", b"same-origin"),
        ),
    ],
)
def test_csrf_metadata_fails_closed_without_reflection(
    bff_settings_factory: Callable[..., Settings],
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    settings = bff_settings_factory()
    expected = "Q" * 43
    raw = raw_patch(settings, expected, replace_headers=headers)
    with pytest.raises(ProfilePatchFailure) as captured:
        require_csrf(raw, expected_origin=settings.bff_origin, expected_token=expected)
    assert (captured.value.status, captured.value.code) == (403, "csrf_failed")
    assert expected not in str(captured.value)


@pytest.mark.parametrize(
    ("raw_overrides", "status", "code"),
    [
        ({"query": b"x=1"}, 400, "bad_request"),
        ({"extra_headers": ((b"authorization", b"Bearer browser"),)}, 400, "bad_request"),
        ({"extra_headers": ((b"transfer-encoding", b"chunked"),)}, 400, "bad_request"),
        ({"complete": False}, 400, "bad_request"),
        ({"oversized": True}, 400, "bad_request"),
        ({"body": b""}, 400, "bad_request"),
        ({"extra_headers": ((b"content-length", b"1"),)}, 400, "bad_request"),
    ],
)
def test_profile_patch_rejects_framing_and_browser_authorization(
    bff_settings_factory: Callable[..., Settings],
    raw_overrides: dict[str, object],
    status: int,
    code: str,
) -> None:
    raw = raw_patch(bff_settings_factory(), "Q" * 43, **raw_overrides)  # type: ignore[arg-type]
    with pytest.raises(ProfilePatchFailure) as captured:
        validate_profile_patch(raw)
    assert (captured.value.status, captured.value.code) == (status, code)


@pytest.mark.parametrize(
    ("header_name", "header_values", "status", "code"),
    [
        ("content-type", (), 415, "unsupported_media_type"),
        ("content-type", (b"application/json",), 415, "unsupported_media_type"),
        (
            "content-type",
            (b"application/merge-patch+json", b"application/merge-patch+json"),
            415,
            "unsupported_media_type",
        ),
        ("if-match", (), 428, "precondition_required"),
        ("if-match", (b'W/"v1"',), 400, "invalid_precondition"),
        ("if-match", (b"*",), 400, "invalid_precondition"),
        ("if-match", (b'"v0"',), 400, "invalid_precondition"),
        ("if-match", (b'"v01"',), 400, "invalid_precondition"),
        ("if-match", (b' "v1"',), 400, "invalid_precondition"),
        ("if-match", (b'"v9223372036854775808"',), 400, "invalid_precondition"),
        ("if-match", (b'"v1"', b'"v1"'), 400, "invalid_precondition"),
    ],
)
def test_profile_patch_media_and_precondition_are_duplicate_sensitive(
    bff_settings_factory: Callable[..., Settings],
    header_name: str,
    header_values: tuple[bytes, ...],
    status: int,
    code: str,
) -> None:
    settings = bff_settings_factory()
    token = "Q" * 43
    raw = raw_patch(settings, token)
    headers = tuple(
        (name, value) for name, value in raw.headers if name.lower() != header_name.encode()
    ) + tuple((header_name.encode(), value) for value in header_values)
    changed = RawProfilePatch(
        headers=headers,
        query_string=raw.query_string,
        body=raw.body,
        body_complete=True,
        body_oversized=False,
    )
    with pytest.raises(ProfilePatchFailure) as captured:
        validate_profile_patch(changed)
    assert (captured.value.status, captured.value.code) == (status, code)


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        (b"{", 400, "bad_request"),
        (b'{"display_name":null,"display_name":null}', 400, "bad_request"),
        (b"[]", 400, "bad_request"),
        (b'{"other":null}', 422, "validation_failed"),
        (b'{"display_name":null,"other":null}', 422, "validation_failed"),
        (b'{"display_name":1}', 422, "validation_failed"),
        (b'{"display_name":"   "}', 422, "validation_failed"),
        (json.dumps({"display_name": "x" * 101}).encode(), 422, "validation_failed"),
        (json.dumps({"display_name": "bad\nname"}).encode(), 422, "validation_failed"),
        (json.dumps({"display_name": "\nname"}).encode(), 422, "validation_failed"),
        (json.dumps({"display_name": "bad\u2028name"}).encode(), 422, "validation_failed"),
        (json.dumps({"display_name": "bad\u2029name"}).encode(), 422, "validation_failed"),
        (rb'{"display_name":"\ud800"}', 422, "validation_failed"),
        (rb'{"display_name":"\udfff"}', 422, "validation_failed"),
    ],
)
def test_profile_patch_json_and_display_name_validation_is_exact(
    bff_settings_factory: Callable[..., Settings],
    body: bytes,
    status: int,
    code: str,
) -> None:
    raw = raw_patch(bff_settings_factory(), "Q" * 43, body=body)
    with pytest.raises(ProfilePatchFailure) as captured:
        validate_profile_patch(raw)
    assert (captured.value.status, captured.value.code) == (status, code)


def test_profile_patch_accepts_surrogate_pair_as_canonical_supplementary_utf8(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    raw = raw_patch(
        bff_settings_factory(),
        "Q" * 43,
        body=rb'{"display_name":"\ud83d\ude00"}',
    )

    parsed = validate_profile_patch(raw)

    assert parsed.body == b'{"display_name":"\xf0\x9f\x98\x80"}'
