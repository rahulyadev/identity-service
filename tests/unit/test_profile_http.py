from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from starlette.requests import Request

from identity_service.api.authentication import AuthenticatedAccess
from identity_service.api.problems import PublicProblemError
from identity_service.api.profile import (
    ProfileResponse,
    _parse_display_name_patch,
    _parse_if_match,
    _validate_patch_media_type,
)
from identity_service.security.contracts import VerifiedAccessToken
from identity_service.services.schemas import ProfileView


def _request(*, headers: list[tuple[bytes, bytes]] | None = None, body: bytes = b"") -> Request:
    return Request(
        {
            "type": "http",
            "method": "PATCH",
            "path": "/v1/me",
            "headers": headers or [],
            "identity_service.body": body,
        }
    )


def test_if_match_parser_accepts_only_positive_signed_int64() -> None:
    assert _parse_if_match(_request(headers=[(b"if-match", b'"v1"')])) == 1
    assert (
        _parse_if_match(_request(headers=[(b"if-match", b'"v9223372036854775807"')]))
        == 9223372036854775807
    )
    with pytest.raises(PublicProblemError) as missing:
        _parse_if_match(_request())
    assert missing.value.code == "precondition_required"
    with pytest.raises(PublicProblemError) as invalid:
        _parse_if_match(_request(headers=[(b"if-match", b'"v01"')]))
    assert invalid.value.code == "invalid_precondition"
    with pytest.raises(PublicProblemError) as oversized:
        _parse_if_match(_request(headers=[(b"if-match", ('"v' + "9" * 5000 + '"').encode())]))
    assert oversized.value.code == "invalid_precondition"


def test_patch_media_type_accepts_case_insensitive_base_with_parameters() -> None:
    _validate_patch_media_type(
        _request(headers=[(b"content-type", b"Application/Merge-Patch+Json; charset=utf-8")])
    )
    with pytest.raises(PublicProblemError) as error:
        _validate_patch_media_type(_request(headers=[(b"content-type", b"application/json")]))
    assert error.value.code == "unsupported_media_type"


def test_display_name_patch_parser_is_duplicate_sensitive_and_normalizes() -> None:
    assert (
        _parse_display_name_patch(_request(body=b'{"display_name":"  Local Name  "}'))
        == "Local Name"
    )
    assert _parse_display_name_patch(_request(body=b'{"display_name":null}')) is None
    with pytest.raises(PublicProblemError) as duplicate:
        _parse_display_name_patch(_request(body=b'{"display_name":"A","display_name":"B"}'))
    assert duplicate.value.code == "validation_failed"


def test_authenticated_access_string_forms_are_redacted() -> None:
    now = datetime.now(UTC)
    verified = VerifiedAccessToken(
        issuer="issuer-sentinel",
        subject="subject-sentinel",
        client_id="client-sentinel",
        audience=frozenset({"audience-sentinel"}),
        scopes=frozenset({"scope-sentinel"}),
        issued_at=now,
        expires_at=now,
        auth_time=now,
        not_before=None,
        key_id_fingerprint="key-sentinel",
    )
    access = AuthenticatedAccess("token-sentinel", verified)
    assert repr(access) == str(access) == "AuthenticatedAccess(<redacted>)"
    for sentinel in ("token", "issuer", "subject", "client", "scope", "key"):
        assert sentinel not in repr(access).casefold()


def test_profile_response_maps_only_external_effective_fields() -> None:
    now = datetime.now(UTC)
    view = ProfileView(
        user_id=uuid.uuid4(),
        provider_email="person@example.test",
        provider_email_verified=True,
        provider_display_name="Provider",
        provider_avatar_url="https://images.example.test/avatar.png",
        display_name_override="Local",
        effective_display_name="Local",
        version=3,
        created_at=now,
        updated_at=now,
    )
    response = ProfileResponse.from_view(view).model_dump(mode="json")
    assert set(response) == {
        "user_id",
        "email",
        "email_verified",
        "display_name",
        "avatar_url",
        "version",
        "created_at",
        "updated_at",
    }
    assert response["display_name"] == "Local"
    assert "provider_email" not in response
