from __future__ import annotations

import unicodedata
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from identity_service.services.schemas import ProviderIdentityInput, ProviderProfileInput
from identity_service.services.validation import (
    normalize_display_name_override,
    normalize_provider_name,
)

AUTH_URL = "https://u:p@cdn.invalid/a"  # pragma: allowlist secret (test fixture)


def test_subject_is_opaque_non_uuid_text_and_is_not_normalized() -> None:
    value = ProviderIdentityInput(
        issuer="HTTPS://Issuer/Exact",
        subject="Not-A-UUID Subject",
        auth_time=datetime.now(UTC),
    )
    assert value.issuer == "HTTPS://Issuer/Exact"
    assert value.subject == "Not-A-UUID Subject"


@pytest.mark.parametrize(
    ("field", "value"), [("issuer", ""), ("subject", ""), ("subject", "x" * 256)]
)
def test_provider_identity_bounds(field: str, value: str) -> None:
    data = {"issuer": "issuer", "subject": "subject"}
    data[field] = value
    with pytest.raises(ValidationError):
        ProviderIdentityInput(**data)


def test_auth_time_must_be_timezone_aware() -> None:
    with pytest.raises(ValidationError):
        ProviderIdentityInput(issuer="issuer", subject="subject", auth_time=datetime.now())


def test_provider_boolean_is_strict() -> None:
    with pytest.raises(ValidationError):
        ProviderProfileInput(email_verified="true")  # type: ignore[arg-type]


def test_missing_email_cannot_be_verified() -> None:
    with pytest.raises(ValidationError):
        ProviderProfileInput(email=None, email_verified=True)
    snapshot = ProviderProfileInput(email=None, email_verified=False)
    assert snapshot.email is None
    assert snapshot.email_verified is False


def test_names_are_trimmed_and_normalized_to_nfc() -> None:
    decomposed = "  Jose\u0301  "
    profile = ProviderProfileInput(display_name=decomposed)
    assert profile.display_name == unicodedata.normalize("NFC", decomposed).strip()
    assert normalize_display_name_override(decomposed) == "José"


@pytest.mark.parametrize(
    "value",
    [
        "line\nbreak",
        "\nleading",
        "trailing\n",
        "carriage\rreturn",
        "control\x00value",
        "line\u2028break",
    ],
)
def test_names_reject_controls_and_line_breaks(value: str) -> None:
    with pytest.raises(ValidationError):
        ProviderProfileInput(display_name=value)
    with pytest.raises(ValueError):
        normalize_display_name_override(value)


def test_name_code_point_boundary_and_empty_behavior() -> None:
    assert normalize_provider_name("x" * 100) == "x" * 100
    with pytest.raises(ValueError):
        normalize_provider_name("x" * 101)
    assert normalize_provider_name("  ") is None
    with pytest.raises(ValueError):
        normalize_display_name_override("  ")
    assert normalize_display_name_override(None) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://cdn.invalid/avatar.png", "https://cdn.invalid/avatar.png"),
        ("https://cdn.invalid:8443/avatar.png", "https://cdn.invalid:8443/avatar.png"),
        ("http://cdn.invalid/avatar.png", None),
        (AUTH_URL, None),
        ("https://bad host/avatar.png", None),
        ("https://cdn.invalid/avatar image.png", None),
        ("not-a-url", None),
        ("", None),
    ],
)
def test_avatar_policy_stores_only_valid_credential_free_https(
    value: str, expected: str | None
) -> None:
    assert ProviderProfileInput(avatar_url=value).avatar_url == expected


def test_avatar_and_email_length_limits() -> None:
    assert (
        ProviderProfileInput(avatar_url="https://example.invalid/" + "x" * 3000).avatar_url is None
    )
    with pytest.raises(ValidationError):
        ProviderProfileInput(email="x" * 321)
    with pytest.raises(ValidationError):
        ProviderProfileInput(email="")
    assert ProviderProfileInput(email="x" * 320).email == "x" * 320
