"""Raw, duplicate-sensitive CSRF and profile-patch request validation."""

from __future__ import annotations

import json
import re
import secrets
import unicodedata
from dataclasses import dataclass, field

from reference_bff.json_safety import UnsafeJsonError, load_json_object
from reference_bff.sessions import is_canonical_session_id

MAX_PROFILE_PATCH_BYTES = 4096
MAX_PROFILE_VERSION = 9_223_372_036_854_775_807
STRONG_IF_MATCH = re.compile(r'"v([1-9][0-9]{0,18})"')
CANONICAL_CONTENT_LENGTH = re.compile(rb"0|[1-9][0-9]{0,3}")


@dataclass(frozen=True, slots=True)
class ProfilePatchError(Exception):
    status: int
    code: str


ProfilePatchFailure = ProfilePatchError


@dataclass(frozen=True, slots=True, repr=False)
class RawProfilePatch:
    headers: tuple[tuple[bytes, bytes], ...] = field(repr=False)
    query_string: bytes = field(repr=False)
    body: bytes = field(repr=False)
    body_complete: bool
    body_oversized: bool

    def __repr__(self) -> str:
        return "RawProfilePatch(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ValidatedProfilePatch:
    if_match: str
    body: bytes = field(repr=False)

    def __repr__(self) -> str:
        return "ValidatedProfilePatch(<redacted>)"


def _header_values(raw: RawProfilePatch, name: bytes) -> list[bytes]:
    return [value for candidate, value in raw.headers if candidate.lower() == name]


def require_csrf(
    raw: RawProfilePatch,
    *,
    expected_origin: str,
    expected_token: str,
) -> None:
    origins = _header_values(raw, b"origin")
    tokens = _header_values(raw, b"x-csrf-token")
    fetch_sites = _header_values(raw, b"sec-fetch-site")
    if len(origins) != 1 or origins[0] != expected_origin.encode("ascii"):
        raise ProfilePatchFailure(403, "csrf_failed")
    if len(tokens) != 1:
        raise ProfilePatchFailure(403, "csrf_failed")
    try:
        token = tokens[0].decode("ascii", errors="strict")
    except UnicodeError:
        raise ProfilePatchFailure(403, "csrf_failed") from None
    if not is_canonical_session_id(token) or not secrets.compare_digest(token, expected_token):
        raise ProfilePatchFailure(403, "csrf_failed")
    if len(fetch_sites) > 1 or (fetch_sites and fetch_sites[0] != b"same-origin"):
        raise ProfilePatchFailure(403, "csrf_failed")


def validate_profile_patch(raw: RawProfilePatch) -> ValidatedProfilePatch:
    if (
        raw.query_string
        or _header_values(raw, b"authorization")
        or _header_values(raw, b"transfer-encoding")
    ):
        raise ProfilePatchFailure(400, "bad_request")
    if not raw.body_complete or raw.body_oversized or not raw.body:
        raise ProfilePatchFailure(400, "bad_request")

    lengths = _header_values(raw, b"content-length")
    if len(lengths) > 1:
        raise ProfilePatchFailure(400, "bad_request")
    if lengths:
        value = lengths[0]
        if CANONICAL_CONTENT_LENGTH.fullmatch(value) is None or int(value) != len(raw.body):
            raise ProfilePatchFailure(400, "bad_request")
    if len(raw.body) > MAX_PROFILE_PATCH_BYTES:
        raise ProfilePatchFailure(400, "bad_request")

    content_types = _header_values(raw, b"content-type")
    if len(content_types) != 1:
        raise ProfilePatchFailure(415, "unsupported_media_type")
    try:
        content_type = content_types[0].decode("ascii", errors="strict")
    except UnicodeError:
        raise ProfilePatchFailure(415, "unsupported_media_type") from None
    parts = [part.strip().casefold() for part in content_type.split(";")]
    if parts[0] != "application/merge-patch+json" or (
        len(parts) != 1 and not (len(parts) == 2 and parts[1] == "charset=utf-8")
    ):
        raise ProfilePatchFailure(415, "unsupported_media_type")

    preconditions = _header_values(raw, b"if-match")
    if not preconditions:
        raise ProfilePatchFailure(428, "precondition_required")
    if len(preconditions) != 1:
        raise ProfilePatchFailure(400, "invalid_precondition")
    try:
        if_match = preconditions[0].decode("ascii", errors="strict")
    except UnicodeError:
        raise ProfilePatchFailure(400, "invalid_precondition") from None
    match = STRONG_IF_MATCH.fullmatch(if_match)
    if match is None or int(match.group(1)) > MAX_PROFILE_VERSION:
        raise ProfilePatchFailure(400, "invalid_precondition")

    try:
        document = load_json_object(raw.body)
    except UnsafeJsonError:
        raise ProfilePatchFailure(400, "bad_request") from None
    if set(document) != {"display_name"}:
        raise ProfilePatchFailure(422, "validation_failed")
    display_name = document["display_name"]
    if display_name is not None:
        if type(display_name) is not str:
            raise ProfilePatchFailure(422, "validation_failed")
        display_name = unicodedata.normalize("NFC", display_name)
        if any(unicodedata.category(character) in {"Cc", "Zl", "Zp"} for character in display_name):
            raise ProfilePatchFailure(422, "validation_failed")
        display_name = display_name.strip()
        if not display_name or len(display_name) > 100:
            raise ProfilePatchFailure(422, "validation_failed")
        try:
            display_name.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise ProfilePatchFailure(422, "validation_failed") from None
    canonical = json.dumps(
        {"display_name": display_name},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return ValidatedProfilePatch(if_match=if_match, body=canonical)
