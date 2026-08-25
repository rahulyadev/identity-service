from __future__ import annotations

from urllib.parse import quote

import pytest
from reference_bff.return_targets import (
    InvalidReturnTargetError,
    canonical_local_return_target,
    return_target_from_query,
)


@pytest.mark.parametrize(
    "target",
    ["/", "/profile", "/profile/", "/profile/settings?tab=privacy", "/café?q=one two"],
)
def test_canonical_local_targets_round_trip_through_outer_query(target: str) -> None:
    assert canonical_local_return_target(target) == target
    query = f"return_to={quote(target, safe='')}".encode()
    assert return_target_from_query(query) == target


def test_missing_return_target_defaults_to_root() -> None:
    assert return_target_from_query(b"") == "/"


@pytest.mark.parametrize(
    "target",
    [
        "",
        "relative",
        "https://evil.invalid/path",
        "//evil.invalid/path",
        "/\\evil.invalid/path",
        "/path#fragment",
        "/%2F%2Fevil.invalid",
        "/%5Cevil.invalid",
        "/a/../b",
        "/a/./b",
        "/a//b",
        "/control\x00value",
        "/control\nvalue",
        "/" + "x" * 4097,
        "/e\u0301",
    ],
)
def test_return_target_rejects_open_redirect_and_noncanonical_attacks(target: str) -> None:
    with pytest.raises(InvalidReturnTargetError):
        canonical_local_return_target(target)


@pytest.mark.parametrize("character", ["\u0085", "\u009f", "\u200b", "\u202e"])
def test_return_target_rejects_unicode_controls_and_format_characters(
    character: str,
) -> None:
    target = f"/profile{character}settings"
    with pytest.raises(InvalidReturnTargetError):
        canonical_local_return_target(target)
    query = f"return_to={quote(target, safe='')}".encode()
    with pytest.raises(InvalidReturnTargetError):
        return_target_from_query(query)


@pytest.mark.parametrize(
    "query",
    [
        b"return_to=",
        b"other=%2F",
        b"return_to=%2F&other=1",
        b"return_to=%2F&return_to=%2Fprofile",
        b"return_to=/profile",
        b"return_to=%2fprofile",
        b"return_to=%252F%252Fevil.invalid",
        b"return_to=%FF",
        b"return_to=+%2Fprofile",
        b"return_to=%2Fprofile%23fragment",
        b"return_to=%2F%2Fevil.invalid",
        b"return_to=%2F%5Cevil.invalid",
    ],
)
def test_query_extraction_rejects_duplicates_invalid_encoding_and_authority_confusion(
    query: bytes,
) -> None:
    with pytest.raises(InvalidReturnTargetError):
        return_target_from_query(query)


def test_query_extraction_rejects_non_ascii_and_predecode_size_bounds() -> None:
    with pytest.raises(InvalidReturnTargetError):
        return_target_from_query(b"return_to=/\xff")
    with pytest.raises(InvalidReturnTargetError):
        return_target_from_query(b"return_to=" + b"x" * 500, max_bytes=128)
    with pytest.raises(InvalidReturnTargetError):
        canonical_local_return_target("/\ud800")
