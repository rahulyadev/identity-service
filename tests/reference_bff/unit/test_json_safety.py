from __future__ import annotations

import pytest
from reference_bff.json_safety import UnsafeJsonError, load_json, load_json_object


def test_safe_json_accepts_bounded_exact_objects() -> None:
    assert load_json_object(b'{"value":1,"nested":{"items":[true,null,"text"]}}') == {
        "value": 1,
        "nested": {"items": [True, None, "text"]},
    }


@pytest.mark.parametrize(
    "document",
    [
        b'{"value":1,"value":2}',
        b'{"value":1.5}',
        b'{"value":NaN}',
        b'{"value":123456789012345678901}',
        b'{"value":',
        b"\xff",
        b"[]",
    ],
)
def test_object_parser_rejects_duplicates_numeric_abuse_malformed_and_wrong_topology(
    document: bytes,
) -> None:
    with pytest.raises(UnsafeJsonError):
        load_json_object(document)


def test_json_parser_rejects_excessive_nesting_items_and_strings() -> None:
    with pytest.raises(UnsafeJsonError):
        load_json(b"[" * 40 + b"0" + b"]" * 40)
    with pytest.raises(UnsafeJsonError):
        load_json(("[" + ",".join("0" for _ in range(600)) + "]").encode())
    with pytest.raises(UnsafeJsonError):
        load_json(('"' + "x" * 65_537 + '"').encode())
