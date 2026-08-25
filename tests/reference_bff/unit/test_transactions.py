from __future__ import annotations

import json

import pytest
from reference_bff.transactions import (
    OPAQUE_TOKEN,
    PKCE_VERIFIER,
    ExpiredTransactionError,
    MalformedTransactionError,
    new_transaction,
    parse_consumed_transaction,
    pkce_s256_challenge,
)


def test_published_rfc7636_s256_vector() -> None:
    verifier = "".join(("dBjftJeZ4C", "VP-mB92K27", "uhbUJU1p1r", "_wW1gFWFOE", "jXk"))
    expected = "".join(("E9Melhoa2O", "wvFrEMTJgu", "CHaoeK1t8U", "RWbuGJSstw", "-cM"))
    assert pkce_s256_challenge(verifier) == expected


def test_transaction_values_are_independent_bounded_and_versioned() -> None:
    transactions = [
        new_transaction(
            return_to="/profile?tab=security",
            callback_uri="http://localhost:8081/auth/callback",
            ttl_seconds=300,
            now=1_900_000_000,
        )
        for _ in range(50)
    ]
    assert len({transaction.state for transaction in transactions}) == 50
    assert len({transaction.nonce for transaction in transactions}) == 50
    assert len({transaction.transaction_id for transaction in transactions}) == 50
    assert len({transaction.pkce_verifier for transaction in transactions}) == 50
    assert all(OPAQUE_TOKEN.fullmatch(transaction.state) for transaction in transactions)
    assert all(OPAQUE_TOKEN.fullmatch(transaction.nonce) for transaction in transactions)
    assert all(OPAQUE_TOKEN.fullmatch(transaction.transaction_id) for transaction in transactions)
    assert all(PKCE_VERIFIER.fullmatch(transaction.pkce_verifier) for transaction in transactions)
    assert all(len(transaction.code_challenge) == 43 for transaction in transactions)
    assert all(
        transaction.expires_at - transaction.created_at == 300 for transaction in transactions
    )


def test_record_contains_only_the_bounded_transaction_contract() -> None:
    transaction = new_transaction(
        return_to="/",
        callback_uri="http://localhost:8081/auth/callback",
        ttl_seconds=300,
        now=1_900_000_000,
    )
    document = json.loads(transaction.as_json_bytes())
    assert set(document) == {
        "version",
        "transaction_id",
        "state",
        "nonce",
        "pkce_verifier",
        "return_to",
        "created_at",
        "expires_at",
        "callback_uri",
    }
    assert "secret" not in document
    rendered = repr(transaction)
    assert rendered == "AuthorizationTransaction(<redacted>)"
    assert all(str(value) not in rendered for value in document.values())
    assert (
        parse_consumed_transaction(
            transaction.as_json_bytes(),
            expected_state=transaction.state,
            expected_callback_uri=transaction.callback_uri,
            expected_ttl_seconds=300,
            now=1_900_000_001,
        )
        == transaction
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda record: record.update(version=2),
        lambda record: record.update(created_at=True),
        lambda record: record.update(expires_at=record["created_at"] + 301),
        lambda record: record.update(callback_uri="http://evil.invalid/auth/callback"),
        lambda record: record.update(return_to="//evil.invalid"),
        lambda record: record.update(state=42),
        lambda record: record.update(extra="value"),
        lambda record: record.pop("nonce"),
    ],
)
def test_parser_rejects_wrong_version_fields_types_and_boundaries(mutation: object) -> None:
    transaction = new_transaction(
        return_to="/",
        callback_uri="http://localhost:8081/auth/callback",
        ttl_seconds=300,
        now=1_900_000_000,
    )
    record = json.loads(transaction.as_json_bytes())
    mutation(record)  # type: ignore[operator]
    with pytest.raises(MalformedTransactionError):
        parse_consumed_transaction(
            json.dumps(record).encode(),
            expected_state=transaction.state,
            expected_callback_uri=transaction.callback_uri,
            expected_ttl_seconds=300,
            now=1_900_000_001,
        )


def test_parser_uses_constant_state_match_and_rejects_expiry() -> None:
    transaction = new_transaction(
        return_to="/",
        callback_uri="http://localhost:8081/auth/callback",
        ttl_seconds=300,
        now=1_900_000_000,
    )
    with pytest.raises(MalformedTransactionError):
        parse_consumed_transaction(
            transaction.as_json_bytes(),
            expected_state="A" * 43,
            expected_callback_uri=transaction.callback_uri,
            expected_ttl_seconds=300,
            now=1_900_000_001,
        )
    with pytest.raises(ExpiredTransactionError):
        parse_consumed_transaction(
            transaction.as_json_bytes(),
            expected_state=transaction.state,
            expected_callback_uri=transaction.callback_uri,
            expected_ttl_seconds=300,
            now=transaction.expires_at,
        )


def test_primitive_input_bounds_reject_invalid_pkce_and_lifetime() -> None:
    with pytest.raises(ValueError, match="PKCE"):
        pkce_s256_challenge("too-short")
    with pytest.raises(ValueError, match="lifetime"):
        new_transaction(
            return_to="/",
            callback_uri="http://localhost:8081/auth/callback",
            ttl_seconds=601,
        )
