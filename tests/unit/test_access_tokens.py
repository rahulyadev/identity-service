from __future__ import annotations

import json
import time
import warnings
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from identity_service.config import Settings
from identity_service.observability import Metrics
from identity_service.security import AccessTokenVerifier, JwksCache, UpstreamHttpClient
from identity_service.security.errors import (
    InsufficientScopeError,
    InvalidTokenError,
    TokenVerificationUnavailableError,
)
from tests.fixtures.fake_cognito import FakeCognito


def _raw_payload_token(fake: FakeCognito, payload_json: bytes) -> str:
    header = json.dumps(
        {"alg": "RS256", "kid": fake.active_kid, "typ": "JWT"},
        separators=(",", ":"),
    ).encode()
    return fake.compact_jws(header_json=header, payload_json=payload_json)


def _base_claims(fake: FakeCognito) -> dict[str, object]:
    now = int(time.time())
    return {
        "iss": fake.issuer,
        "sub": "opaque-Subject_1",
        "client_id": fake.client_id,
        "aud": fake.resource,
        "token_use": "access",
        "scope": f"openid {fake.read_scope} {fake.write_scope}",
        "exp": now + 3600,
        "iat": now,
        "auth_time": now - 10,
    }


def _integer_conversion_limit_token(fake: FakeCognito) -> str:
    claims = _base_claims(fake)
    claims.pop("exp")
    payload = (
        json.dumps(claims, separators=(",", ":")).encode()[:-1] + b',"exp":' + b"9" * 5000 + b"}"
    )
    return _raw_payload_token(fake, payload)


@contextmanager
def _stack(
    settings_factory: Callable[..., Settings],
    fake: FakeCognito,
    **overrides: object,
) -> Iterator[tuple[AccessTokenVerifier, JwksCache, UpstreamHttpClient, Metrics]]:
    values = fake.settings_overrides()
    values.update(overrides)
    settings = settings_factory(**values)
    metrics = Metrics()
    client = UpstreamHttpClient(settings, transport=fake.transport())
    cache = JwksCache(settings, client, metrics=metrics)
    verifier = AccessTokenVerifier(settings, cache, metrics=metrics)
    try:
        yield verifier, cache, client, metrics
    finally:
        cache.close()
        client.close()


def test_valid_access_token_produces_minimal_immutable_contract(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    raw_token = fake_cognito.token()
    with _stack(settings_factory, fake_cognito) as (verifier, _, _, metrics):
        verified = verifier.verify_access_token(raw_token, {fake_cognito.read_scope})
        rendered_metrics = metrics.render(type("Engine", (), {"pool": object()})())  # type: ignore[arg-type]
    assert verified.subject == "opaque-Subject_1"
    assert verified.client_id == fake_cognito.client_id
    assert verified.audience == frozenset({fake_cognito.resource})
    assert fake_cognito.read_scope in verified.scopes
    assert verified.not_before is None
    assert verified.key_id_fingerprint != fake_cognito.active_kid
    assert raw_token not in repr(verified)
    assert repr(verified) == "VerifiedAccessToken(<redacted>)"
    assert str(verified) == "VerifiedAccessToken(<redacted>)"
    for prohibited in (
        verified.issuer,
        verified.subject,
        verified.client_id,
        *verified.audience,
        *verified.scopes,
        verified.key_id_fingerprint,
    ):
        assert prohibited not in repr(verified)
        assert prohibited not in str(verified)
    assert b'outcome="valid"' in rendered_metrics


@pytest.mark.parametrize(
    ("headers", "algorithm"),
    [
        ({}, "none"),
        ({"alg": "none"}, "none"),
        ({"kid": None}, "RS256"),
        ({"kid": "k" * 129}, "RS256"),
        ({"jku": "https://attacker.invalid/keys"}, "RS256"),
        ({"x5u": "https://attacker.invalid/cert"}, "RS256"),
        ({"jwk": {"kty": "RSA"}}, "RS256"),
        ({"crit": ["unknown"]}, "RS256"),
        ({"typ": "not-a-jwt"}, "RS256"),
    ],
)
def test_token_header_policy_rejects_algorithm_and_key_location_input(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    headers: dict[str, object],
    algorithm: str,
) -> None:
    token = fake_cognito.token(headers=headers, algorithm=algorithm)
    with (
        _stack(settings_factory, fake_cognito) as (verifier, _, _, _),
        pytest.raises(InvalidTokenError),
    ):
        verifier.verify_access_token(token)


def test_token_header_accepts_compatible_type(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    token = fake_cognito.token(headers={"typ": "at+jwt"})
    with _stack(settings_factory, fake_cognito) as (verifier, _, _, _):
        assert verifier.verify_access_token(token).subject == "opaque-Subject_1"


@pytest.mark.parametrize(
    ("claims", "drop_claims", "outcome"),
    [
        ({"iss": "http://wrong.invalid/pool"}, (), "wrong_issuer"),
        ({"aud": "different-resource"}, (), "wrong_audience"),
        ({}, ("aud",), "malformed"),
        ({"client_id": "wrong-client"}, (), "wrong_client"),
        ({}, ("client_id",), "malformed"),
        ({"token_use": "id"}, (), "wrong_token_use"),
        ({}, ("token_use",), "malformed"),
        ({"scope": ""}, (), "malformed"),
        ({"scope": "openid openid"}, (), "malformed"),
        ({"scope": "openid  profile"}, (), "malformed"),
        ({"sub": ""}, (), "malformed"),
        ({}, ("sub",), "malformed"),
        ({"exp": "tomorrow"}, (), "malformed"),
        ({"iat": True}, (), "malformed"),
        ({"auth_time": False}, (), "malformed"),
        ({"nbf": "later"}, (), "malformed"),
    ],
)
def test_every_required_cognito_claim_is_strictly_validated(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    claims: dict[str, object],
    drop_claims: tuple[str, ...],
    outcome: str,
) -> None:
    token = fake_cognito.token(claims=claims, drop_claims=drop_claims)
    with (
        _stack(settings_factory, fake_cognito) as (verifier, _, _, _),
        pytest.raises(InvalidTokenError) as captured,
    ):
        verifier.verify_access_token(token)
    assert captured.value.outcome == outcome


def test_time_relationships_and_clock_skew_are_enforced(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    now = int(time.time())
    invalid_claims = (
        {"exp": now - 100},
        {"nbf": now + 100},
        {"iat": now + 100, "exp": now + 1000},
        {"iat": now, "exp": now},
        {"iat": now, "auth_time": now + 100},
    )
    with _stack(settings_factory, fake_cognito, jwt_clock_skew_seconds=1) as (
        verifier,
        _,
        _,
        _,
    ):
        for claims in invalid_claims:
            with pytest.raises(InvalidTokenError):
                verifier.verify_access_token(fake_cognito.token(claims=claims))


def test_audience_string_and_list_are_supported_but_resource_is_required(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    with _stack(settings_factory, fake_cognito) as (verifier, _, _, _):
        single = verifier.verify_access_token(fake_cognito.token())
        listed = verifier.verify_access_token(
            fake_cognito.token(claims={"aud": ["other", fake_cognito.resource]})
        )
        with pytest.raises(InvalidTokenError, match="invalid"):
            verifier.verify_access_token(fake_cognito.token(claims={"aud": ["other"]}))
    assert single.audience == frozenset({fake_cognito.resource})
    assert listed.audience == frozenset({"other", fake_cognito.resource})


def test_required_scope_policy_distinguishes_read_write_and_openid(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    token = fake_cognito.token(claims={"scope": f"openid {fake_cognito.read_scope}"})
    with _stack(settings_factory, fake_cognito) as (verifier, _, _, _):
        assert verifier.verify_access_token(token, {fake_cognito.read_scope}).subject
        with pytest.raises(InsufficientScopeError):
            verifier.verify_access_token(token, {fake_cognito.write_scope})


def test_non_uuid_subject_is_accepted_and_case_preserved(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    token = fake_cognito.token(claims={"sub": "Provider-Subject:CaseSensitive"})
    with _stack(settings_factory, fake_cognito) as (verifier, _, _, _):
        assert verifier.verify_access_token(token).subject == "Provider-Subject:CaseSensitive"


def test_unknown_claims_are_not_retained(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    token = fake_cognito.token(claims={"email": "not-retained@example.test", "unknown": {"x": 1}})
    with _stack(settings_factory, fake_cognito) as (verifier, _, _, _):
        verified = verifier.verify_access_token(token)
    assert not hasattr(verified, "email")
    assert not hasattr(verified, "unknown")


def test_bad_signature_and_unknown_key_are_distinct_safe_failures(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bad_signature = fake_cognito.token(signing_key=other_key)
    unknown_key = fake_cognito.token(key_id="absent-key")
    with _stack(settings_factory, fake_cognito) as (verifier, _, _, _):
        with pytest.raises(InvalidTokenError) as bad:
            verifier.verify_access_token(bad_signature)
        with pytest.raises(InvalidTokenError) as unknown:
            verifier.verify_access_token(unknown_key)
    assert bad.value.outcome == "bad_signature"
    assert unknown.value.outcome == "unknown_key"


def test_unknown_rotated_key_during_outage_is_dependency_unavailable(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    with _stack(settings_factory, fake_cognito) as (verifier, _, _, _):
        verifier.verify_access_token(fake_cognito.token())
        token = fake_cognito.token(key_id="possible-rotated-key")
        fake_cognito.jwks_status = 500
        with pytest.raises(TokenVerificationUnavailableError):
            verifier.verify_access_token(token)


def test_malformed_and_oversized_tokens_do_not_fetch_jwks(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    with _stack(settings_factory, fake_cognito, jwt_max_token_bytes=256) as (
        verifier,
        _,
        _,
        _,
    ):
        for token in ("malformed", "a." + "b" * 300 + ".c", "é.a.b"):
            with pytest.raises(InvalidTokenError):
                verifier.verify_access_token(token)
    assert fake_cognito.jwks_fetches == 0


@pytest.mark.parametrize(
    ("claim", "value", "outcome"),
    [
        ("exp", [], "malformed"),
        ("exp", {}, "malformed"),
        ("iat", [], "malformed"),
        ("iat", {}, "malformed"),
        ("nbf", [], "malformed"),
        ("nbf", {}, "malformed"),
        ("auth_time", [], "malformed"),
        ("auth_time", {}, "malformed"),
        ("exp", float("inf"), "malformed"),
        ("exp", float("-inf"), "malformed"),
        ("exp", float("nan"), "malformed"),
        ("exp", 10**100, "malformed"),
        ("exp", -(10**100), "expired"),
        ("iat", 10**100, "not_yet_valid"),
        ("iat", -(10**100), "malformed"),
        ("nbf", 10**100, "not_yet_valid"),
        ("nbf", -(10**100), "malformed"),
        ("auth_time", 10**100, "malformed"),
        ("auth_time", -(10**100), "malformed"),
    ],
)
def test_attacker_controlled_registered_claim_types_have_typed_outcomes(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    claim: str,
    value: object,
    outcome: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    token = fake_cognito.token(claims={claim: value})
    with _stack(settings_factory, fake_cognito) as (verifier, _, _, metrics):
        with pytest.raises(InvalidTokenError) as captured:
            verifier.verify_access_token(token)
        samples = [
            sample
            for metric in metrics.jwt_validation.collect()
            for sample in metric.samples
            if sample.name.endswith("_total") and sample.labels.get("outcome") == outcome
        ]
    assert captured.value.outcome == outcome
    assert len(samples) == 1 and samples[0].value == 1
    assert fake_cognito.userinfo_fetches == 0
    assert token not in caplog.text


@pytest.mark.parametrize(
    ("case", "token_factory", "expected_fetches"),
    [
        (
            "deep_header",
            lambda fake: fake.compact_jws(
                header_json=(
                    b'{"alg":"RS256","kid":"'
                    + fake.active_kid.encode()
                    + b'","nested":'
                    + b"[" * 1500
                    + b"0"
                    + b"]" * 1500
                    + b"}"
                ),
                payload_json=b"{}",
            ),
            0,
        ),
        (
            "malformed_header",
            lambda fake: fake.compact_jws(header_json=b'{"alg":', payload_json=b"{}"),
            0,
        ),
        (
            "deep_payload",
            lambda fake: _raw_payload_token(
                fake,
                b'{"nested":' + b"[" * 1500 + b"0" + b"]" * 1500 + b"}",
            ),
            0,
        ),
        (
            "malformed_payload",
            lambda fake: _raw_payload_token(fake, b'{"exp":'),
            1,
        ),
        (
            "integer_conversion_limit",
            _integer_conversion_limit_token,
            1,
        ),
    ],
)
def test_malformed_signed_json_has_typed_boundary_and_bounded_side_effects(
    settings_factory: Callable[..., Settings],
    fake_cognito: FakeCognito,
    case: str,
    token_factory: Callable[[FakeCognito], str],
    expected_fetches: int,
    caplog: pytest.LogCaptureFixture,
) -> None:
    del case
    token = token_factory(fake_cognito)
    with _stack(settings_factory, fake_cognito) as (verifier, _, _, metrics):
        with pytest.raises(InvalidTokenError) as captured:
            verifier.verify_access_token(token)
        samples = [
            sample
            for metric in metrics.jwt_validation.collect()
            for sample in metric.samples
            if sample.name.endswith("_total") and sample.labels.get("outcome") == "malformed"
        ]
    assert captured.value.outcome == "malformed"
    assert fake_cognito.jwks_fetches == expected_fetches
    assert fake_cognito.userinfo_fetches == 0
    assert len(samples) == 1 and samples[0].value == 1
    assert token not in caplog.text


def test_json_depth_prescan_ignores_structural_characters_inside_strings(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    token = fake_cognito.token(claims={"ignored": "[" * 200 + "}" * 200})
    with _stack(settings_factory, fake_cognito) as (verifier, _, _, _):
        assert verifier.verify_access_token(token).subject == "opaque-Subject_1"


def test_decode_enforces_minimum_key_length_and_maps_key_invariant_failure(
    settings_factory: Callable[..., Settings], fake_cognito: FakeCognito
) -> None:
    token = fake_cognito.token()
    with _stack(settings_factory, fake_cognito) as (verifier, _, _, metrics):
        original_decode = jwt.decode
        observed: dict[str, object] = {}

        def capture_options(*args: object, **kwargs: object) -> object:
            observed.update(kwargs.get("options", {}))  # type: ignore[arg-type]
            return original_decode(*args, **kwargs)  # type: ignore[arg-type]

        with (
            patch("identity_service.security.tokens.jwt.decode", side_effect=capture_options),
            warnings.catch_warnings(record=True) as caught,
        ):
            assert verifier.verify_access_token(token).subject == "opaque-Subject_1"
        assert observed["enforce_minimum_key_length"] is True
        assert not [warning for warning in caught if "key" in str(warning.message).casefold()]

        with (
            patch(
                "identity_service.security.tokens.jwt.decode",
                side_effect=jwt.InvalidKeyError("test-only verification material detail"),
            ),
            pytest.raises(TokenVerificationUnavailableError) as captured,
        ):
            verifier.verify_access_token(token)
    assert "test-only" not in str(captured.value)
    rendered = metrics.render(type("Engine", (), {"pool": object()})())  # type: ignore[arg-type]
    assert b'outcome="dependency_unavailable"' in rendered
