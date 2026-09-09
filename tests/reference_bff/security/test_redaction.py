from __future__ import annotations

import base64
import io
import json
import logging
import sys
from collections.abc import Callable

import pytest
from pydantic import ValidationError
from reference_bff.auth_diagnostics import (
    CALLBACK_REJECTION_EVENT,
    CallbackRejection,
    CallbackRequestId,
)
from reference_bff.auth_diagnostics import TokenFailureCategory as Category
from reference_bff.config import Settings
from reference_bff.logging import JsonFormatter, RedactingFilter, TextFormatter, configure_logging

from tests.http_client import ASGIClient
from tests.reference_bff.contract.test_callback_vertical_slice import (
    CountingStore,
    assert_rejection,
    diagnostic_app,
)
from tests.reference_bff.unit.test_auth_diagnostics import independent_provider
from tests.reference_bff.unit.test_tokens import resign

SYNTHETIC_UUID = "0" * 12 + "40008000" + "0" * 12
SYNTHETIC_TOKEN_ID = ".".join(
    base64.urlsafe_b64encode(part).rstrip(b"=").decode()
    for part in (b'{"alg":"RS256"}', b'{"sub":"synthetic"}', b"sig")
)


def test_log_filter_redacts_oauth_and_credential_url_material() -> None:
    username = "user"
    credential = "password"
    sensitive_message = (
        f"state=sensitive-state redis://{username}:{credential}@cache.invalid/0 "
        "client_secret=secret access_token=synthetic-access id_token=synthetic-id "
        "refresh_token=synthetic-refresh code=synthetic-code subject=synthetic-subject "
        "session_id=synthetic-session csrf_token=synthetic-csrf "
        "X-CSRF-Token=synthetic-header-csrf __Host-oauth=synthetic-binding"
    )
    record = logging.LogRecord(
        "reference_bff.test",
        logging.ERROR,
        __file__,
        1,
        sensitive_message,
        (),
        None,
    )
    assert RedactingFilter().filter(record)
    rendered = record.getMessage()
    assert "sensitive-state" not in rendered
    assert "password" not in rendered
    assert "client_secret=secret" not in rendered
    assert "synthetic-access" not in rendered
    assert "synthetic-id" not in rendered
    assert "synthetic-refresh" not in rendered
    assert "synthetic-code" not in rendered
    assert "synthetic-subject" not in rendered
    assert "synthetic-session" not in rendered
    assert "synthetic-binding" not in rendered
    assert "synthetic-csrf" not in rendered
    assert "synthetic-header-csrf" not in rendered
    assert "[REDACTED]" in rendered


def test_invalid_secret_bearing_settings_never_render_input(
    bff_settings_factory: Callable[..., Settings],
) -> None:
    sentinel = "never-render-validation-secret"  # pragma: allowlist secret
    try:
        bff_settings_factory(
            redis_url=f"redis://user:{sentinel}@cache.invalid/not-a-database",
            client_secret=sentinel,
        )
    except ValidationError as error:
        rendered = str(error)
    else:
        raise AssertionError("invalid settings were accepted")
    assert sentinel not in rendered


class HostileDiagnostic:
    def __str__(self):
        raise AssertionError("diagnostic object must not be stringified")

    def __repr__(self):
        raise AssertionError("diagnostic object must not be represented")

    def __eq__(self, other):
        raise AssertionError("diagnostic object must not be compared")


@pytest.mark.parametrize("mode", ["json", "console"])
@pytest.mark.parametrize("filtered", [False, True])
@pytest.mark.parametrize(
    "variant",
    [
        "valid",
        "malformed-category",
        "string-category",
        "raw-id",
        "malformed-event",
        "missing-event",
        "object-id",
    ],
)
def test_diagnostic_allowlist_precedes_formatting_and_never_serializes_hostile_values(
    bff_settings_factory, mode, filtered, variant
):
    settings = bff_settings_factory(log_format=mode)
    correlation = CallbackRequestId()
    diagnostic = CallbackRejection(Category.ID_NONCE, correlation)
    if variant == "malformed-category":
        diagnostic = CallbackRejection(HostileDiagnostic(), correlation)
    elif variant == "string-category":
        diagnostic = CallbackRejection("id_nonce", correlation)
    elif variant == "raw-id":
        diagnostic = CallbackRejection(Category.ID_NONCE, SYNTHETIC_UUID)
    elif variant == "object-id":
        diagnostic = CallbackRejection(Category.ID_NONCE, HostileDiagnostic())
    elif variant == "malformed-event":
        diagnostic = HostileDiagnostic()
    sentinel = "DO-NOT-EMIT-synthetic.person@example.invalid\r\nforged-event"
    try:
        raise RuntimeError(sentinel)
    except RuntimeError:
        info = sys.exc_info()
    record = logging.LogRecord(
        sentinel, logging.WARNING, sentinel, 123, HostileDiagnostic(), (HostileDiagnostic(),), info
    )
    record.stack_info = sentinel
    record.exc_text = sentinel
    record.levelname = sentinel
    record.request_id = sentinel
    record.token_time = 123456789012345678
    record.claims = {"sub": sentinel, "email": sentinel}
    record.provider_body = HostileDiagnostic()
    if variant == "missing-event":
        record.msg = CALLBACK_REJECTION_EVENT
    else:
        record.callback_rejection = diagnostic
    if filtered:
        assert RedactingFilter().filter(record)
    formatter = JsonFormatter(settings) if mode == "json" else TextFormatter(settings)
    output = formatter.format(record)
    assert "DO-NOT-EMIT" not in output
    assert "example.invalid" not in output
    assert "123456789012345678" not in output
    assert "forged-event" not in output
    assert SYNTHETIC_UUID not in output
    assert "\r" not in output and "\n" not in output
    record_fields = (
        json.loads(output) if mode == "json" else dict(x.split("=", 1) for x in output.split())
    )
    assert set(record_fields) == {
        "timestamp",
        "level",
        "logger",
        "event",
        "service",
        "service_version",
        "environment",
        "category",
        "request_id",
    }
    assert record_fields["event"] == CALLBACK_REJECTION_EVENT
    expected_category = (
        "verification"
        if variant in {"malformed-category", "string-category", "malformed-event", "missing-event"}
        else "id_nonce"
    )
    assert record_fields["category"] == expected_category
    expected_id = (
        correlation.value
        if variant in {"valid", "malformed-category", "string-category"}
        else "unavailable"
    )
    assert record_fields["request_id"] == expected_id


@pytest.mark.parametrize("mode", ["json", "console"])
@pytest.mark.parametrize(
    "caller_id",
    [
        SYNTHETIC_TOKEN_ID,
        "synthetic.person.example.invalid",
        SYNTHETIC_UUID,
        "injected\r\nX-Forged: private-value",
    ],
)
def test_real_http_ignores_hostile_correlation_and_claim_values(
    bff_settings_factory, mode, caller_id
):
    settings = bff_settings_factory(log_format=mode)
    provider = independent_provider(settings)
    store = CountingStore(settings)
    app = diagnostic_app(settings, store, provider)
    stream = io.StringIO()
    configure_logging(settings, stream=stream)
    with ASGIClient(app) as client:
        client.get("/auth/login")
        transaction = store.transactions[0]
        provider.configure(transaction)
        provider.id_token = resign(
            provider.id_token,
            provider.private_key,
            update={
                "nonce": "private-nonce-sentinel",
                "email": "private-person@example.invalid",
                "name": "Private Person Sentinel",
                "identities": [{"userId": "private-id-sentinel"}],
                "custom:time": 123456789012345678,
            },
        )
        response = client.get(
            f"/auth/callback?code={provider.code}&state={transaction.state}",
            headers=[
                ("cookie", f"__Host-oauth={transaction.transaction_id}"),
                ("X-Request-ID", caller_id),
            ],
        )
    output = stream.getvalue()
    assert_rejection(response, output, mode, Category.ID_NONCE)
    combined = output + response.text + str(response.headers)
    for forbidden in (
        caller_id,
        "private-nonce-sentinel",
        "private-person@example.invalid",
        "Private Person Sentinel",
        "private-id-sentinel",
        "123456789012345678",
        provider.id_token,
        provider.access_token,
        provider.refresh_token,
        transaction.state,
        transaction.nonce,
        transaction.pkce_verifier,
    ):
        assert forbidden not in combined
    assert store.session_records == []
    assert provider.events == ["token", "jwks"]
