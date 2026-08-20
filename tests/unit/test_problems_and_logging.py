from __future__ import annotations

import io
import json
import logging
import uuid
from collections.abc import Callable, Iterator

import pytest

from identity_service.api.middleware import valid_request_id
from identity_service.api.problems import PROBLEM_MEDIA_TYPE, problem_response
from identity_service.app import create_app
from identity_service.config import Settings
from identity_service.observability.logging import (
    COMMON_JSON_FIELDS,
    JsonFormatter,
    RedactingFilter,
    configure_logging,
    redact_value,
)
from tests.http_client import ASGIClient


@pytest.fixture(autouse=True)
def preserve_logging_topology() -> Iterator[None]:
    root = logging.getLogger()
    root_handlers = list(root.handlers)
    root_level = root.level
    logger_names = (
        "identity_service",
        "identity_service.http",
        "uvicorn",
        "uvicorn.error",
        "uvicorn.asgi",
        "uvicorn.access",
    )
    logger_state = {
        name: (
            list(logging.getLogger(name).handlers),
            logging.getLogger(name).level,
            logging.getLogger(name).disabled,
            logging.getLogger(name).propagate,
        )
        for name in logger_names
    }
    yield
    root.handlers[:] = root_handlers
    root.setLevel(root_level)
    for name, (handlers, level, disabled, propagate) in logger_state.items():
        logger = logging.getLogger(name)
        logger.handlers[:] = handlers
        logger.setLevel(level)
        logger.disabled = disabled
        logger.propagate = propagate


def _json_records(stream: io.StringIO) -> list[dict[str, object]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line]


def test_request_id_requires_canonical_uuid_v4() -> None:
    canonical = str(uuid.uuid4())
    assert valid_request_id(canonical)
    assert not valid_request_id(canonical.upper())
    assert not valid_request_id(str(uuid.uuid1()))
    assert not valid_request_id("not-a-uuid")


def test_problem_response_is_stable_and_contains_no_internal_detail() -> None:
    request_id = str(uuid.uuid4())
    response = problem_response(
        status=503,
        title="Service Unavailable",
        detail="The service is not ready.",
        request_id=request_id,
        code="not_ready",
    )
    body = json.loads(response.body)
    assert response.status_code == 503
    assert response.media_type == PROBLEM_MEDIA_TYPE
    assert body == {
        "type": "about:blank",
        "title": "Service Unavailable",
        "status": 503,
        "detail": "The service is not ready.",
        "request_id": request_id,
        "code": "not_ready",
    }
    assert "error_code" not in body


def test_central_redaction_handles_nested_keys_and_sensitive_text() -> None:
    user_id = str(uuid.uuid4())
    redacted = redact_value(
        {
            "authorization": "Bearer secret-value",
            "nested": {"provider_email": "person@example.invalid"},
            "message": f"postgresql://user:pass@db/name {user_id}",  # pragma: allowlist secret (synthetic redaction fixture)  # noqa: E501
            "request_id": user_id,
        }
    )
    assert redacted["authorization"] == "[REDACTED]"
    assert redacted["nested"]["provider_email"] == "[REDACTED]"
    assert "pass" not in redacted["message"]
    assert user_id not in redacted["message"]
    assert redacted["request_id"] == user_id


def test_json_log_filter_never_emits_sensitive_extras(
    settings_factory: Callable[..., Settings],
) -> None:
    del settings_factory
    record = logging.LogRecord(
        name="identity_service.test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="failed for https://issuer.invalid/path",
        args=(),
        exc_info=None,
    )
    record.request_id = str(uuid.uuid4())
    record.provider_email = "person@example.invalid"
    record.database_url = (
        "postgresql://user:secret@db/name"  # pragma: allowlist secret (synthetic redaction fixture)
    )
    assert RedactingFilter().filter(record)
    rendered = JsonFormatter().format(record)
    assert "person@example.invalid" not in rendered
    assert "secret" not in rendered
    assert "issuer.invalid" not in rendered
    assert "[REDACTED]" in rendered


def test_log_redaction_preserves_positional_argument_shape() -> None:
    record = logging.LogRecord(
        name="identity_service.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="request %s returned %d",
        args=("https://private.invalid/path", 200),
        exc_info=None,
    )
    assert RedactingFilter().filter(record)
    rendered = JsonFormatter().format(record)
    assert "private.invalid" not in rendered
    assert "returned 200" in rendered


def test_configure_logging_neutralizes_uvicorn_default_handlers(
    settings_factory: Callable[..., Settings],
) -> None:
    for name in ("uvicorn", "uvicorn.error", "uvicorn.asgi", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers[:] = [logging.StreamHandler(io.StringIO())]
        logger.disabled = False
        logger.propagate = False
    application_logger = logging.getLogger("identity_service.http")
    application_logger.handlers[:] = [logging.StreamHandler(io.StringIO())]
    application_logger.disabled = True
    application_logger.propagate = False

    configure_logging(settings_factory(log_format="json"), stream=io.StringIO())

    for name in ("uvicorn", "uvicorn.error", "uvicorn.asgi"):
        logger = logging.getLogger(name)
        assert logger.handlers == []
        assert logger.propagate
        assert not logger.disabled
    access_logger = logging.getLogger("uvicorn.access")
    assert access_logger.handlers == []
    assert not access_logger.propagate
    assert access_logger.disabled
    assert application_logger.handlers == []
    assert application_logger.propagate
    assert not application_logger.disabled


def test_configure_logging_is_idempotent(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(log_format="json")
    stream = io.StringIO()
    configure_logging(settings, stream=stream)
    configure_logging(settings, stream=stream)

    assert len(logging.getLogger().handlers) == 1
    assert len(logging.getLogger().handlers[0].filters) == 1
    logging.getLogger("identity_service.test").info("idempotence_probe")
    assert len(_json_records(stream)) == 1


def test_json_pipeline_formats_and_redacts_uvicorn_error_records(
    settings_factory: Callable[..., Settings],
) -> None:
    stream = io.StringIO()
    configure_logging(settings_factory(log_format="json"), stream=stream)
    identifier = str(uuid.uuid4())
    credential = "synthetic-log-value"
    email = "person" + "@example.invalid"
    bearer = "Bearer " + "synthetic-token-value"
    jwt_value = ".".join(("eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxIn0", "signature"))
    credential_url = f"https://user:{credential}@private.invalid/path"
    database_url = f"postgresql+psycopg://user:{credential}@db.invalid/identity"

    logging.getLogger("uvicorn.error").error(
        "server failure %s %s %s %s %s %s",
        email,
        credential_url,
        database_url,
        bearer,
        jwt_value,
        identifier,
        extra={"database_url": database_url, "error_type": "SyntheticError"},
    )

    records = _json_records(stream)
    assert len(records) == 1
    record = records[0]
    assert record["logger"] == "uvicorn.error"
    assert record["error_type"] == "SyntheticError"
    assert record["database_url"] == "[REDACTED]"
    rendered = json.dumps(record, sort_keys=True)
    for prohibited in (
        email,
        credential,
        "private.invalid",
        "db.invalid",
        bearer,
        jwt_value,
        identifier,
    ):
        assert prohibited not in rendered
    assert "[REDACTED]" in rendered


def test_uvicorn_access_logging_remains_disabled(
    settings_factory: Callable[..., Settings],
) -> None:
    stream = io.StringIO()
    configure_logging(settings_factory(log_format="json"), stream=stream)
    logging.getLogger("uvicorn.access").info("request line must not be emitted")
    assert stream.getvalue() == ""


def test_one_application_request_emits_one_completion_record(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = settings_factory(log_format="json")
    app = create_app(settings)
    stream = io.StringIO()
    configure_logging(settings, stream=stream)
    with ASGIClient(app) as client:
        assert client.get("/health/live").status_code == 200

    request_records = [
        record
        for record in _json_records(stream)
        if record.get("logger") == "identity_service.http"
        and record.get("event") == "request_complete"
    ]
    assert len(request_records) == 1


def test_lifecycle_record_is_not_duplicated(
    settings_factory: Callable[..., Settings],
) -> None:
    stream = io.StringIO()
    configure_logging(settings_factory(log_format="json"), stream=stream)
    logging.getLogger("uvicorn.error").info("Application startup complete.")
    records = _json_records(stream)
    assert len(records) == 1
    assert records[0]["event"] == "application_startup_complete"


def test_console_logging_is_human_readable_for_application_and_uvicorn(
    settings_factory: Callable[..., Settings],
) -> None:
    stream = io.StringIO()
    configure_logging(settings_factory(log_format="console"), stream=stream)
    logging.getLogger("identity_service.test").info("application_event")
    logging.getLogger("uvicorn.error").warning("server_event")
    lines = stream.getvalue().splitlines()
    assert lines == [
        "INFO identity_service.test application_event",
        "WARNING uvicorn.error server_event",
    ]
    assert "\x1b" not in stream.getvalue()


def test_json_application_and_uvicorn_records_have_required_common_fields(
    settings_factory: Callable[..., Settings],
) -> None:
    stream = io.StringIO()
    configure_logging(settings_factory(log_format="json", service_version="0.1.0"), stream=stream)
    logging.getLogger("identity_service.test").info("application_event")
    logging.getLogger("uvicorn.asgi").warning("server event")

    records = _json_records(stream)
    assert len(records) == 2
    assert {record["logger"] for record in records} == {
        "identity_service.test",
        "uvicorn.asgi",
    }
    for record in records:
        assert set(record) >= COMMON_JSON_FIELDS
        assert record["service"] == "identity-service"
        assert record["service_version"] == "0.1.0"
        assert record["environment"] == "test"
        assert record["timestamp"]


def test_server_configures_logging_before_starting_uvicorn(
    settings_factory: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    from identity_service import server

    settings = settings_factory(log_format="json")
    events: list[tuple[str, object]] = []
    monkeypatch.setattr(server, "Settings", lambda: settings)
    monkeypatch.setattr(
        server,
        "configure_logging",
        lambda configured: events.append(("configure", configured)),
    )
    monkeypatch.setattr(
        server.uvicorn,
        "run",
        lambda application, **options: events.append((str(application), options)),
    )

    server.main()

    assert events[0] == ("configure", settings)
    assert events[1][0] == "identity_service.main:app"
    options = events[1][1]
    assert isinstance(options, dict)
    assert options["log_config"] is None
    assert options["log_level"] is None
    assert options["access_log"] is False
    assert options["proxy_headers"] is False
