from __future__ import annotations

import logging
from collections.abc import Callable

from pydantic import ValidationError
from reference_bff.config import Settings
from reference_bff.logging import RedactingFilter


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
