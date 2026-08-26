from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

import pytest
from reference_bff.config import Settings

from tests.reference_bff.unit.test_logout import logout_request
from tests.reference_bff.unit.test_session_flow import stack


def test_logout_logs_only_enumerated_outcome_after_local_deletion(
    bff_settings_factory: Callable[..., Settings],
    caplog: pytest.LogCaptureFixture,
) -> None:
    now = int(time.time())
    settings = bff_settings_factory()
    flow, store, provider, _upstream, session_id = stack(settings, now=now, access_lifetime=900)
    assert store.stored is not None
    record = store.stored.record
    provider.revoke_status = 503
    provider.revoke_body = (
        f'{{"refresh_token":"{record.refresh_token}","subject":"{record.subject}"}}'
    ).encode()

    caplog.set_level(logging.INFO, logger="reference_bff.http")

    async def scenario() -> None:
        await flow.logout(session_id, logout_request(settings, record.csrf_token))
        await flow.close()

    asyncio.run(scenario())
    rendered = caplog.text
    assert "provider_token_revocation_failed" in rendered
    for value in (
        session_id,
        record.subject,
        record.user_id,
        record.csrf_token,
        record.refresh_token,
        record.access_token,
        record.id_token,
        settings.client_secret.get_secret_value(),
        provider.revoke_body.decode(),
    ):
        assert value not in rendered


def test_logout_runtime_source_has_no_global_or_social_provider_signout() -> None:
    from pathlib import Path

    source_root = (
        Path(__file__).resolve().parents[3] / "examples" / "reference_bff" / "src" / "reference_bff"
    )
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (source_root / "app.py", source_root / "session_flow.py")
    ).casefold()
    assert "global_sign_out" not in source
    assert "global-sign-out" not in source
    assert "accounts.google" not in source
    assert "google.com/logout" not in source
