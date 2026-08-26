from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BFF_SOURCE = ROOT / "examples" / "reference_bff" / "src" / "reference_bff"


def test_bff_independently_validates_without_identity_runtime_imports() -> None:
    source = "\n".join(path.read_text() for path in sorted(BFF_SOURCE.glob("*.py")))
    assert "from identity_service" not in source
    assert "import identity_service" not in source
    assert "CognitoTokenVerifier" in source
    assert "AsyncJwksCache" in source
    assert "at_hash" in source


def test_browser_token_storage_and_deferred_unsafe_surfaces_are_absent() -> None:
    source = "\n".join(path.read_text() for path in sorted(BFF_SOURCE.glob("*.py")))
    lowered = source.casefold()
    assert "localstorage" not in lowered
    assert "sessionstorage" not in lowered
    assert "document.cookie" not in lowered
    assert "@app.post" not in lowered
    assert "@app.put" not in lowered
    assert "@app.patch" not in lowered
    assert "@app.delete" not in lowered
    assert '"/auth/logout"' not in source
    assert '"/auth/signed-out"' not in source
    assert '"/session"' not in source
    assert '"/sessions"' not in source
    assert '"/refresh"' not in source
    assert "csrf" not in lowered


def test_session_cookie_source_has_the_exact_host_only_security_boundary() -> None:
    app_source = (BFF_SOURCE / "app.py").read_text()
    assert '"__Host-session"' in (BFF_SOURCE / "sessions.py").read_text()
    assert '"__Host-oauth"' in (BFF_SOURCE / "callback.py").read_text()
    assert "secure=True" in app_source
    assert "httponly=True" in app_source
    assert 'samesite="lax"' in app_source
    assert 'path="/"' in app_source
    assert "domain=" not in app_source.casefold()


def test_callback_binding_uses_raw_headers_one_time_transaction_and_constant_compare() -> None:
    callback_source = (BFF_SOURCE / "callback.py").read_text()
    cookie_source = (BFF_SOURCE / "cookies.py").read_text()
    app_source = (BFF_SOURCE / "app.py").read_text()
    assert "Iterable[tuple[bytes, bytes]]" in callback_source
    assert "MAX_COOKIE_HEADER_BYTES" in cookie_source
    assert "parse_cookie_headers" in callback_source
    assert "request.cookies" not in app_source
    assert "request.headers.get" not in app_source
    assert "store.consume(callback_query.state)" in app_source
    assert "secrets.compare_digest" in app_source
    assert app_source.index("store.consume(callback_query.state)") < app_source.index(
        "secrets.compare_digest"
    )
    assert "delete_cookie" in app_source
