from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import check_public_docs, check_sbom


def _sbom_document(components: dict[str, str]) -> dict[str, object]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {"timestamp": "2026-01-01T00:00:00+00:00"},
        "components": [
            {"type": "library", "name": name, "version": version}
            for name, version in sorted(components.items())
        ],
    }


def test_public_documentation_has_no_process_language(tmp_path: Path) -> None:
    assert check_public_docs.find_process_language() == []
    stale = tmp_path / "public.md"
    stale.write_text("This increment awaits a checkpoint.\n")
    findings = check_public_docs.find_process_language((stale,))
    assert {label for _, _, label in findings} == {"increment", "checkpoint"}


def test_runtime_sbom_semantics_match_exact_lock_and_exclude_development() -> None:
    runtime = {"fastapi": "1.0", "uvicorn": "2.0"}
    development = {**runtime, "pytest": "3.0"}
    document = _sbom_document(runtime)
    serialized = json.dumps(document)

    assert check_sbom.validate_sbom(
        document,
        serialized=serialized,
        runtime_lock=runtime,
        development_lock=development,
    ) == ("1.4", 2, 2, "none")

    stale = _sbom_document({"fastapi": "1.0"})
    with pytest.raises(ValueError, match="stale"):
        check_sbom.validate_sbom(
            stale,
            serialized=json.dumps(stale),
            runtime_lock=runtime,
            development_lock=development,
        )

    development_component = _sbom_document({**runtime, "pytest": "3.0"})
    with pytest.raises(ValueError, match="stale"):
        check_sbom.validate_sbom(
            development_component,
            serialized=json.dumps(development_component),
            runtime_lock=runtime,
            development_lock=development,
        )


@pytest.mark.parametrize(
    "sensitive_value",
    [
        "/home/example/private/repository",
        "https://user:credential@example.invalid/index",  # pragma: allowlist secret
        "postgresql+psycopg://database.invalid/name",
        '"token": "value"',  # pragma: allowlist secret
    ],
)
def test_runtime_sbom_rejects_credentials_and_local_paths(sensitive_value: str) -> None:
    runtime = {"fastapi": "1.0"}
    document = _sbom_document(runtime)
    with pytest.raises(ValueError, match=r"credential|path|structured"):
        check_sbom.validate_sbom(
            document,
            serialized=json.dumps(document) + sensitive_value,
            runtime_lock=runtime,
            development_lock=runtime,
        )


def test_actual_runtime_and_development_locks_have_expected_boundary() -> None:
    runtime = check_sbom.locked_components(check_sbom.ROOT / "requirements.lock")
    development = check_sbom.locked_components(check_sbom.ROOT / "requirements-dev.lock")
    assert len(runtime) == 30
    assert {
        "httpx2",
        "httpcore2",
        "truststore",
        "pyjwt",
        "cryptography",
        "cffi",
        "pycparser",
    } <= set(runtime)
    assert set(runtime) < set(development)
    assert "pytest" not in runtime
    assert "pytest" in development
