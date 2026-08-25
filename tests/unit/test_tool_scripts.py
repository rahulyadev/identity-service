from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts import check_locks, check_secrets, container_smoke


def test_secret_scanner_uses_resolved_git_with_fixed_no_shell_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    def fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        observed["args"] = args
        observed.update(kwargs)
        return subprocess.CompletedProcess(args, 0, stdout=b"README.md\0")

    monkeypatch.setattr(check_secrets.shutil, "which", lambda name: "/safe/git")
    monkeypatch.setattr(check_secrets.subprocess, "run", fake_run)

    assert check_secrets.repository_files() == [check_secrets.ROOT / "README.md"]
    assert observed["args"] == [
        "/safe/git",
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
    ]
    assert observed["shell"] is False
    assert observed["cwd"] == check_secrets.ROOT


def test_container_runner_allows_only_resolved_docker_without_a_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    def fake_run(args: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed["args"] = args
        observed.update(kwargs)
        return subprocess.CompletedProcess(args, 0, stdout="10001\n")

    monkeypatch.setattr(container_smoke.shutil, "which", lambda name: "/safe/docker")
    monkeypatch.setattr(container_smoke.subprocess, "run", fake_run)

    assert container_smoke.run("docker", "compose", "version", capture=True) == "10001"
    assert observed["args"] == ("/safe/docker", "compose", "version")
    assert observed["shell"] is False
    assert observed["cwd"] == Path(container_smoke.ROOT)
    with pytest.raises(ValueError, match="only Docker"):
        container_smoke.run("sh", "-c", "true")


def test_container_endpoint_allowlist_rejects_arbitrary_targets() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        container_smoke.wait_for_json("http://external.invalid", "ready")


def test_lock_checker_uses_fixed_interpreter_argv_without_a_shell(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    observed: dict[str, Any] = {}

    def fake_run(args: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed["args"] = args
        observed.update(kwargs)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(check_locks.subprocess, "run", fake_run)
    check_locks._compile("requirements.in", "requirements.lock", tmp_path)

    assert observed["args"][0] == check_locks.sys.executable
    assert observed["args"][1:4] == ("-m", "piptools", "compile")
    assert observed["args"][-2:] == ("--output-file=requirements.lock", "requirements.in")
    assert observed["shell"] is False
    assert observed["cwd"] == tmp_path


def test_lock_checker_covers_identity_bff_and_combined_development_sets() -> None:
    assert check_locks.LOCKS == (
        ("requirements.in", "requirements.lock"),
        ("examples/reference_bff/requirements.in", "examples/reference_bff/requirements.lock"),
        ("requirements-dev.in", "requirements-dev.lock"),
    )


def test_container_tmpfs_suppression_is_a_fixed_non_user_path() -> None:
    assert container_smoke.CONTAINER_TMPFS == "/tmp"


def test_raw_http_response_classifier_rejects_success_and_multiple_responses() -> None:
    safe = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
    assert container_smoke.classify_raw_response(safe, connection_terminated=True) == "client_error"
    assert (
        container_smoke.classify_raw_response(b"", connection_terminated=True)
        == "connection_terminated"
    )
    with pytest.raises(RuntimeError, match="successful"):
        container_smoke.classify_raw_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            connection_terminated=True,
        )
    with pytest.raises(RuntimeError, match="more than one"):
        container_smoke.classify_raw_response(safe + safe, connection_terminated=True)
