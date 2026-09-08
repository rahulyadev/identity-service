from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts import check_locks, check_secrets, compile_locks, container_smoke


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


def test_lock_wrapper_uses_exact_fixed_argv_environment_and_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    observed: list[dict[str, Any]] = []

    def fake_run(args: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.append({"args": args, **kwargs})
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(compile_locks.subprocess, "run", fake_run)
    monkeypatch.setenv("CUSTOM_COMPILE_COMMAND", "unsafe caller override")
    monkeypatch.setenv("PIP_NO_INDEX", "1")
    monkeypatch.setenv("PIP_EXTRA_INDEX_URL", "https://external.invalid/simple")
    compile_locks._compile_all(tmp_path)

    assert len(observed) == 3
    for invocation, (input_name, output_name) in zip(observed, compile_locks.LOCKS, strict=True):
        assert invocation["args"] == (
            compile_locks.sys.executable,
            *compile_locks.COMPILE_ARGUMENTS,
            f"--output-file={output_name}",
            input_name,
        )
        assert "--no-index" not in invocation["args"]
        assert invocation["shell"] is False
        assert invocation["cwd"] == tmp_path
        assert invocation["env"]["CUSTOM_COMPILE_COMMAND"] == "make lock"
        assert invocation["env"]["PIP_CONFIG_FILE"] == compile_locks.os.devnull
        assert invocation["env"]["PIP_INDEX_URL"] == "https://pypi.org/simple"
        assert "PIP_NO_INDEX" not in invocation["env"]
        assert "PIP_EXTRA_INDEX_URL" not in invocation["env"]


def test_lock_wrapper_covers_identity_bff_and_combined_development_sets() -> None:
    assert compile_locks.LOCKS == (
        ("requirements.in", "requirements.lock"),
        ("examples/reference_bff/requirements.in", "examples/reference_bff/requirements.lock"),
        ("requirements-dev.in", "requirements-dev.lock"),
    )


def test_lock_wrapper_write_mode_resolves_fresh_without_subprocesses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "repository"
    observed: list[Path] = []

    for input_name, _ in compile_locks.LOCKS:
        source = root / input_name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(f"input:{input_name}\n")

    def fake_compile_all(directory: Path) -> None:
        observed.append(directory)
        for input_name, output_name in compile_locks.LOCKS:
            assert (directory / input_name).read_text() == f"input:{input_name}\n"
            destination = directory / output_name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(f"generated:{output_name}\n")

    monkeypatch.setattr(compile_locks, "ROOT", root)
    monkeypatch.setattr(compile_locks, "_compile_all", fake_compile_all)

    assert compile_locks.write_locks() == 0
    assert len(observed) == 1
    assert observed[0] != root
    for _, output_name in compile_locks.LOCKS:
        assert (root / output_name).read_text() == f"generated:{output_name}\n"


def test_lock_wrapper_check_mode_resolves_twice_without_subprocesses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "repository"
    observed: list[Path] = []

    for input_name, output_name in compile_locks.LOCKS:
        source = root / input_name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(f"input:{input_name}\n")
        destination = root / output_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("idna==3.18 --hash=sha256:" + "a" * 64 + "\n")

    def fake_compile_all(directory: Path, *, check: bool = False) -> None:
        assert check is True
        observed.append(directory)
        for input_name, output_name in compile_locks.LOCKS:
            assert (directory / input_name).read_text() == f"input:{input_name}\n"
            destination = directory / output_name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text("idna==3.18 --hash=sha256:" + "a" * 64 + "\n")

    monkeypatch.setattr(compile_locks, "ROOT", root)
    monkeypatch.setattr(compile_locks, "_compile_all", fake_compile_all)

    assert compile_locks.check_locks() == 0
    assert len(observed) == 2
    assert observed[0] != observed[1]


def test_lock_wrapper_check_mode_rejects_byte_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "repository"
    invocation = 0

    for input_name, output_name in compile_locks.LOCKS:
        source = root / input_name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(f"input:{input_name}\n")
        destination = root / output_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("idna==3.18 --hash=sha256:" + "a" * 64 + "\n")

    def fake_compile_all(directory: Path, *, check: bool = False) -> None:
        assert check is True
        nonlocal invocation
        invocation += 1
        for _, output_name in compile_locks.LOCKS:
            destination = directory / output_name
            destination.parent.mkdir(parents=True, exist_ok=True)
            content = (root / output_name).read_bytes()
            if invocation == 2 and output_name == "requirements.lock":
                content += b"# drift\n"
            destination.write_bytes(content)

    monkeypatch.setattr(compile_locks, "ROOT", root)
    monkeypatch.setattr(compile_locks, "_compile_all", fake_compile_all)

    assert compile_locks.check_locks() == 1
    assert capsys.readouterr().out == (
        "requirements.lock differs between independent locked resolutions\n"
    )


def test_lock_checker_delegates_to_the_canonical_wrapper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(check_locks, "check_locks", lambda: 17)
    assert check_locks.main() == 17


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
