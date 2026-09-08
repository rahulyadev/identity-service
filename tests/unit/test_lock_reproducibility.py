"""Locked-version integrity, including actual pinned pip-tools execution on public fixtures."""

from __future__ import annotations

import importlib.metadata
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import compile_locks

HASH = "a" * 64
VALID = f"platformdirs==4.11.6 --hash=sha256:{HASH}\n"
ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("name", [output for _, output in compile_locks.LOCKS])
def test_all_existing_lock_grammars_are_supported(name: str) -> None:
    compile_locks._validate_seed((ROOT / name).read_bytes())


@pytest.mark.parametrize(
    "seed",
    [
        b"",
        b"\xff",
        b"name==1\r\n",
        b"name==1\n",
        b"name==1 \\\n",
        b"name==1 \\\n# interrupted\n",
        b"name==1 --hash=sha256:bad\n",
        b"name==1 --hash=md5:" + b"a" * 32,
        b"name==1 --hash=sha256:" + b"g" * 64,
        f"name==1 --hash=sha256:{HASH} --hash=sha256:{HASH}\n".encode(),
        f"name==1.* --hash=sha256:{HASH}\n".encode(),
        f"name>=1 --hash=sha256:{HASH}\n".encode(),
        f"name[extra]==1 --hash=sha256:{HASH}\n".encode(),
        f"name @ https://external.invalid/package.whl --hash=sha256:{HASH}\n".encode(),
        f"https://external.invalid/package.whl --hash=sha256:{HASH}\n".encode(),
        f"name==1 --hash=sha256:{HASH}\nName==1 --hash=sha256:{HASH}\n".encode(),
        f"name==1; --index-url https://external.invalid --hash=sha256:{HASH}\n".encode(),
    ]
    + [
        directive.encode() + b"\n" + VALID.encode()
        for directive in [
            "--index-url https://external.invalid/simple",
            "--extra-index-url https://external.invalid",
            "--find-links /tmp/wheels",
            "--trusted-host external.invalid",
            "--no-index",
            "-r other.lock",
            "--requirement=other.lock",
            "-c other.lock",
            "--constraint=other.lock",
            "-e ./project",
            "--editable=./project",
            "--config-settings=key=value",
            "../package.whl",
        ]
    ],
)
def test_unsafe_or_incomplete_seeds_fail_before_resolver(seed: bytes) -> None:
    with pytest.raises(ValueError):
        compile_locks._validate_seed(seed)


def test_safe_pep508_marker_is_parsed_as_requirement_not_resolver_options() -> None:
    compile_locks._validate_seed(
        f'name==1; python_version >= "3.14" --hash=sha256:{HASH}\n'.encode()
    )


@pytest.mark.parametrize("mode", ["check", "write"])
def test_compiler_disables_config_and_sanitizes_overrides(monkeypatch, tmp_path, mode):
    observed = []

    def run(args, **kwargs):
        observed.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    for key in [
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "PIP_FIND_LINKS",
        "PIP_TRUSTED_HOST",
        "PIP_CONFIG_FILE",
        "PIP_CONSTRAINT",
        "PIP_TOOLS_UPGRADE",
        "PIP_TOOLS_CONFIG",
        "PIP_TOOLS_REUSE_HASHES",
        "CUSTOM_COMPILE_COMMAND",
    ]:
        monkeypatch.setenv(key, "unsafe-caller-value")
    monkeypatch.setattr(compile_locks, "ROOT", tmp_path)
    monkeypatch.setattr(compile_locks.subprocess, "run", run)
    compile_locks._compile_all(tmp_path, check=mode == "check")
    for (args, kwargs), (source, output) in zip(observed, compile_locks.LOCKS, strict=True):
        assert args == (
            compile_locks.sys.executable,
            *compile_locks.COMPILE_ARGUMENTS,
            *(compile_locks.CHECK_ARGUMENTS if mode == "check" else ()),
            f"--output-file={output}",
            source,
        )
        assert "--no-config" in args
        assert ("--no-upgrade" in args) == (mode == "check")
        assert ("--no-reuse-hashes" in args) == (mode == "check")
        assert kwargs["shell"] is False and kwargs["cwd"] == tmp_path
        environment = kwargs["env"]
        assert "unsafe-caller-value" not in environment.values()
        assert environment["PIP_INDEX_URL"] == "https://pypi.org/simple"
        assert environment["PIP_CONFIG_FILE"] == compile_locks.os.devnull
        assert environment["CUSTOM_COMPILE_COMMAND"] == "make lock"


def fixture_root(root: Path) -> dict[str, bytes]:
    sources = {}
    for source, output in compile_locks.LOCKS:
        for name, data in [(source, b"platformdirs>=4.11.6,<5\n"), (output, VALID.encode())]:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            sources[name] = data
    return sources


@pytest.mark.parametrize("output", [name for _, name in compile_locks.LOCKS])
def test_all_seeds_are_validated_before_any_compiler_call(monkeypatch, tmp_path, output):
    sources = fixture_root(tmp_path)
    (tmp_path / output).write_text("--index-url https://external.invalid\n")
    sources[output] = (tmp_path / output).read_bytes()
    monkeypatch.setattr(compile_locks, "ROOT", tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("unsafe seed reached resolver")

    monkeypatch.setattr(compile_locks, "_compile_all", forbidden)
    with pytest.raises(ValueError):
        compile_locks.check_locks()
    assert {name: (tmp_path / name).read_bytes() for name in sources} == sources


@pytest.mark.parametrize(
    "failure", ["different-outputs", "changed-output", "resolver", "source-race"]
)
def test_check_failures_preserve_repository_files(monkeypatch, tmp_path, failure):
    sources = fixture_root(tmp_path)
    monkeypatch.setattr(compile_locks, "ROOT", tmp_path)
    calls = []

    def compile_fixture(directory, *, check=False):
        assert check
        calls.append(directory)
        assert {name: (directory / name).read_bytes() for name in sources} == sources
        if failure == "resolver":
            raise RuntimeError("dependency resolution failed")
        if failure == "changed-output" or (failure == "different-outputs" and len(calls) == 2):
            (directory / "requirements.lock").write_bytes(VALID.encode() + b"# changed\n")
        if failure == "source-race" and len(calls) == 2:
            # Simulate another actor; the checker must detect it without undoing their write.
            (tmp_path / "requirements.in").write_bytes(b"platformdirs==4.11.7\n")

    monkeypatch.setattr(compile_locks, "_compile_all", compile_fixture)
    if failure == "resolver":
        with pytest.raises(RuntimeError):
            compile_locks.check_locks()
    else:
        assert compile_locks.check_locks() == 1
    if failure == "source-race":
        sources["requirements.in"] = b"platformdirs==4.11.7\n"
    assert {name: (tmp_path / name).read_bytes() for name in sources} == sources
    assert all(not directory.exists() for directory in calls)


def test_nonzero_compiler_exit_is_never_a_success(monkeypatch, tmp_path):
    def fail(args, **kwargs):
        return subprocess.CompletedProcess(args, 23, stdout="", stderr="synthetic resolver failure")

    monkeypatch.setattr(compile_locks.subprocess, "run", fail)
    with pytest.raises(RuntimeError, match="dependency resolution failed"):
        compile_locks._compile("requirements.in", "requirements.lock", tmp_path, check=True)


@pytest.fixture(scope="module")
def public_locked_fixture(tmp_path_factory):
    """Create authentic small seeds with pip-tools, not handcrafted trusted hashes."""
    assert importlib.metadata.version("pip-tools") == "7.6.1"
    root = tmp_path_factory.mktemp("public-lock-seeds")
    for source, _ in compile_locks.LOCKS:
        path = root / source
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("platformdirs==4.11.6\nidna==3.19\n")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(compile_locks, "ROOT", root)
        assert not (root / ".cache").exists()
        compile_locks.write_locks()
    for source, _ in compile_locks.LOCKS:
        (root / source).write_text("platformdirs>=4.11.6,<=4.11.7\nidna==3.19\n")
    return root


@pytest.mark.timeout(180)
@pytest.mark.parametrize(
    "mutation",
    [
        "none",
        "wrong-hash",
        "missing-hash",
        "added-member",
        "removed-member",
        "incompatible-input",
        "impossible-input",
    ],
)
def test_real_pinned_compiler_rehashes_and_rejects_drift(
    public_locked_fixture, monkeypatch, tmp_path, mutation
):
    for source, output in compile_locks.LOCKS:
        for name in (source, output):
            destination = tmp_path / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(public_locked_fixture / name, destination)
    lock = tmp_path / "requirements.lock"
    original = lock.read_bytes()
    hashes = re.findall(rb"--hash=sha256:([a-f0-9]{64})", original)
    assert len(hashes) >= 2 and b"0" * 64 not in hashes
    if mutation == "wrong-hash":
        lock.write_bytes(original.replace(hashes[0], b"0" * 64))
    elif mutation == "missing-hash":
        # Remove one whole hash; the entry remains valid but its independent hash set differs.
        lock.write_bytes(re.sub(rb"    --hash=sha256:[a-f0-9]{64} \\\n", b"", original, count=1))
        assert lock.read_bytes() != original
    elif mutation == "added-member":
        lock.write_bytes(original + b"packaging==26.3 --hash=sha256:" + b"0" * 64 + b"\n")
    elif mutation == "removed-member":
        # A valid nonempty seed is missing a required graph member; resolution must restore it.
        lock.write_bytes(original[: original.index(b"platformdirs==")])
    elif mutation == "incompatible-input":
        (tmp_path / "requirements.in").write_text("platformdirs==4.11.7\n")
    elif mutation == "impossible-input":
        (tmp_path / "requirements.in").write_text("platformdirs==0.0.0\n")
    snapshot = {
        name: (tmp_path / name).read_bytes() for pair in compile_locks.LOCKS for name in pair
    }
    monkeypatch.setattr(compile_locks, "ROOT", tmp_path)
    assert not (tmp_path / ".cache").exists()  # Every scenario starts with clean public caches.
    # Real config files and inherited options must not change compiler behavior or contact them.
    (tmp_path / ".pip-tools.toml").write_text(
        '[tool.pip-tools]\nindex-url = "https://external.invalid"\nupgrade = true\n'
    )
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pip-tools]\nindex-url = "https://external.invalid"\n'
    )
    monkeypatch.setenv("PIP_TOOLS_UPGRADE", "true")
    monkeypatch.setenv("PIP_INDEX_URL", "https://external.invalid")
    if mutation == "impossible-input":
        with pytest.raises(RuntimeError, match="dependency resolution failed"):
            compile_locks.check_locks()
    else:
        assert compile_locks.check_locks() == (0 if mutation == "none" else 1)
    assert {name: (tmp_path / name).read_bytes() for name in snapshot} == snapshot
    if mutation == "none":
        assert all(
            b"platformdirs==4.11.6" in (tmp_path / output).read_bytes()
            for _, output in compile_locks.LOCKS
        )
        # Explicit generation starts from inputs alone and selects the newer public version.
        assert compile_locks.write_locks() == 0
        assert all(
            b"platformdirs==4.11.7" in (tmp_path / output).read_bytes()
            for _, output in compile_locks.LOCKS
        )
    elif mutation == "wrong-hash":
        # Observe the actual regenerated bytes directly, beyond a nonzero comparison status.
        proof = tmp_path / "rehash-proof"
        proof.mkdir()
        (proof / ".pip-tools.toml").write_text(
            '[tool.pip-tools]\nindex-url = "https://external.invalid"\nupgrade = true\n'
        )
        shutil.copyfile(tmp_path / "requirements.in", proof / "requirements.in")
        shutil.copyfile(lock, proof / "requirements.lock")
        compile_locks._compile("requirements.in", "requirements.lock", proof, check=True)
        assert (proof / "requirements.lock").read_bytes() == original
        assert b"0" * 64 not in (proof / "requirements.lock").read_bytes()
