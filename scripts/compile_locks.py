"""Generate and verify every dependency lock through one fixed pip-tools wrapper."""

from __future__ import annotations

import os
import re
import shutil

# The command below uses the running verified interpreter and fixed repository filenames.
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]
CUSTOM_COMPILE_COMMAND = "make lock"
PYPI_INDEX_URL = "https://pypi.org/simple"
LOCKS = (
    ("requirements.in", "requirements.lock"),
    ("examples/reference_bff/requirements.in", "examples/reference_bff/requirements.lock"),
    ("requirements-dev.in", "requirements-dev.lock"),
)
COMPILE_ARGUMENTS = (
    "-m",
    "piptools",
    "compile",
    "--generate-hashes",
    "--allow-unsafe",
    "--strip-extras",
    "--resolver=backtracking",
    "--no-config",
)
CHECK_ARGUMENTS = ("--no-upgrade", "--no-reuse-hashes")


def _validate_seed(data: bytes) -> None:
    """Accept only exact named pins with SHA-256 hashes, never pip directives/URLs."""
    try:
        text = data.decode("ascii")
    except UnicodeError:
        raise ValueError("unsupported dependency lock syntax") from None
    if any(ord(character) < 32 and character not in "\n\t" for character in text):
        raise ValueError("unsupported dependency lock syntax")
    pending = ""
    names: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            if pending:
                raise ValueError("interrupted dependency lock entry")
            continue
        continued = line.endswith("\\")
        pending += line[:-1].rstrip() + " " if continued else line
        if continued:
            continue
        pin, *hashes = pending.split(" --hash=")
        pending = ""
        if not hashes or any(
            re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in hashes
        ):
            raise ValueError("missing or malformed dependency lock hashes")
        if len(set(hashes)) != len(hashes):
            raise ValueError("duplicate dependency lock hash")
        try:
            requirement = Requirement(pin)
            specifiers = list(requirement.specifier)
            if (
                requirement.url is not None
                or requirement.extras
                or len(specifiers) != 1
                or specifiers[0].operator != "=="
            ):
                raise ValueError("unsupported dependency lock requirement")
            Version(specifiers[0].version)
        except InvalidRequirement, InvalidVersion:
            raise ValueError("unsupported dependency lock requirement") from None
        name = canonicalize_name(requirement.name)
        if name in names:
            raise ValueError("duplicate dependency lock member")
        names.add(name)
    if pending or not names:
        raise ValueError("incomplete dependency lock")


def _environment() -> dict[str, str]:
    pip_cache = ROOT / ".cache" / "pip"
    pip_tools_cache = ROOT / ".cache" / "pip-tools"
    pip_cache.mkdir(parents=True, exist_ok=True)
    pip_tools_cache.mkdir(parents=True, exist_ok=True)
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("PIP_", "PIP_TOOLS_")) and name != "CUSTOM_COMPILE_COMMAND"
    }
    environment["CUSTOM_COMPILE_COMMAND"] = CUSTOM_COMPILE_COMMAND
    environment["PIP_CACHE_DIR"] = str(pip_cache)
    environment["PIP_CONFIG_FILE"] = os.devnull
    environment["PIP_INDEX_URL"] = PYPI_INDEX_URL
    environment["PIP_TOOLS_CACHE_DIR"] = str(pip_tools_cache)
    return environment


def _compile(input_name: str, output_name: str, directory: Path, *, check: bool = False) -> None:
    command = (
        sys.executable,
        *COMPILE_ARGUMENTS,
        *(CHECK_ARGUMENTS if check else ()),
        f"--output-file={output_name}",
        input_name,
    )
    result = subprocess.run(  # nosec B603
        command,
        cwd=directory,
        check=False,
        capture_output=True,
        env=_environment(),
        shell=False,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"dependency resolution failed for {input_name}: {result.stderr.strip()}"
        )


def _compile_all(directory: Path, *, check: bool = False) -> None:
    for input_name, output_name in LOCKS:
        _compile(input_name, output_name, directory, check=check)


def write_locks() -> int:
    """Write every canonical repository lock using the fixed wrapper."""
    with tempfile.TemporaryDirectory(prefix="identity-service-lock-write-") as temporary:
        directory = Path(temporary)
        _prepare_inputs(directory)
        _compile_all(directory)
        for _, output_name in LOCKS:
            destination = ROOT / output_name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(directory / output_name, destination)
    return 0


def _prepare_inputs(directory: Path) -> None:
    for input_name, _ in LOCKS:
        destination = directory / input_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / input_name, destination)


def check_locks() -> int:
    """Verify reviewed versions by resolving twice with independently regenerated hashes."""
    sources = {name: (ROOT / name).read_bytes() for pair in LOCKS for name in pair}
    for _, output_name in LOCKS:
        _validate_seed(sources[output_name])
    with (
        tempfile.TemporaryDirectory(prefix="identity-service-lock-check-a-") as first_temporary,
        tempfile.TemporaryDirectory(prefix="identity-service-lock-check-b-") as second_temporary,
    ):
        first_directory = Path(first_temporary)
        second_directory = Path(second_temporary)
        for directory in (first_directory, second_directory):
            for name, data in sources.items():
                destination = directory / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
            _compile_all(directory, check=True)
        if any((ROOT / name).read_bytes() != data for name, data in sources.items()):
            print("dependency inputs or locks changed during verification")
            return 1
        for _, output_name in LOCKS:
            first = (first_directory / output_name).read_bytes()
            second = (second_directory / output_name).read_bytes()
            if first != second:
                print(f"{output_name} differs between independent locked resolutions")
                return 1
            if first != sources[output_name]:
                print(f"{output_name} does not match the regenerated locked resolution")
                return 1
    print("dependency lock files match two independently rehashed locked resolutions")
    return 0


def main() -> int:
    return write_locks()


if __name__ == "__main__":
    raise SystemExit(main())
