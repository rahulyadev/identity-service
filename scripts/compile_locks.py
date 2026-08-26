"""Generate and verify every dependency lock through one fixed pip-tools wrapper."""

from __future__ import annotations

import os
import shutil

# The command below uses the running verified interpreter and fixed repository filenames.
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path

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
)


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


def _compile(input_name: str, output_name: str, directory: Path) -> None:
    command = (
        sys.executable,
        *COMPILE_ARGUMENTS,
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


def _compile_all(directory: Path) -> None:
    for input_name, output_name in LOCKS:
        _compile(input_name, output_name, directory)


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
    """Resolve twice in isolation and compare both results with canonical locks."""
    with (
        tempfile.TemporaryDirectory(prefix="identity-service-lock-check-a-") as first_temporary,
        tempfile.TemporaryDirectory(prefix="identity-service-lock-check-b-") as second_temporary,
    ):
        first_directory = Path(first_temporary)
        second_directory = Path(second_temporary)
        _prepare_inputs(first_directory)
        _prepare_inputs(second_directory)
        _compile_all(first_directory)
        _compile_all(second_directory)
        for _, output_name in LOCKS:
            first = (first_directory / output_name).read_bytes()
            second = (second_directory / output_name).read_bytes()
            if first != second:
                print(f"{output_name} differs between independent fresh resolutions")
                return 1
            if first != (ROOT / output_name).read_bytes():
                print(f"{output_name} does not match a fresh resolution")
                return 1
    print("dependency lock files match two independent fresh hash-locked resolutions")
    return 0


def main() -> int:
    return write_locks()


if __name__ == "__main__":
    raise SystemExit(main())
