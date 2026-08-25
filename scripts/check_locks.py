"""Re-resolve dependency inputs and compare exact hash-locked output."""

from __future__ import annotations

import os
import shutil

# The command below uses the running verified interpreter and fixed repository filenames.
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCKS = (
    ("requirements.in", "requirements.lock"),
    ("examples/reference_bff/requirements.in", "examples/reference_bff/requirements.lock"),
    ("requirements-dev.in", "requirements-dev.lock"),
)


def _compile(input_name: str, output_name: str, directory: Path) -> None:
    pip_cache = ROOT / ".cache" / "pip"
    pip_tools_cache = ROOT / ".cache" / "pip-tools"
    pip_cache.mkdir(parents=True, exist_ok=True)
    pip_tools_cache.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["PIP_CACHE_DIR"] = str(pip_cache)
    environment["PIP_TOOLS_CACHE_DIR"] = str(pip_tools_cache)
    command = (
        sys.executable,
        "-m",
        "piptools",
        "compile",
        "--generate-hashes",
        "--allow-unsafe",
        "--strip-extras",
        "--resolver=backtracking",
        f"--output-file={output_name}",
        input_name,
    )
    # Every argument is fixed above; no shell or caller-controlled executable is used.
    result = subprocess.run(  # nosec B603
        command,
        cwd=directory,
        check=False,
        capture_output=True,
        env=environment,
        shell=False,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"dependency resolution failed for {input_name}: {result.stderr.strip()}"
        )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="identity-service-lock-check-") as temporary:
        directory = Path(temporary)
        for input_name, _ in LOCKS:
            (directory / input_name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / input_name, directory / input_name)
        for input_name, output_name in LOCKS:
            _compile(input_name, output_name, directory)
            if (directory / output_name).read_bytes() != (ROOT / output_name).read_bytes():
                print(f"{output_name} does not match a fresh resolution")
                return 1
    print("dependency lock files match fresh hash-locked resolutions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
