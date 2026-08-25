"""Create a project-local Python 3.14.4 environment with a verified pip wheel."""

from __future__ import annotations

import hashlib
import http.client
import sys
import sysconfig
import tempfile
import venv
import zipfile
from pathlib import Path

PYTHON_VERSION = (3, 14, 4)
PIP_VERSION = "26.2.1"
PIP_WHEEL_HOST = "files.pythonhosted.org"
PIP_WHEEL_PATH = (
    "/packages/f3/6e/"
    "1736e5b4ae2b778ef2f81c47d797de9f891d4d8acb047a24ca37a60294dd/"
    "pip-26.2.1-py3-none-any.whl"
)
PIP_WHEEL_SHA256 = "71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e"  # pragma: allowlist secret (public package digest)  # noqa: E501
MAX_PIP_WHEEL_BYTES = 5 * 1024 * 1024
ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".venv"


def _venv_python() -> Path:
    return VENV / "bin" / "python"


def _site_packages() -> Path:
    return Path(
        sysconfig.get_path(
            "purelib",
            scheme="venv",
            vars={"base": str(VENV), "platbase": str(VENV)},
        )
    )


def _download_pip_wheel(destination: Path) -> None:
    connection = http.client.HTTPSConnection(PIP_WHEEL_HOST, timeout=30)
    try:
        connection.request("GET", PIP_WHEEL_PATH)
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError(f"pip wheel download returned HTTP {response.status}")
        content = response.read(MAX_PIP_WHEEL_BYTES + 1)
    finally:
        connection.close()
    if len(content) > MAX_PIP_WHEEL_BYTES:
        raise RuntimeError("pip wheel download exceeded the fixed size limit")
    destination.write_bytes(content)


def main() -> int:
    if sys.version_info[:3] != PYTHON_VERSION:
        print("Python 3.14.4 is required", file=sys.stderr)
        return 2

    if not _venv_python().exists():
        if VENV.exists():
            raise RuntimeError(".venv exists but is incomplete; inspect it before removing it")
        venv.EnvBuilder(with_pip=False).create(VENV)

    site_packages = _site_packages()
    if not (site_packages / "pip" / "__init__.py").is_file():
        with tempfile.TemporaryDirectory(prefix="identity-service-pip-") as temp_dir:
            wheel = Path(temp_dir) / f"pip-{PIP_VERSION}-py3-none-any.whl"
            _download_pip_wheel(wheel)
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            if digest != PIP_WHEEL_SHA256:
                raise RuntimeError("downloaded pip wheel did not match its pinned SHA-256")
            with zipfile.ZipFile(wheel) as archive:
                archive.extractall(site_packages)

    print(f"pip {PIP_VERSION} available in {_venv_python()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
