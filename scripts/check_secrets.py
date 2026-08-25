"""Run detect-secrets sequentially without printing candidate secret values."""

from __future__ import annotations

import shutil

# subprocess is restricted to a fixed argv, a resolved git binary, and shell=False below.
import subprocess  # nosec B404
from pathlib import Path

from detect_secrets.core.scan import scan_file
from detect_secrets.settings import default_settings

ROOT = Path(__file__).resolve().parents[1]


def repository_files() -> list[Path]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required for the repository secret scan")
    # The executable is resolved above and no caller-controlled argument enters this fixed argv.
    result = subprocess.run(  # nosec B603
        [git, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        shell=False,
    )
    return [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]


def main() -> int:
    findings: list[tuple[str, int, str]] = []
    with default_settings():
        for filename in repository_files():
            for candidate in scan_file(str(filename)):
                findings.append(
                    (
                        str(filename.relative_to(ROOT)),
                        candidate.line_number,
                        candidate.type,
                    )
                )
    if findings:
        for filename, line, finding_type in findings:
            print(f"{filename}:{line}: {finding_type}")
        return 1
    print("detect-secrets found no unallowlisted candidates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
