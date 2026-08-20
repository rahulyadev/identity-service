"""Reject implementation-process narration in public product documentation."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_FILES = (
    ROOT / "README.md",
    *(sorted((ROOT / "docs").glob("*.md"))),
    ROOT / "src" / "identity_service" / "app.py",
    ROOT / "openapi" / "openapi.json",
)
PROHIBITED = {
    "phase 1": re.compile(r"\bphase\s+1\b", re.IGNORECASE),
    "increment": re.compile(r"\bincrement\b", re.IGNORECASE),
    "checkpoint": re.compile(r"\bcheckpoint\b", re.IGNORECASE),
    "GPT": re.compile(r"\bGPT\b", re.IGNORECASE),
    "Codex": re.compile(r"\bCodex\b", re.IGNORECASE),
    "agent gate": re.compile(r"\bagent\s+gate\b", re.IGNORECASE),
    "approved": re.compile(r"\bapproved\b", re.IGNORECASE),
    "accepted": re.compile(r"\baccepted\b", re.IGNORECASE),
    "milestone approval": re.compile(r"\bmilestone\s+approval\b", re.IGNORECASE),
}


def find_process_language(files: tuple[Path, ...] = PUBLIC_FILES) -> list[tuple[Path, int, str]]:
    findings: list[tuple[Path, int, str]] = []
    for path in files:
        for line_number, line in enumerate(path.read_text().splitlines(), start=1):
            for label, pattern in PROHIBITED.items():
                if pattern.search(line):
                    findings.append((path, line_number, label))
    return findings


def main() -> int:
    findings = find_process_language()
    if findings:
        for path, line_number, label in findings:
            print(f"{path.relative_to(ROOT)}:{line_number}: prohibited public phrase: {label}")
        return 1
    print(f"public documentation hygiene passed for {len(PUBLIC_FILES)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
