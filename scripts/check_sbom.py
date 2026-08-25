"""Semantically validate the pip-audit CycloneDX runtime dependency SBOM."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SBOM = ROOT / ".cache" / "security" / "identity-service-runtime.cdx.json"
LOCK_ENTRY = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\]+)\s*\\?$")
SUPPORTED_SPEC_VERSIONS = frozenset({"1.4", "1.5", "1.6", "1.7"})


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def locked_components(path: Path) -> dict[str, str]:
    components: dict[str, str] = {}
    for line in path.read_text().splitlines():
        match = LOCK_ENTRY.fullmatch(line)
        if match is None:
            continue
        name, version = match.groups()
        normalized = normalize_name(name)
        if normalized in components:
            raise ValueError(f"duplicate normalized package in {path.name}: {normalized}")
        components[normalized] = version
    if not components:
        raise ValueError(f"no pinned packages found in {path.name}")
    return components


def _component_versions(document: dict[str, Any]) -> tuple[dict[str, str], str]:
    components = document.get("components")
    if not isinstance(components, list):
        raise ValueError("CycloneDX components must be a list")

    observed: dict[str, str] = {}
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("CycloneDX component entries must be objects")
        name = component.get("name")
        version = component.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ValueError("every CycloneDX component must have a string name and version")
        normalized = normalize_name(name)
        if normalized in observed:
            raise ValueError(f"duplicate CycloneDX component: {normalized}")
        observed[normalized] = version

    root_name = "none"
    metadata = document.get("metadata")
    root_component = metadata.get("component") if isinstance(metadata, dict) else None
    if root_component is not None:
        if not isinstance(root_component, dict):
            raise ValueError("CycloneDX metadata component must be an object")
        if (
            root_component.get("name") != "identity-service"
            or root_component.get("version") != "0.1.0"
        ):
            raise ValueError("unexpected root application component")
        if root_component.get("type") != "application":
            raise ValueError("identity-service root component must have application type")
        root_name = "identity-service@0.1.0"
    return observed, root_name


def _reject_sensitive_content(serialized: str, repository_root: Path) -> None:
    lowered = serialized.lower()
    forbidden_literals = (
        str(repository_root).lower(),
        "/home/",
        "/users/",
        "postgresql+psycopg://",
        "database_url",
        "git+ssh://",
        "ssh://",
        "git@",
    )
    if any(value in lowered for value in forbidden_literals):
        raise ValueError("SBOM contains a credential, private-repository, or local-path marker")
    if re.search(r"https?://[^\s\"/:@]+:[^\s\"/@]+@", serialized, re.IGNORECASE):
        raise ValueError("SBOM contains credential-bearing URL user information")
    if re.search(r'"(?:password|secret|token|credential)"\s*:', serialized, re.IGNORECASE):
        raise ValueError("SBOM contains credential-like structured data")
    if re.search(r"[A-Za-z]:\\\\", serialized):
        raise ValueError("SBOM contains a local Windows path")


def validate_sbom(
    document: dict[str, Any],
    *,
    serialized: str,
    runtime_lock: dict[str, str],
    development_lock: dict[str, str],
    repository_root: Path = ROOT,
) -> tuple[str, int, int, str]:
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM is not a CycloneDX document")
    specification = document.get("specVersion")
    if specification not in SUPPORTED_SPEC_VERSIONS:
        raise ValueError("SBOM uses an unsupported CycloneDX specification version")

    observed, root_name = _component_versions(document)
    if observed != runtime_lock:
        missing = sorted(set(runtime_lock) - set(observed))
        extra = sorted(set(observed) - set(runtime_lock))
        changed = sorted(
            name
            for name in set(observed) & set(runtime_lock)
            if observed[name] != runtime_lock[name]
        )
        raise ValueError(
            f"SBOM component set is stale: missing={missing} extra={extra} changed={changed}"
        )

    development_only = set(development_lock) - set(runtime_lock)
    included_development_only = sorted(development_only & set(observed))
    if included_development_only:
        raise ValueError(f"SBOM contains development-only packages: {included_development_only}")
    _reject_sensitive_content(serialized, repository_root)
    return str(specification), len(observed), len(runtime_lock), root_name


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom", type=Path, default=DEFAULT_SBOM)
    parser.add_argument("--runtime-lock", type=Path, default=ROOT / "requirements.lock")
    parser.add_argument("--development-lock", type=Path, default=ROOT / "requirements-dev.lock")
    args = parser.parse_args()

    try:
        serialized = args.sbom.read_text()
        parsed = json.loads(serialized)
        if not isinstance(parsed, dict):
            raise ValueError("CycloneDX root must be an object")
        specification, components, runtime_count, root_name = validate_sbom(
            parsed,
            serialized=serialized,
            runtime_lock=locked_components(args.runtime_lock),
            development_lock=locked_components(args.development_lock),
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"runtime SBOM validation failed: {error}")
        return 1

    print(
        "runtime SBOM validation passed: "
        f"CycloneDX={specification} components={components} runtime_lock={runtime_count} "
        f"root={root_name} development_only=absent sensitive_values=absent local_paths=absent"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
