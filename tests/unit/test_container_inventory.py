from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from examples.reference_bff.scripts import container_smoke as bff_smoke
from scripts import container_smoke as api_smoke

CORE_PACKAGES = (
    "libc6",
    "libssl3",
    "libgnutls30",
    "libbz2-1.0",
    "libffi8",
    "liblzma5",
    "libsqlite3-0",
    "libuuid1",
    "zlib1g",
    "libstdc++6",
    "libgcc-s1",
    "libcrypt1",
)


@pytest.fixture
def inventory_root(tmp_path: Path) -> Path:
    database = tmp_path / "var/lib/dpkg"
    (database / "info").mkdir(parents=True)
    library = tmp_path / "usr/lib/synthetic"
    library.mkdir(parents=True)
    (tmp_path / "etc/ld.so.conf.d").mkdir(parents=True)
    records = []
    for name in (*CORE_PACKAGES, "synthetic-data"):
        records.append(
            f"Package: {name}\nStatus: install ok installed\nArchitecture: amd64\n"
            "Version: 1:2.3-4+deb12u1\nConffiles:\n /etc/synthetic fixture-checksum\n"
            "Description: synthetic fixture\n continuation\n\n"
        )
        relative = f"usr/lib/synthetic/{name}.so.1"
        contents = b"\x7fELFsynthetic-not-executable-" + name.encode()
        (tmp_path / relative).write_bytes(contents)
        (database / "info" / (name + ":amd64.list")).write_text(
            "/etc/ld.so.conf.d\n/" + relative + "\n"
        )
        digest = hashlib.md5(contents, usedforsecurity=False).hexdigest()
        (database / "info" / (name + ":amd64.md5sums")).write_text(f"{digest}  {relative}\n")
    (database / "status").write_text("".join(records))
    return tmp_path


def execute_probe(root: Path, owner_uid: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            bff_smoke.inventory_probe_source(
                str(root), os.getuid() if owner_uid is None else owner_uid
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def fixture_sbom(inventory: dict[str, Any]) -> dict[str, Any]:
    return {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": package["name"],
                "versionInfo": package["version"],
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": (
                            f"pkg:deb/debian/{package['name']}@{package['version']}"
                            f"?arch={package['architecture']}&distro=debian-12"
                        ),
                    }
                ],
            }
            for package in inventory["packages"]
        ],
    }


def test_real_probe_reconciles_files_database_and_sbom(inventory_root: Path) -> None:
    result = execute_probe(inventory_root)
    assert result.returncode == 0, result.stderr
    inventory = json.loads(result.stdout)
    assert {p["name"] for p in inventory["packages"]} == {*CORE_PACKAGES, "synthetic-data"}
    assert all(p["libraries"] for p in inventory["packages"] if p["name"] in CORE_PACKAGES)
    bff_smoke.verify_inventory_sbom(inventory, fixture_sbom(inventory))


@pytest.mark.parametrize(
    "mutation",
    (
        "missing",
        "empty",
        "directory",
        "symlink",
        "truncated",
        "missing-field",
        "duplicate-field",
        "duplicate-package",
        "missing-core",
        "orphan-package",
        "writable",
        "wrong-owner",
        "missing-list",
        "empty-list",
        "missing-library",
        "changed-library",
        "missing-checksum",
        "bad-checksum",
        "nul",
    ),
)
def test_actual_probe_rejects_incomplete_or_uncontrolled_inventory(
    inventory_root: Path,
    mutation: str,
) -> None:
    database = inventory_root / "var/lib/dpkg"
    status = database / "status"
    source = status.read_text()
    info = database / "info/libc6:amd64"
    library = inventory_root / "usr/lib/synthetic/libc6.so.1"
    owner = os.getuid()
    if mutation in {"missing", "directory", "symlink"}:
        status.unlink()
        if mutation == "directory":
            status.mkdir()
        if mutation == "symlink":
            (database / "copied-status").write_text(source)
            status.symlink_to("copied-status")
    elif mutation == "empty":
        status.write_text("")
    elif mutation == "truncated":
        status.write_text(source[:-1])
    elif mutation == "missing-field":
        status.write_text(source.replace("Architecture: amd64\n", "", 1))
    elif mutation == "duplicate-field":
        status.write_text(source.replace("Package: libc6", "Package: libc6\nPackage: libc6"))
    elif mutation == "duplicate-package":
        status.write_text(source + source.split("\n\n")[0] + "\n\n")
    elif mutation == "missing-core":
        status.write_text(source.split("\n\n", 1)[1])
    elif mutation == "orphan-package":
        status.write_text(source[: source.index("Package: synthetic-data")])
    elif mutation == "writable":
        status.chmod(0o666)
    elif mutation == "wrong-owner":
        owner += 1
    elif mutation == "missing-list":
        info.with_suffix(".list").unlink()
    elif mutation == "empty-list":
        info.with_suffix(".list").write_text("")
    elif mutation == "missing-library":
        library.unlink()
    elif mutation == "changed-library":
        library.write_bytes(b"\x7fELFchanged")
    elif mutation == "missing-checksum":
        info.with_suffix(".md5sums").unlink()
    elif mutation == "bad-checksum":
        info.with_suffix(".md5sums").write_text("malformed\n")
    elif mutation == "nul":
        status.write_text(source + "\x00\n\n")
    else:
        raise AssertionError("unknown mutation")
    result = execute_probe(inventory_root, owner)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize("mutation", ("empty", "omission", "version", "arch", "duplicate", "purl"))
def test_sbom_catalog_omission_and_misbinding_are_not_clean(
    inventory_root: Path,
    mutation: str,
) -> None:
    inventory = json.loads(execute_probe(inventory_root).stdout)
    sbom = fixture_sbom(inventory)
    if mutation == "empty":
        sbom["packages"] = []
    elif mutation == "omission":
        sbom["packages"].pop()
    elif mutation == "version":
        sbom["packages"][0]["versionInfo"] = "0.0.0"
    elif mutation == "arch":
        reference = sbom["packages"][0]["externalRefs"][0]
        reference["referenceLocator"] = reference["referenceLocator"].replace("amd64", "arm64")
    elif mutation == "duplicate":
        sbom["packages"].append(copy.deepcopy(sbom["packages"][0]))
    elif mutation == "purl":
        sbom["packages"][0]["externalRefs"] = []
    with pytest.raises(RuntimeError, match="container SBOM failed"):
        bff_smoke.verify_inventory_sbom(inventory, sbom)


@pytest.mark.parametrize("image", ("api", "bff"))
@pytest.mark.parametrize("version", ("3.14.7", "3.14.4"))
def test_both_packed_gates_execute_the_shared_probe(
    monkeypatch: pytest.MonkeyPatch,
    image: str,
    version: str,
) -> None:
    module = api_smoke if image == "api" else bff_smoke
    calls = []

    def docker(*args: str, **kwargs: object) -> str:
        calls.append((args, kwargs))
        assert args[-3:] == ("python", "-c", bff_smoke.inventory_probe_source())
        assert ("app" if image == "api" else "bff") in args
        return json.dumps({"python": version, "owner_uid": 0})

    monkeypatch.setattr(module, "run", docker)
    if version == "3.14.7":
        assert module.verify_packed_inventory()["python"] == version
    else:
        with pytest.raises(RuntimeError, match="inventory/runtime differs"):
            module.verify_packed_inventory()
    assert len(calls) == 1
