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


def write_fixture_file(path: Path, contents: bytes) -> None:
    path.write_bytes(contents)
    path.chmod(0o600)


def create_inventory_fixture(root: Path) -> Path:
    root.chmod(0o700)
    for relative_directory in (
        "var",
        "var/lib",
        "var/lib/dpkg",
        "var/lib/dpkg/info",
        "usr",
        "usr/lib",
        "usr/lib/synthetic",
        "etc",
        "etc/ld.so.conf.d",
    ):
        directory = root / relative_directory
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
    database = root / "var/lib/dpkg"
    records = []
    for name in (*CORE_PACKAGES, "synthetic-data"):
        records.append(
            f"Package: {name}\nStatus: install ok installed\nArchitecture: amd64\n"
            "Version: 1:2.3-4+deb12u1\nConffiles:\n /etc/synthetic fixture-checksum\n"
            "Description: synthetic fixture\n continuation\n\n"
        )
        relative = f"usr/lib/synthetic/{name}.so.1"
        contents = b"\x7fELFsynthetic-not-executable-" + name.encode()
        write_fixture_file(root / relative, contents)
        write_fixture_file(
            database / "info" / (name + ":amd64.list"),
            ("/etc/ld.so.conf.d\n/" + relative + "\n").encode(),
        )
        digest = hashlib.md5(contents, usedforsecurity=False).hexdigest()
        write_fixture_file(
            database / "info" / (name + ":amd64.md5sums"), f"{digest}  {relative}\n".encode()
        )
    write_fixture_file(database / "status", "".join(records).encode())
    return root


@pytest.fixture
def inventory_root(tmp_path: Path) -> Path:
    return create_inventory_fixture(tmp_path)


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


def pristine_inventory(root: Path) -> dict[str, Any]:
    result = execute_probe(root)
    assert result.returncode == 0, result.stderr
    inventory = json.loads(result.stdout)
    assert {p["name"] for p in inventory["packages"]} == {*CORE_PACKAGES, "synthetic-data"}
    assert all(p["libraries"] for p in inventory["packages"] if p["name"] in CORE_PACKAGES)
    bff_smoke.verify_inventory_sbom(inventory, fixture_sbom(inventory))
    return inventory


def test_real_probe_reconciles_files_database_and_sbom(inventory_root: Path) -> None:
    pristine_inventory(inventory_root)


@pytest.mark.parametrize("mask", (0o002, 0o022, 0o077), ids=("0002", "0022", "0077"))
@pytest.mark.parametrize("fail_scope", (False, True), ids=("normal", "exception"))
def test_fixture_permissions_ignore_umask_and_restore_isolated_scope(
    tmp_path: Path, mask: int, fail_scope: bool
) -> None:
    # Only this child changes its umask; neither pytest nor its caller is modified.
    source = """
import json
import os
from pathlib import Path
import runpy
import stat
import sys

helpers = runpy.run_path(sys.argv[1])
root = Path(sys.argv[2])
mask = int(sys.argv[3])
fail_scope = sys.argv[4] == "True"

class ExpectedScopeError(Exception):
    pass

original = os.umask(mask)
try:
    helpers["create_inventory_fixture"](root)
    for path in (root, *root.rglob("*")):
        info = path.lstat()
        assert stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
        expected = 0o700 if stat.S_ISDIR(info.st_mode) else 0o600
        assert stat.S_IMODE(info.st_mode) == expected, (path, oct(info.st_mode))
        assert info.st_uid == os.getuid() and info.st_gid == os.getgid()
    helpers["pristine_inventory"](root)
    if fail_scope:
        raise ExpectedScopeError
except ExpectedScopeError:
    assert fail_scope
finally:
    assert os.umask(original) == mask
restored = os.umask(original)
assert restored == original
print(json.dumps({"original": original, "restored": restored, "mask": mask}))
"""
    result = subprocess.run(
        [sys.executable, "-c", source, __file__, str(tmp_path), str(mask), str(fail_scope)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout)
    assert observed["mask"] == mask
    assert observed["restored"] == observed["original"]


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
    pristine_inventory(inventory_root)
    database = inventory_root / "var/lib/dpkg"
    status = database / "status"
    source = status.read_text()
    info = database / "info/libc6:amd64"
    library = inventory_root / "usr/lib/synthetic/libc6.so.1"
    owner = os.getuid()
    if mutation in {"missing", "directory", "symlink"}:
        status.unlink()
        if mutation == "directory":
            status.mkdir(mode=0o700)
            status.chmod(0o700)
        if mutation == "symlink":
            write_fixture_file(database / "copied-status", source.encode())
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
    expected_failure = {
        "missing": "FileNotFoundError",
        "empty": "metadata-size",
        "directory": "metadata-control",
        "symlink": "metadata-control",
        "truncated": "status-truncated",
        "missing-field": "status-required-fields",
        "duplicate-field": "duplicate-field",
        "duplicate-package": "duplicate-package",
        "missing-core": "core-package-coverage",
        "orphan-package": "orphan-package-ownership",
        "writable": "metadata-control",
        "wrong-owner": "metadata-control",
        "missing-list": "ownership-list",
        "empty-list": "metadata-size",
        "missing-library": "retained-library-missing",
        "changed-library": "library-checksum",
        "missing-checksum": "FileNotFoundError",
        "bad-checksum": "file-checksum-record",
        "nul": "metadata-framing",
    }[mutation]
    assert expected_failure in result.stderr.splitlines()[-1]


@pytest.mark.parametrize("mutation", ("empty", "omission", "version", "arch", "duplicate", "purl"))
def test_sbom_catalog_omission_and_misbinding_are_not_clean(
    inventory_root: Path,
    mutation: str,
) -> None:
    inventory = pristine_inventory(inventory_root)
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
