"""Verify the production image-release workflow without executing a shell."""

from __future__ import annotations

import copy
import hashlib
import re
import sys
from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release-production.yml"
API_DOCKERFILE_PATH = ROOT / "Dockerfile"
BFF_DOCKERFILE_PATH = ROOT / "examples" / "reference_bff" / "Dockerfile"

BASE_IMAGE = (
    "python:3.14.4-slim-bookworm@"
    "sha256:fc74d22ffd0d5ac395a4b7bdda75a4539758862c49ebf3005647084631e63789"
)
QEMU_IMAGE = (
    "docker.io/tonistiigi/binfmt:qemu-v10.0.4@"
    "sha256:8f58e6214f4cc9dc83ce8f5acad1ece508eb6b20e696a8c1e9f274481982c541"
)
BUILDKIT_IMAGE = (
    "docker.io/moby/buildkit:buildx-stable-1@"
    "sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
)
REPOSITORY = "rahulyadev/identity-service"
AWS_ACCOUNT_ID = "402906459349"
AWS_REGION = "ap-south-1"
AWS_ROLE_ARN = "arn:aws:iam::402906459349:role/platform-infrastructure-production-identity-deployer"
ECR_REGISTRY = "402906459349.dkr.ecr.ap-south-1.amazonaws.com"
API_REPOSITORY = "platform-infrastructure-production-identity-api"
BFF_REPOSITORY = "platform-infrastructure-production-identity-bff"
API_IMAGE = f"{ECR_REGISTRY}/{API_REPOSITORY}"
BFF_IMAGE = f"{ECR_REGISTRY}/{BFF_REPOSITORY}"
PLATFORM = "linux/arm64"
RUN_SHELL = "bash --noprofile --norc -euo pipefail {0}"

ACTION_PINS = {
    "actions/checkout": (
        "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",  # pragma: allowlist secret
        "v7.0.0",
        2,
    ),
    "actions/setup-python": (
        "5fda3b95a4ea91299a34e894583c3862153e4b97",  # pragma: allowlist secret
        "v7.0.0",
        1,
    ),
    "docker/setup-qemu-action": (
        "29109295f81e9208d7d86ff1c6c12d2833863392",  # pragma: allowlist secret
        "v3.6.0",
        1,
    ),
    "docker/setup-buildx-action": (
        "e468171a9de216ec08956ac3ada2f0791b6bd435",  # pragma: allowlist secret
        "v3.11.1",
        1,
    ),
    "docker/build-push-action": (
        "263435318d21b8e681c14492fe198d362a7d2c83",  # pragma: allowlist secret
        "v6.18.0",
        4,
    ),
    "aws-actions/configure-aws-credentials": (
        "00943011d9042930efac3dcd3a170e4273319bc8",  # pragma: allowlist secret
        "v5.1.0",
        1,
    ),
    "aws-actions/amazon-ecr-login": (
        "062b18b96a7aff071d4dc91bc00c4c1a7945b076",  # pragma: allowlist secret
        "v2.0.1",
        1,
    ),
    "actions/attest-build-provenance": (
        "977bb373ede98d70efdf65b84cb5f73e068dcc2a",  # pragma: allowlist secret
        "v3.0.0",
        2,
    ),
    "actions/upload-artifact": (
        "ea165f8d65b6e75b540449e92b4886f43607fa02",  # pragma: allowlist secret
        "v4.6.2",
        1,
    ),
}

VALIDATE_IF = (
    "${{ github.repository == 'rahulyadev/identity-service' && "
    "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && "
    "github.event.pull_request == null && github.head_ref == '' && github.base_ref == '' }}"
)
RELEASE_IF = (
    "${{ needs.validate.result == 'success' && "
    "github.repository == 'rahulyadev/identity-service' && "
    "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && "
    "github.event.pull_request == null && github.head_ref == '' && github.base_ref == '' }}"
)

VALIDATE_STEP_ORDER = (
    "Guard dispatch context",
    "Check out exact dispatch source",
    "Verify exact checkout",
    "Set up exact Python",
    "Install locked validation environment",
    "Run complete repository validation",
)
RELEASE_STEP_ORDER = (
    "Guard release context",
    "Check out exact dispatch source",
    "Verify exact checkout",
    "Set up pinned ARM64 emulation",
    "Set up pinned Buildx",
    "Verify ARM64 builder support",
    "Prebuild API ARM64 OCI image",
    "Prebuild BFF ARM64 OCI image",
    "Configure short-lived AWS credentials",
    "Authenticate to exact ECR registry",
    "Push API immutable image",
    "Validate API digest",
    "Attest API digest",
    "Push BFF immutable image",
    "Validate BFF digest",
    "Attest BFF digest",
    "Write bounded release manifest",
    "Upload release manifest",
    "Report non-deployable partial release",
    "Remove local release files",
)

RUN_DIGESTS = {
    ("validate", "Guard dispatch context"): (
        "266ecdb1e18ca80e3a9ec98b6a753e791eb29ec3079a7557c51e29fae2654a4e"  # pragma: allowlist secret  # noqa: E501
    ),
    ("validate", "Verify exact checkout"): (
        "51e059ad31a96806bd378fefb09f79154d853e85f1df8e4da88355dccd55676d"  # pragma: allowlist secret  # noqa: E501
    ),
    ("validate", "Install locked validation environment"): (
        "bae5853fd1c0e7a57539c5b15e7d58e86605aad4d852355d4e3621c20f314b6c"  # pragma: allowlist secret  # noqa: E501
    ),
    ("validate", "Run complete repository validation"): (
        "dba2ea38e726423b3e7d0fc14783a889ae57877812dfcf613f4bcd7d2ba529a9"  # pragma: allowlist secret  # noqa: E501
    ),
    ("release", "Guard release context"): (
        "a721b97cd7911645331bf80740aac76332695fcf61d8eb4c47fee49d9d3f7295"  # pragma: allowlist secret  # noqa: E501
    ),
    ("release", "Verify exact checkout"): (
        "51e059ad31a96806bd378fefb09f79154d853e85f1df8e4da88355dccd55676d"  # pragma: allowlist secret  # noqa: E501
    ),
    ("release", "Verify ARM64 builder support"): (
        "da5d3734f1991cb69e2d2889379cd33be0338b7d176a71705e0921d6f91e3301"  # pragma: allowlist secret  # noqa: E501
    ),
    ("release", "Validate API digest"): (
        "b6bd5ecc600ab13b7d6a41816ed04b6f22f899712142a4f3e8f85f4244eb5cdc"  # pragma: allowlist secret  # noqa: E501
    ),
    ("release", "Validate BFF digest"): (
        "34f0ade0423d6c602a1ae46652896838faea843f0debc21f72feb6ce0a68a125"  # pragma: allowlist secret  # noqa: E501
    ),
    ("release", "Write bounded release manifest"): (
        "238a4e205f2de8f9bf477b1bbfe33b0a645dc4b0b3c929940f923f258c048e97"  # pragma: allowlist secret  # noqa: E501
    ),
    ("release", "Report non-deployable partial release"): (
        "3b053d11b02f76ec568e908d27f5386e64656357bacbe9078899f47f43c848e5"  # pragma: allowlist secret  # noqa: E501
    ),
    ("release", "Remove local release files"): (
        "7c574da11c0fbbfd4c7f8d8419a6301c4d7900da0406aa9c9144fce89c9a32d3"  # pragma: allowlist secret  # noqa: E501
    ),
}

RUN_METADATA = {
    ("validate", "Guard dispatch context"): {
        "name": "Guard dispatch context",
        "timeout-minutes": 1,
        "env": {
            "EXPECTED_REPOSITORY": REPOSITORY,
            "EXPECTED_EVENT": "workflow_dispatch",
            "EXPECTED_REF": "refs/heads/main",
        },
    },
    ("validate", "Verify exact checkout"): {
        "name": "Verify exact checkout",
        "timeout-minutes": 1,
    },
    ("validate", "Install locked validation environment"): {
        "name": "Install locked validation environment",
        "timeout-minutes": 10,
    },
    ("validate", "Run complete repository validation"): {
        "name": "Run complete repository validation",
        "timeout-minutes": 35,
    },
    ("release", "Guard release context"): {
        "name": "Guard release context",
        "timeout-minutes": 1,
        "env": {
            "EXPECTED_REPOSITORY": REPOSITORY,
            "EXPECTED_EVENT": "workflow_dispatch",
            "EXPECTED_REF": "refs/heads/main",
        },
    },
    ("release", "Verify exact checkout"): {
        "name": "Verify exact checkout",
        "timeout-minutes": 1,
    },
    ("release", "Verify ARM64 builder support"): {
        "name": "Verify ARM64 builder support",
        "timeout-minutes": 2,
        "env": {"BUILDER_PLATFORMS": "${{ steps.buildx.outputs.platforms }}"},
    },
    ("release", "Validate API digest"): {
        "name": "Validate API digest",
        "timeout-minutes": 1,
        "env": {"API_DIGEST": "${{ steps.push-api.outputs.digest }}"},
    },
    ("release", "Validate BFF digest"): {
        "name": "Validate BFF digest",
        "timeout-minutes": 1,
        "env": {"BFF_DIGEST": "${{ steps.push-bff.outputs.digest }}"},
    },
    ("release", "Write bounded release manifest"): {
        "name": "Write bounded release manifest",
        "timeout-minutes": 2,
        "env": {
            "SOURCE_REPOSITORY": REPOSITORY,
            "SOURCE_SHA": "${{ github.sha }}",
            "WORKFLOW_RUN_ID": "${{ github.run_id }}",
            "WORKFLOW_RUN_ATTEMPT": "${{ github.run_attempt }}",
            "API_DIGEST": "${{ steps.push-api.outputs.digest }}",
            "BFF_DIGEST": "${{ steps.push-bff.outputs.digest }}",
        },
    },
    ("release", "Report non-deployable partial release"): {
        "name": "Report non-deployable partial release",
        "if": "${{ failure() && steps.push-api.outputs.digest != '' }}",
        "timeout-minutes": 1,
        "env": {
            "API_DIGEST": "${{ steps.push-api.outputs.digest }}",
            "BFF_DIGEST": "${{ steps.push-bff.outputs.digest }}",
        },
    },
    ("release", "Remove local release files"): {
        "name": "Remove local release files",
        "if": "${{ always() }}",
        "timeout-minutes": 1,
    },
}

LABELS = (
    "org.opencontainers.image.source=https://github.com/rahulyadev/identity-service\n"
    "org.opencontainers.image.revision=${{ github.sha }}\n"
)

FORBIDDEN_RAW = (
    re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE),
    re.compile(r"(?m)^\s*secrets\s*:\s*inherit\s*$", re.IGNORECASE),
    re.compile(r"aws-access-key-id", re.IGNORECASE),
    re.compile(r"aws-secret-access-key", re.IGNORECASE),
    re.compile(r"aws-session-token", re.IGNORECASE),
    re.compile(r"(?m)^\s*continue-on-error\s*:", re.IGNORECASE),
)
FORBIDDEN_RUN = (
    re.compile(r"(?m)^\s*set\s+-[^\n]*x"),
    re.compile(r"(?m)^\s*(?:printenv|env)(?:\s|$)"),
    re.compile(r"(?m)^\s*aws(?:\s|$)"),
    re.compile(r"(?m)^\s*(?:curl|wget)[^\n]*\|"),
    re.compile(r"(?m)^\s*(?:pip|pip3|npm|apt|apt-get)\s+(?:install|add)\b"),
    re.compile(r"(?m)^\s*docker\s+(?:push|manifest|login)\b"),
    re.compile(r"\b(?:ssm|ec2|secretsmanager|cognito|route53|rollback)\b", re.IGNORECASE),
    re.compile(r"\b(?:batch-delete-image|delete-repository|put-image)\b", re.IGNORECASE),
)


class ContractError(Exception):
    """A value-free workflow contract failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class StrictLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML 1.2-like loader with duplicate-key rejection."""


StrictLoader.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for resolver_key, resolvers in tuple(StrictLoader.yaml_implicit_resolvers.items()):
    StrictLoader.yaml_implicit_resolvers[resolver_key] = [
        resolver for resolver in resolvers if resolver[0] != "tag:yaml.org,2002:bool"
    ]
StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


def _construct_unique_mapping(
    loader: StrictLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[object, object]:
    if not isinstance(node, yaml.nodes.MappingNode):
        raise ContractError("yaml-mapping")
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as error:
            raise ContractError("yaml-key") from error
        if duplicate:
            raise ContractError("yaml-duplicate-key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _mapping(value: object, code: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ContractError(code)
    return cast(dict[str, object], value)


def _sequence(value: object, code: str) -> list[object]:
    if not isinstance(value, list):
        raise ContractError(code)
    return value


def _expect(actual: object, expected: object, code: str) -> None:
    if type(actual) is not type(expected) or actual != expected:
        raise ContractError(code)


def _strict_safe_load(source: str) -> object:
    loader = StrictLoader(source)
    try:
        loaded: object = loader.get_single_data()
        return loaded
    finally:
        loader.dispose()


def parse_workflow_source(source: str) -> dict[str, object]:
    """Parse one bounded workflow document with no YAML indirection."""

    if not isinstance(source, str) or not source or len(source.encode("utf-8")) > 100_000:
        raise ContractError("workflow-size")
    if "\x00" in source or "\r" in source:
        raise ContractError("workflow-encoding")
    for pattern in FORBIDDEN_RAW:
        if pattern.search(source):
            raise ContractError("workflow-forbidden")
    try:
        for token in yaml.scan(source, Loader=StrictLoader):
            if isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken)):
                raise ContractError("yaml-indirection")
            if isinstance(token, yaml.tokens.ScalarToken) and token.value == "<<":
                raise ContractError("yaml-merge")
        loaded = _strict_safe_load(source)
    except ContractError:
        raise
    except (UnicodeError, yaml.YAMLError) as error:
        raise ContractError("workflow-yaml") from error
    return _mapping(loaded, "workflow-root")


def _action_step(
    name: str,
    action: str,
    timeout: int,
    inputs: dict[str, object],
    *,
    step_id: str | None = None,
) -> dict[str, object]:
    pin, _, _ = ACTION_PINS[action]
    step: dict[str, object] = {
        "name": name,
        "uses": f"{action}@{pin}",
        "timeout-minutes": timeout,
    }
    if step_id is not None:
        step["id"] = step_id
    step["with"] = inputs
    return step


def _checkout_step() -> dict[str, object]:
    return _action_step(
        "Check out exact dispatch source",
        "actions/checkout",
        5,
        {
            "ref": "${{ github.sha }}",
            "fetch-depth": 1,
            "persist-credentials": False,
        },
    )


def _build_step(
    name: str,
    dockerfile: str,
    *,
    push: bool,
    step_id: str | None = None,
    destination: str | None = None,
    image: str | None = None,
) -> dict[str, object]:
    inputs: dict[str, object] = {
        "context": ".",
        "file": dockerfile,
        "target": "runtime",
        "platforms": PLATFORM,
        "builder": "${{ steps.buildx.outputs.name }}",
        "pull": True,
        "push": push,
    }
    if destination is not None:
        inputs["outputs"] = destination
    if image is not None:
        inputs["tags"] = f"${{{{ env.{image}_IMAGE }}}}:${{{{ env.RELEASE_TAG }}}}"
    inputs.update({"labels": LABELS, "sbom": True, "provenance": "mode=max"})
    return _action_step(
        name,
        "docker/build-push-action",
        30,
        inputs,
        step_id=step_id,
    )


def _expected_action_steps() -> dict[tuple[str, str], dict[str, object]]:
    return {
        ("validate", "Check out exact dispatch source"): _checkout_step(),
        ("validate", "Set up exact Python"): _action_step(
            "Set up exact Python",
            "actions/setup-python",
            5,
            {"python-version": "3.14.4", "check-latest": False},
        ),
        ("release", "Check out exact dispatch source"): _checkout_step(),
        ("release", "Set up pinned ARM64 emulation"): _action_step(
            "Set up pinned ARM64 emulation",
            "docker/setup-qemu-action",
            5,
            {"image": QEMU_IMAGE, "platforms": "arm64", "cache-image": True},
        ),
        ("release", "Set up pinned Buildx"): _action_step(
            "Set up pinned Buildx",
            "docker/setup-buildx-action",
            5,
            {
                "version": "v0.36.1",
                "driver": "docker-container",
                "driver-opts": f"image={BUILDKIT_IMAGE}",
                "install": False,
                "use": True,
                "cleanup": True,
            },
            step_id="buildx",
        ),
        ("release", "Prebuild API ARM64 OCI image"): _build_step(
            "Prebuild API ARM64 OCI image",
            "Dockerfile",
            push=False,
            destination=(
                "type=oci,dest=${{ runner.temp }}/identity-api-"
                "${{ github.run_id }}-${{ github.run_attempt }}.oci"
            ),
        ),
        ("release", "Prebuild BFF ARM64 OCI image"): _build_step(
            "Prebuild BFF ARM64 OCI image",
            "examples/reference_bff/Dockerfile",
            push=False,
            destination=(
                "type=oci,dest=${{ runner.temp }}/identity-bff-"
                "${{ github.run_id }}-${{ github.run_attempt }}.oci"
            ),
        ),
        ("release", "Configure short-lived AWS credentials"): _action_step(
            "Configure short-lived AWS credentials",
            "aws-actions/configure-aws-credentials",
            3,
            {
                "role-to-assume": AWS_ROLE_ARN,
                "aws-region": AWS_REGION,
                "audience": "sts.amazonaws.com",
                "role-duration-seconds": 900,
                "role-session-name": (
                    "identity-release-${{ github.run_id }}-${{ github.run_attempt }}"
                ),
                "output-credentials": False,
                "unset-current-credentials": True,
            },
        ),
        ("release", "Authenticate to exact ECR registry"): _action_step(
            "Authenticate to exact ECR registry",
            "aws-actions/amazon-ecr-login",
            3,
            {
                "registries": AWS_ACCOUNT_ID,
                "mask-password": True,
                "skip-logout": False,
            },
        ),
        ("release", "Push API immutable image"): _build_step(
            "Push API immutable image",
            "Dockerfile",
            push=True,
            step_id="push-api",
            image="API",
        ),
        ("release", "Attest API digest"): _action_step(
            "Attest API digest",
            "actions/attest-build-provenance",
            5,
            {
                "subject-name": "${{ env.API_IMAGE }}",
                "subject-digest": "${{ steps.push-api.outputs.digest }}",
                "push-to-registry": True,
            },
        ),
        ("release", "Push BFF immutable image"): _build_step(
            "Push BFF immutable image",
            "examples/reference_bff/Dockerfile",
            push=True,
            step_id="push-bff",
            image="BFF",
        ),
        ("release", "Attest BFF digest"): _action_step(
            "Attest BFF digest",
            "actions/attest-build-provenance",
            5,
            {
                "subject-name": "${{ env.BFF_IMAGE }}",
                "subject-digest": "${{ steps.push-bff.outputs.digest }}",
                "push-to-registry": True,
            },
        ),
        ("release", "Upload release manifest"): _action_step(
            "Upload release manifest",
            "actions/upload-artifact",
            3,
            {
                "name": (
                    "identity-production-release-${{ github.run_id }}-${{ github.run_attempt }}"
                ),
                "path": "release-manifest.json",
                "if-no-files-found": "error",
                "retention-days": 7,
                "compression-level": 9,
                "overwrite": False,
                "include-hidden-files": False,
            },
        ),
    }


EXPECTED_ACTION_STEPS = _expected_action_steps()


def _validate_action_comments(source: str) -> None:
    for action, (pin, version, expected_count) in ACTION_PINS.items():
        expected_line = f"uses: {action}@{pin} # {version}"
        if source.count(expected_line) != expected_count:
            raise ContractError("action-comment")


def _validate_run_step(job_name: str, step: dict[str, object]) -> None:
    name = step.get("name")
    if not isinstance(name, str) or not isinstance(step.get("run"), str):
        raise ContractError("run-step")
    key = (job_name, name)
    if key not in RUN_DIGESTS or key not in RUN_METADATA:
        raise ContractError("run-step-order")
    command = cast(str, step["run"])
    for pattern in FORBIDDEN_RUN:
        if pattern.search(command):
            raise ContractError("run-command")
    metadata = {item: value for item, value in step.items() if item != "run"}
    _expect(metadata, RUN_METADATA[key], "run-metadata")
    digest = hashlib.sha256(command.encode("utf-8")).hexdigest()
    _expect(digest, RUN_DIGESTS[key], "run-contract")


def _validate_steps(job_name: str, value: object, order: tuple[str, ...]) -> None:
    steps = _sequence(value, f"{job_name}-steps")
    mappings = [_mapping(step, f"{job_name}-step") for step in steps]
    names = tuple(step.get("name") for step in mappings)
    _expect(names, order, f"{job_name}-step-order")
    for step in mappings:
        name = cast(str, step["name"])
        if "run" in step:
            _validate_run_step(job_name, step)
            continue
        key = (job_name, name)
        if key not in EXPECTED_ACTION_STEPS:
            raise ContractError("action-step")
        _expect(step, EXPECTED_ACTION_STEPS[key], "action-contract")
        uses = step.get("uses")
        if not isinstance(uses, str):
            raise ContractError("action-use")
        match = re.fullmatch(r"([a-z0-9-]+/[a-z0-9-]+)@([0-9a-f]{40})", uses)
        if match is None or match.group(1) not in ACTION_PINS:
            raise ContractError("action-pin")
        if ACTION_PINS[match.group(1)][0] != match.group(2):
            raise ContractError("action-pin")


def verify_workflow_source(source: str) -> dict[str, object]:
    """Verify the complete static workflow contract and return parsed data for tests."""

    workflow = parse_workflow_source(source)
    _expect(
        set(workflow),
        {"name", "on", "permissions", "concurrency", "defaults", "jobs"},
        "workflow-keys",
    )
    _expect(workflow["name"], "release production images", "workflow-name")
    _expect(workflow["on"], {"workflow_dispatch": {}}, "workflow-trigger")
    _expect(workflow["permissions"], {}, "workflow-permissions")
    _expect(
        workflow["concurrency"],
        {"group": "identity-production-image-release", "cancel-in-progress": False},
        "workflow-concurrency",
    )
    _expect(workflow["defaults"], {"run": {"shell": RUN_SHELL}}, "workflow-shell")

    jobs = _mapping(workflow["jobs"], "jobs")
    _expect(set(jobs), {"validate", "release"}, "job-inventory")
    validate = _mapping(jobs["validate"], "validate-job")
    release = _mapping(jobs["release"], "release-job")
    validate_meta = {key: value for key, value in validate.items() if key != "steps"}
    release_meta = {key: value for key, value in release.items() if key != "steps"}
    _expect(
        validate_meta,
        {
            "name": "Validate exact source",
            "if": VALIDATE_IF,
            "runs-on": "ubuntu-24.04",
            "timeout-minutes": 45,
            "permissions": {"contents": "read"},
        },
        "validate-job-contract",
    )
    _expect(
        release_meta,
        {
            "name": "Build and publish immutable ARM64 images",
            "needs": "validate",
            "if": RELEASE_IF,
            "environment": "production",
            "runs-on": "ubuntu-24.04",
            "timeout-minutes": 90,
            "permissions": {
                "contents": "read",
                "id-token": "write",
                "attestations": "write",
            },
            "env": {
                "AWS_ACCOUNT_ID": AWS_ACCOUNT_ID,
                "AWS_REGION": AWS_REGION,
                "AWS_ROLE_ARN": AWS_ROLE_ARN,
                "ECR_REGISTRY": ECR_REGISTRY,
                "API_REPOSITORY": API_REPOSITORY,
                "BFF_REPOSITORY": BFF_REPOSITORY,
                "API_IMAGE": API_IMAGE,
                "BFF_IMAGE": BFF_IMAGE,
                "API_DOCKERFILE": "Dockerfile",
                "BFF_DOCKERFILE": "examples/reference_bff/Dockerfile",
                "BUILD_TARGET": "runtime",
                "BUILD_PLATFORM": PLATFORM,
                "RELEASE_TAG": (
                    "sha-${{ github.sha }}-run-${{ github.run_id }}-"
                    "attempt-${{ github.run_attempt }}"
                ),
                "DOCKER_BUILD_RECORD_UPLOAD": "false",
                "DOCKER_BUILD_SUMMARY": "false",
            },
        },
        "release-job-contract",
    )
    _validate_steps("validate", validate["steps"], VALIDATE_STEP_ORDER)
    _validate_steps("release", release["steps"], RELEASE_STEP_ORDER)
    _validate_action_comments(source)
    return workflow


def _dockerfile_from_instructions(source: str) -> tuple[tuple[str, str | None], ...]:
    instructions: list[tuple[str, str | None]] = []
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or not line.upper().startswith("FROM "):
            continue
        match = re.fullmatch(r"FROM\s+(\S+)(?:\s+AS\s+([A-Za-z0-9_.-]+))?", line, re.IGNORECASE)
        if match is None:
            raise ContractError("dockerfile-from")
        instructions.append((match.group(1), match.group(2)))
    return tuple(instructions)


def verify_dockerfile_sources(api_source: str, bff_source: str) -> None:
    """Require the reviewed multi-architecture base in every external stage."""

    _expect(
        _dockerfile_from_instructions(api_source),
        (
            (BASE_IMAGE, "runtime-dependencies"),
            (BASE_IMAGE, "runtime"),
            ("runtime-dependencies", "test"),
        ),
        "api-base-image",
    )
    _expect(
        _dockerfile_from_instructions(bff_source),
        ((BASE_IMAGE, "runtime-dependencies"), (BASE_IMAGE, "runtime")),
        "bff-base-image",
    )


def verify_repository() -> dict[str, object]:
    """Verify only the three fixed release-contract inputs."""

    try:
        workflow_source = WORKFLOW_PATH.read_text(encoding="utf-8")
        api_source = API_DOCKERFILE_PATH.read_text(encoding="utf-8")
        bff_source = BFF_DOCKERFILE_PATH.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ContractError("repository-input") from error
    workflow = verify_workflow_source(workflow_source)
    verify_dockerfile_sources(api_source, bff_source)
    return workflow


def main() -> int:
    if len(sys.argv) != 1:
        print("release workflow contract failed: arguments", file=sys.stderr)
        return 1
    try:
        verify_repository()
    except ContractError as error:
        print(f"release workflow contract failed: {error.code}", file=sys.stderr)
        return 1
    except Exception:
        print("release workflow contract failed: unexpected", file=sys.stderr)
        return 1
    print("production release workflow contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
