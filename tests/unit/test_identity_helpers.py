from __future__ import annotations

import uuid

from identity_service.models import Profile
from identity_service.services.errors import VersionConflictError
from identity_service.services.identity import advisory_lock_key, new_user_id


def test_application_ids_are_uuid_v4() -> None:
    generated = {new_user_id() for _ in range(100)}
    assert len(generated) == 100
    assert all(value.version == 4 and value.variant == uuid.RFC_4122 for value in generated)


def test_advisory_key_is_stable_signed_int64_and_exact() -> None:
    first = advisory_lock_key("Issuer", "Subject")
    assert first == advisory_lock_key("Issuer", "Subject")
    assert first != advisory_lock_key("issuer", "Subject")
    assert first != advisory_lock_key("Issuer", "subject")
    assert -(2**63) <= first < 2**63


def test_effective_display_name_prefers_user_override() -> None:
    profile = Profile(
        user_id=uuid.uuid4(),
        provider_email_verified=False,
        provider_display_name="Provider",
        display_name_override=None,
        version=1,
    )
    assert profile.effective_display_name == "Provider"
    profile.display_name_override = "Local"
    assert profile.effective_display_name == "Local"


def test_version_conflict_has_stable_domain_code() -> None:
    error = VersionConflictError(3)
    assert error.code == "profile_version_conflict"
    assert error.expected_version == 3
    assert "3" not in str(error)
