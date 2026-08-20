"""Typed domain failures for internal callers."""


class IdentityServiceError(Exception):
    code = "identity_service_error"


class IdentityNotFoundError(IdentityServiceError):
    code = "identity_not_found"


class UserUnavailableError(IdentityServiceError):
    code = "user_unavailable"


class VersionConflictError(IdentityServiceError):
    code = "profile_version_conflict"

    def __init__(self, expected_version: int) -> None:
        super().__init__("profile version does not match the expected version")
        self.expected_version = expected_version
