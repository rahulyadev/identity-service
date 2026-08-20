"""Internal identity/profile operations; no HTTP profile routes are exposed."""

from identity_service.services.errors import (
    IdentityNotFoundError,
    UserUnavailableError,
    VersionConflictError,
)
from identity_service.services.identity import IdentityProfileService
from identity_service.services.schemas import (
    ProfileView,
    ProviderIdentityInput,
    ProviderProfileInput,
)

__all__ = [
    "IdentityNotFoundError",
    "IdentityProfileService",
    "ProfileView",
    "ProviderIdentityInput",
    "ProviderProfileInput",
    "UserUnavailableError",
    "VersionConflictError",
]
