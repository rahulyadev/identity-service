"""Internal identity/profile operations used by the authenticated HTTP adapter."""

from identity_service.services.errors import (
    IdentityNotFoundError,
    UserUnavailableError,
    VersionConflictError,
)
from identity_service.services.identity import IdentityProfileService
from identity_service.services.schemas import (
    BootstrapProfileResult,
    ProfileView,
    ProviderIdentityInput,
    ProviderProfileInput,
)

__all__ = [
    "BootstrapProfileResult",
    "IdentityNotFoundError",
    "IdentityProfileService",
    "ProfileView",
    "ProviderIdentityInput",
    "ProviderProfileInput",
    "UserUnavailableError",
    "VersionConflictError",
]
