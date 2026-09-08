"""Closed, value-free callback diagnostics and independently generated correlation."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum


class TokenFailureCategory(Enum):
    VERIFICATION = "verification"
    ID_FORMAT = "id_format"
    ACCESS_FORMAT = "access_format"
    ID_HEADER = "id_header"
    ACCESS_HEADER = "access_header"
    ID_SIGNING_KEY = "id_signing_key"
    ACCESS_SIGNING_KEY = "access_signing_key"
    ID_SIGNATURE = "id_signature"
    ACCESS_SIGNATURE = "access_signature"
    ID_REQUIRED_CLAIM = "id_required_claim"
    ACCESS_REQUIRED_CLAIM = "access_required_claim"
    ID_ISSUER = "id_issuer"
    ACCESS_ISSUER = "access_issuer"
    ID_AUDIENCE = "id_audience"
    ACCESS_AUDIENCE = "access_audience"
    ID_USE = "id_token_use"
    ACCESS_USE = "access_token_use"
    ID_TIME = "id_time"
    ACCESS_TIME = "access_time"
    ID_SUBJECT = "id_subject"
    ACCESS_SUBJECT = "access_subject"
    ID_FAMILY = "id_family"
    ACCESS_FAMILY = "access_family"
    ID_VERIFICATION = "id_verification"
    ACCESS_VERIFICATION = "access_verification"
    ID_NONCE = "id_nonce"
    ACCESS_CLIENT = "access_client"
    ACCESS_SCOPE = "access_scope"
    SUBJECT_CONTINUITY = "subject_continuity"
    FAMILY_CONTINUITY = "family_continuity"
    ID_AT_HASH = "id_at_hash"
    REFRESH_FORMAT = "refresh_format"


def safe_category(value: object) -> TokenFailureCategory:
    # Do not coerce strings, stringify objects, or inspect arbitrary exception text.
    return value if type(value) is TokenFailureCategory else TokenFailureCategory.VERIFICATION


@dataclass(frozen=True, slots=True)
class CallbackRequestId:
    # No constructor argument can introduce a caller-supplied ID into this type.
    value: str = field(default_factory=lambda: uuid.uuid4().hex, init=False)


@dataclass(frozen=True, slots=True)
class CallbackRejection:
    category: TokenFailureCategory
    request_id: CallbackRequestId


CALLBACK_REJECTION_EVENT = "callback_token_rejected"
