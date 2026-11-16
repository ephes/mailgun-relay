from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Iterable

from mailgun_relay.config import TokenPolicy


class AuthError(Exception):
    """Authentication failed.

    Never includes the supplied credentials in its message so the error is safe to log.
    """


_REQUIRED_USERNAME = "api"
MAX_BASIC_DECODED_BYTES = 4096
MAX_BASIC_ENCODED_BYTES = 4 * ((MAX_BASIC_DECODED_BYTES + 2) // 3)
MAX_AUTHORIZATION_BYTES = len("Basic ") + MAX_BASIC_ENCODED_BYTES


def authenticate(authorization: str | None, policies: Iterable[TokenPolicy]) -> TokenPolicy:
    """Resolve an HTTP Basic Authorization header to a matched TokenPolicy.

    Verifies username `api` and constant-time compares the SHA-256 of the supplied
    password against every configured token; iterates every policy to avoid early-exit
    timing leaks.
    """
    if not authorization or not authorization.startswith("Basic "):
        raise AuthError("missing or unsupported Authorization scheme")

    # HTTP headers arrive as latin-1 (one character per wire byte). Bound the
    # entire value before slicing/stripping, including otherwise ignored padding.
    if len(authorization) > MAX_AUTHORIZATION_BYTES:
        raise AuthError("malformed Basic credentials")
    encoded = authorization[len("Basic ") :].strip()
    padding = 2 if encoded.endswith("==") else int(encoded.endswith("="))
    if (
        len(encoded) > MAX_BASIC_ENCODED_BYTES
        or len(encoded) * 3 // 4 - padding > MAX_BASIC_DECODED_BYTES
    ):
        raise AuthError("malformed Basic credentials")
    decoded: str | None = None
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8", errors="strict")
    except ValueError:
        # binascii.Error (bad base64) and UnicodeDecodeError are ValueErrors;
        # b64decode raises a plain ValueError for non-ASCII input, e.g. a
        # header byte >= 0x80 (headers are decoded as latin-1).
        pass
    # Raise after leaving the decoder's handler: even a suppressed context can
    # retain credential bytes in UnicodeDecodeError.object for direct callers.
    if decoded is None:
        raise AuthError("malformed Basic credentials")

    if ":" not in decoded:
        raise AuthError("malformed Basic credentials")

    username, _, password = decoded.partition(":")

    username_ok = hmac.compare_digest(username.encode("utf-8"), _REQUIRED_USERNAME.encode("utf-8"))
    supplied_digest = hashlib.sha256(password.encode("utf-8")).hexdigest()

    matched: TokenPolicy | None = None
    for policy in policies:
        if hmac.compare_digest(policy.token_sha256, supplied_digest):
            matched = policy

    if matched is None or not username_ok:
        raise AuthError("invalid credentials")

    return matched
