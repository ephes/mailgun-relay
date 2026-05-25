from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from collections.abc import Iterable

from mailgun_relay.config import TokenPolicy


class AuthError(Exception):
    """Authentication failed.

    Never includes the supplied credentials in its message so the error is safe to log.
    """


_REQUIRED_USERNAME = "api"


def authenticate(authorization: str | None, policies: Iterable[TokenPolicy]) -> TokenPolicy:
    """Resolve an HTTP Basic Authorization header to a matched TokenPolicy.

    Verifies username `api` and constant-time compares the SHA-256 of the supplied
    password against every configured token; iterates every policy to avoid early-exit
    timing leaks.
    """
    if not authorization or not authorization.startswith("Basic "):
        raise AuthError("missing or unsupported Authorization scheme")

    encoded = authorization[len("Basic ") :].strip()
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise AuthError("malformed Basic credentials") from exc

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
