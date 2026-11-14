"""Typed errors from the API's RFC 9457 problem details (codes at https://llms.ink/docs/#errors)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class LlmsInkError(Exception):
    """An API error, or llms.ink couldn't be reached (then ``status`` and ``code`` are ``None``).

    ``code`` is the problem's machine-readable code (``invalid_url``, ``unprocessable``, ``upstream_error``…),
    ``detail`` the human-readable message, ``errors`` the per-parameter issues of ``invalid_request``.
    ``retry_after`` is the ``Retry-After`` header in seconds, when the response had one.
    """

    def __init__(
        self,
        detail: str,
        *,
        status: Optional[int] = None,
        code: Optional[str] = None,
        title: Optional[str] = None,
        errors: Optional[List[Dict[str, Any]]] = None,
        retry_after: Optional[int] = None,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status = status
        self.code = code
        self.title = title
        self.errors = errors or []
        self.retry_after = retry_after

    def __repr__(self) -> str:
        return f"{type(self).__name__}(status={self.status!r}, code={self.code!r}, detail={self.detail!r})"


class InvalidKey(LlmsInkError):
    """401 ``invalid_key``: the API key is unknown or revoked. Requests never fall back to anonymous."""


class RateLimited(LlmsInkError):
    """429 ``rate_limited``: too many requests this minute; wait ``retry_after`` seconds."""


class QuotaExceeded(LlmsInkError):
    """429 ``quota_exceeded``: the daily quota of new links is used up; ``retry_after`` is the seconds until it
    resets (midnight UTC). Cached links still work."""


_BY_CODE = {"invalid_key": InvalidKey, "rate_limited": RateLimited, "quota_exceeded": QuotaExceeded}


def error_for(code: Optional[str]) -> type:
    """The exception class for a problem ``code``."""
    return _BY_CODE.get(code or "", LlmsInkError)
