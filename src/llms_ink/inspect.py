"""Explicit hosted inspection; independent from the optional local guard."""
from __future__ import annotations

import hashlib
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

from .errors import LlmsInkError


@dataclass(frozen=True)
class InspectionReceipt:
    """Validated, unsigned receipt bound to the exact supplied UTF-8 text."""
    detection: str
    coverage: str
    recommendation: str
    reason: str
    model_revision: str
    policy_revision: str
    preprocessing_revision: str
    content_digest: str
    input_tokens: int
    inspected_tokens: int
    windows: int
    enforced: bool


def _receipt(r: Any, digest: str, status: int) -> InspectionReceipt:
    def fail() -> None:
        raise LlmsInkError("Inspect returned an invalid or unsupported receipt. Withhold the content.", code="inspection_unavailable")
    if not isinstance(r, dict):
        fail()
    if status not in (200, 422, 503) or (status != 200 and r.get("detection") != "unknown"):
        fail()
    expected = {"contentDigest": digest, "modelRevision": "4a43fec65a670e48835d8e8c85c705b4b0d1c907", "policyRevision": "llms-ink-inspect-1", "preprocessingRevision": "utf8-json-stringify-1"}
    if any(r.get(k) != v for k, v in expected.items()) or r.get("enforced") is not False:
        fail()
    if any(type(r.get(k)) is not int or r[k] < 0 for k in ("inputTokens", "inspectedTokens", "windows")):
        fail()
    total, scanned, windows = r["inputTokens"], r["inspectedTokens"], r["windows"]
    if total > 9007199254740991 or scanned > total or windows > 43:
        fail()
    detection, coverage, recommendation, reason = (r.get(k) for k in ("detection", "coverage", "recommendation", "reason"))
    valid = False
    if detection == "no_finding":
        valid = coverage == "complete" and recommendation == "continue" and reason == "no_finding" and total <= 8192 and scanned == total and (total == 0 or windows > 0)
    elif detection == "flagged":
        valid = coverage in ("complete", "partial") and recommendation == "withhold" and reason in ("instruction_pattern", "model_detection") and total <= 8192 and scanned > 0 and windows > 0 and (coverage != "complete" or scanned == total)
    elif detection == "unknown":
        valid = coverage == "none" and recommendation == "withhold" and scanned == 0 and windows == 0 and reason in ("token_limit", "model_unavailable", "model_failure", "inspection_timeout")
    if not valid:
        fail()
    return InspectionReceipt(detection, coverage, recommendation, reason, r["modelRevision"], r["policyRevision"], r["preprocessingRevision"], digest, total, scanned, windows, False)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def inspect_text(text: str, key: Optional[str], base_url: str, timeout: float) -> InspectionReceipt:
    from .client import _problem
    from . import __version__
    if not key:
        raise LlmsInkError("Inspect requires an inspection-enabled API key.", code="key_required")
    url = urllib.parse.urlsplit(base_url)
    if url.username or url.password or url.query or url.fragment or (url.scheme != "https" and not (url.scheme == "http" and url.hostname in ("localhost", "127.0.0.1", "::1"))):
        raise ValueError("Inspect requires HTTPS (or localhost for development).")
    if not isinstance(text, str) or not text:
        raise ValueError("Inspect requires nonempty text.")
    content = text.encode("utf-8", errors="strict")
    body = json.dumps({"format": "text", "content": text}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > 131072:
        raise ValueError("Inspect request exceeds 128 KiB after JSON encoding.")
    digest = hashlib.sha256(content).hexdigest()
    request = urllib.request.Request(base_url + "/api/v0/inspect", data=body, headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json", "Accept": "application/json", "User-Agent": f"llms-ink-python/{__version__}"})
    try:
        try:
            response = urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout)
        except urllib.error.HTTPError as err:
            response = err
        with response:
            raw = response.read(16385)
            status = response.code
            if len(raw) > 16384:
                raise LlmsInkError("Inspect response exceeds 16 KiB.", code="inspection_unavailable")
            try:
                data = json.loads(raw)
            except (ValueError, UnicodeError):
                raise LlmsInkError("Inspect returned invalid JSON.", code="inspection_unavailable") from None
            if status != 200 and isinstance(data, dict) and "detection" not in data:
                raise _problem(response, raw)
            return _receipt(data, digest, status)
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError):
        raise LlmsInkError("Inspection did not return a receipt. Withhold the content.", code="inspection_unavailable") from None
