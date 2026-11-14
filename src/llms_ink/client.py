"""The llms.ink JSON API (https://llms.ink/docs/) over the standard library's urllib."""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional

from . import __version__
from .errors import LlmsInkError, error_for

DEFAULT_BASE_URL = "https://llms.ink"
MODES = ("llms", "full")


@dataclass
class Segment:
    """A transcript line; ``start`` and ``end`` are seconds into the source video."""

    start: float
    end: float
    text: str


@dataclass
class Transcript:
    source: str
    segments: List[Segment]


@dataclass
class Media:
    """Video results only: what ``/api/v0/frame`` and ``/api/v0/media`` can serve."""

    duration: Optional[float]
    has_video: bool
    has_audio: bool
    thumbnail: Optional[str]
    downloads: List[str]
    is_live: Optional[bool] = None
    transcript: Optional[Transcript] = None

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "Media":
        t = d.get("transcript")
        return cls(
            duration=d.get("duration"),
            has_video=bool(d.get("hasVideo")),
            has_audio=bool(d.get("hasAudio")),
            thumbnail=d.get("thumbnail"),
            downloads=list(d.get("downloads") or []),
            is_live=d.get("isLive"),
            transcript=Transcript(
                source=t.get("source", ""),
                segments=[Segment(s["start"], s["end"], s["text"]) for s in t.get("segments") or []],
            )
            if t
            else None,
        )


@dataclass
class Result:
    """``GET /api/v0/llms``: the llms.txt or llms-full.txt of a link and what it was built from.

    ``kind`` is ``site``, ``section``, ``page``, ``repo``, ``document`` or ``video``; ``source`` is ``native``
    (published by the site) or ``generated`` (made by llms.ink). ``text`` is the Markdown file.
    """

    url: str
    kind: str
    source: str
    mode: str
    title: str
    text: str
    tokens: int
    pages: int
    model: Optional[str]
    cached: bool
    generated_at: str
    media: Optional[Media] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "Result":
        return cls(
            url=d.get("url", ""),
            kind=d.get("kind", ""),
            source=d.get("source", ""),
            mode=d.get("mode", ""),
            title=d.get("title", ""),
            text=d.get("text", ""),
            tokens=d.get("tokens", 0),
            pages=d.get("pages", 0),
            model=d.get("model"),
            cached=bool(d.get("cached")),
            generated_at=d.get("generatedAt", ""),
            media=Media.from_json(d["media"]) if d.get("media") else None,
            raw=d,
        )


@dataclass
class CheckIssue:
    """``level`` is ``error``, ``warning`` or ``info``; ``code`` names the check (``missing_title``, ``broken_link``…)."""

    level: str
    code: str
    line: Optional[int]
    message: str


@dataclass
class BrokenLink:
    url: str
    status: int  # 0 when it didn't answer in time


@dataclass
class CheckLinks:
    total: int
    checked: int
    broken: List[BrokenLink]


@dataclass
class CheckSummary:
    errors: int
    warnings: int


@dataclass
class ParsedLink:
    """``- [title](url): notes``. ``url`` is resolved against ``base`` / the fetched URL when possible."""

    title: str
    url: str
    notes: Optional[str]
    line: int


@dataclass
class ParsedSection:
    """An H2 section; ``optional`` when it's named "Optional"; ``text`` is its non-link content."""

    name: str
    optional: bool
    text: Optional[str]
    links: List[ParsedLink]


@dataclass
class Parsed:
    """The structure of an llms.txt: H1 ``title``, blockquote ``summary``, ``details`` before the first H2."""

    title: Optional[str]
    summary: Optional[str]
    details: Optional[str]
    sections: List[ParsedSection]

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "Parsed":
        return cls(
            title=d.get("title"),
            summary=d.get("summary"),
            details=d.get("details"),
            sections=[
                ParsedSection(
                    name=s["name"],
                    optional=bool(s.get("optional")),
                    text=s.get("text"),
                    links=[ParsedLink(l["title"], l["url"], l.get("notes"), l.get("line", 0)) for l in s.get("links") or []],
                )
                for s in d.get("sections") or []
            ],
        )


@dataclass
class CheckResult:
    """``GET``/``POST /api/v0/check``: an llms.txt checked against the format and its links.

    ``site`` and ``url`` are None for :meth:`Client.check_text` without ``base``; ``llms_full`` is None when it
    wasn't checked; ``parsed`` is None when nothing was found.
    """

    site: Optional[str]
    url: Optional[str]
    found: bool
    status: int
    title: Optional[str]
    tokens: int
    sections: int
    links: CheckLinks
    llms_full: Optional[bool]
    issues: List[CheckIssue]
    summary: CheckSummary
    checked_at: str
    parsed: Optional[Parsed] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "CheckResult":
        links = d.get("links") or {}
        summary = d.get("summary") or {}
        return cls(
            site=d.get("site"),
            url=d.get("url"),
            found=bool(d.get("found")),
            status=d.get("status", 0),
            title=d.get("title"),
            tokens=d.get("tokens", 0),
            sections=d.get("sections", 0),
            links=CheckLinks(
                total=links.get("total", 0),
                checked=links.get("checked", 0),
                broken=[BrokenLink(b["url"], b["status"]) for b in links.get("broken") or []],
            ),
            llms_full=None if d.get("llmsFull") is None else bool(d["llmsFull"]),
            issues=[CheckIssue(i["level"], i["code"], i.get("line"), i["message"]) for i in d.get("issues") or []],
            summary=CheckSummary(errors=summary.get("errors", 0), warnings=summary.get("warnings", 0)),
            checked_at=d.get("checkedAt", ""),
            parsed=Parsed.from_json(d["parsed"]) if d.get("parsed") else None,
            raw=d,
        )


class Client:
    """A client for https://llms.ink.

    ``key`` is an optional API key (``lk_…``), sent as ``Authorization: Bearer``; it defaults to the
    ``LLMS_INK_KEY`` environment variable. Without one, requests are anonymous and share the free limits.
    ``base_url`` defaults to ``LLMS_INK_API`` or https://llms.ink. Building a big site or a video can take
    minutes, hence the long default ``timeout`` (seconds).
    """

    def __init__(
        self,
        key: Optional[str] = None,
        *,
        base_url: Optional[str] = None,
        timeout: float = 300.0,
    ) -> None:
        key = key if key is not None else os.environ.get("LLMS_INK_KEY")
        self.key = key.strip() if key and key.strip() else None
        self.base_url = (base_url or os.environ.get("LLMS_INK_API") or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout

    def __repr__(self) -> str:
        return f"Client(base_url={self.base_url!r}, key={'set' if self.key else None!r})"

    def llms(self, url: str, mode: str = "llms", fresh: bool = False) -> Result:
        """llms.txt (``mode='llms'``, an index of links) or llms-full.txt (``mode='full'``, the content inlined)
        for any public link. ``fresh=True`` skips the cache and rebuilds (counts against the daily quota)."""
        if mode not in MODES:
            raise ValueError(f"mode must be 'llms' (the index) or 'full' (llms-full.txt), not {mode!r}")
        params = {"url": url, "mode": mode}
        if fresh:
            params["fresh"] = "1"
        return Result.from_json(self._get("/api/v0/llms", params))

    def check(self, url: str) -> CheckResult:
        """Checks a site's published llms.txt against the format and that its links answer."""
        return CheckResult.from_json(self._get("/api/v0/check", {"url": url}))

    def check_text(self, text: str, base: Optional[str] = None, links: bool = False) -> CheckResult:
        """Parses and checks llms.txt text you already have (``POST /api/v0/check``). ``base`` is the public URL
        it lives at (resolves relative links, reported as ``url``/``site``); ``links=True`` also checks up to 25
        linked URLs and llms-full.txt next to ``base``."""
        params: Dict[str, str] = {}
        if base:
            params["base"] = base
        if links:
            params["links"] = "1"
        return CheckResult.from_json(self._get("/api/v0/check", params, text.encode("utf-8")))

    def _get(self, path: str, params: Dict[str, str], body: Optional[bytes] = None) -> Dict[str, Any]:
        headers = {"Accept": "application/json", "User-Agent": f"llms-ink-python/{__version__}"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"
        if body is not None:
            headers["Content-Type"] = "text/markdown; charset=utf-8"
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        request = urllib.request.Request(f"{self.base_url}{path}{query}", data=body, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as res:
                body = res.read()
        except urllib.error.HTTPError as err:
            raise _problem(err, err.read()) from None
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as err:
            reason = getattr(err, "reason", err)
            raise LlmsInkError(f"Couldn't reach {self.base_url}: {reason}") from err
        try:
            return json.loads(body)
        except ValueError as err:
            raise LlmsInkError(f"{self.base_url}{path} answered with something other than JSON.") from err


def _problem(err: urllib.error.HTTPError, raw: bytes) -> LlmsInkError:
    """An HTTP error response and its body → the typed error for its problem ``code``."""
    try:
        data = json.loads(raw)
    except ValueError:
        data = None
    if not isinstance(data, dict):
        data = {}
    status = data.get("status") if isinstance(data.get("status"), int) else err.code
    detail = data.get("detail") or data.get("title") or f"HTTP {err.code} {err.reason or 'error'}"
    code = data.get("code")
    return error_for(code)(
        detail,
        status=status,
        code=code,
        title=data.get("title"),
        errors=data.get("errors"),
        retry_after=_retry_after(err.headers.get("Retry-After") if err.headers else None),
    )


def _retry_after(value: Optional[str]) -> Optional[int]:
    """``Retry-After`` as seconds: delta-seconds, or an HTTP date turned into seconds from now."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return int(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0, int((when - datetime.now(timezone.utc)).total_seconds()))


def _metadata(result: Result) -> Dict[str, Any]:
    """Document metadata for the LangChain and LlamaIndex loaders."""
    return {
        "url": result.url,
        "title": result.title,
        "kind": result.kind,
        "source": result.source,
        "mode": result.mode,
        "tokens": result.tokens,
        "generated_at": result.generated_at,
    }
