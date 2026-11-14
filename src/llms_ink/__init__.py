"""Turn any link — site, docs section, page, GitHub repo, PDF or video — into llms.txt and llms-full.txt.

    >>> from llms_ink import Client
    >>> Client().llms("llmstxt.org").text
"""

__version__ = "0.5.0"

from .client import (  # noqa: E402
    DEFAULT_BASE_URL,
    BrokenLink,
    CheckIssue,
    CheckLinks,
    CheckResult,
    CheckSummary,
    Client,
    Media,
    Parsed,
    ParsedLink,
    ParsedSection,
    Result,
    Segment,
    Transcript,
)
from .inspect import InspectionReceipt  # noqa: E402
from .errors import InvalidKey, LlmsInkError, QuotaExceeded, RateLimited  # noqa: E402

__all__ = [
    "DEFAULT_BASE_URL",
    "BrokenLink",
    "CheckIssue",
    "CheckLinks",
    "CheckResult",
    "CheckSummary",
    "Client",
    "InvalidKey",
    "InspectionReceipt",
    "LlmsInkError",
    "Media",
    "Parsed",
    "ParsedLink",
    "ParsedSection",
    "QuotaExceeded",
    "RateLimited",
    "Result",
    "Segment",
    "Transcript",
    "__version__",
]
