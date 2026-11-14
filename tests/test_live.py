"""One real call to https://llms.ink. Skipped by default; run with: pytest -m live"""

import pytest

from llms_ink import Client, LlmsInkError

pytestmark = pytest.mark.live


def test_llmstxt_org(monkeypatch):
    monkeypatch.delenv("LLMS_INK_API", raising=False)
    r = Client().llms("llmstxt.org")
    assert r.mode == "llms"
    assert r.text.startswith("# ")
    assert r.tokens > 0
    assert r.url.startswith("https://llmstxt.org")


def test_check_text(monkeypatch):
    monkeypatch.delenv("LLMS_INK_API", raising=False)
    text = "# Example\n\n> An example.\n\n## Docs\n\n- [A](/a): first\n"
    try:
        r = Client().check_text(text, base="https://example.com/llms.txt")
    except LlmsInkError as err:
        if err.status in (404, 405):
            pytest.skip(f"POST /api/v0/check not deployed ({err.status})")
        raise
    assert (r.parsed.title, r.parsed.summary) == ("Example", "An example.")
    link = r.parsed.sections[0].links[0]
    assert (link.url, link.notes) == ("https://example.com/a", "first")
    assert r.llms_full is None
