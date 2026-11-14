import pytest

from llms_ink import (
    CheckResult,
    Client,
    InvalidKey,
    LlmsInkError,
    QuotaExceeded,
    RateLimited,
    Result,
    __version__,
)

from .conftest import FULL, GOOD_KEY, LLMS


def test_llms_returns_the_index_as_a_result(stub):
    r = Client().llms("llmstxt.org")
    assert isinstance(r, Result)
    assert r.text == LLMS
    assert (r.url, r.kind, r.source, r.mode, r.title) == ("https://llmstxt.org/", "site", "native", "llms", "llms.txt")
    assert (r.tokens, r.pages, r.model, r.cached, r.generated_at) == (42, 1, None, True, "2026-11-14T00:00:00.000Z")
    assert r.media is None
    assert r.raw["generatedAt"] == r.generated_at
    assert stub.last["path"] == "/api/v0/llms"
    assert stub.last["query"] == {"url": "llmstxt.org", "mode": "llms"}
    assert "Authorization" not in stub.last["headers"]
    assert stub.last["headers"]["User-Agent"] == f"llms-ink-python/{__version__}"
    assert stub.last["headers"]["Accept"] == "application/json"


def test_full_mode_and_fresh(stub):
    r = Client().llms("llmstxt.org", mode="full", fresh=True)
    assert (r.mode, r.text) == ("full", FULL)
    assert stub.last["query"] == {"url": "llmstxt.org", "mode": "full", "fresh": "1"}


def test_bad_mode_fails_before_any_request(stub):
    with pytest.raises(ValueError, match="mode"):
        Client().llms("llmstxt.org", mode="index")
    assert stub.requests == []


def test_video_results_have_media(stub):
    m = Client().llms("youtu.be/x").media
    assert m is not None
    assert (m.duration, m.has_video, m.has_audio, m.downloads, m.is_live) == (61.5, True, True, ["mp4", "m4a"], None)
    assert m.transcript.source == "captions"
    assert (m.transcript.segments[0].start, m.transcript.segments[0].text) == (0, "Hello")


def test_check(stub):
    c = Client().check("llmstxt.org")
    assert stub.last["path"] == "/api/v0/check"
    assert stub.last["query"] == {"url": "llmstxt.org"}
    assert (c.found, c.status, c.title, c.sections, c.llms_full) == (True, 200, "llms.txt", 2, False)
    assert (c.links.total, c.links.broken[0].url, c.links.broken[0].status) == (3, "https://llmstxt.org/gone", 404)
    assert (c.issues[0].level, c.issues[0].code, c.issues[0].line) == ("error", "broken_link", 9)
    assert (c.summary.errors, c.summary.warnings, c.checked_at) == (1, 0, "2026-11-14T00:00:00.000Z")


def test_check_parsed(stub):
    p = Client().check("llmstxt.org").parsed
    assert (p.title, p.summary, p.details) == ("llms.txt", "A proposal.", None)
    assert [(s.name, s.optional, s.text) for s in p.sections] == [("Docs", False, None), ("Optional", True, "Extra.")]
    link = p.sections[0].links[0]
    assert (link.title, link.url, link.notes, link.line) == ("Intro", "https://llmstxt.org/intro.html", "Start here", 7)


def test_check_text_posts_markdown(stub):
    c = Client().check_text("# llms.txt\n")
    assert stub.last["path"] == "/api/v0/check"
    assert stub.last["query"] == {}
    assert stub.last["body"] == b"# llms.txt\n"
    assert stub.last["headers"]["Content-Type"].startswith("text/markdown")
    assert stub.last["headers"]["User-Agent"].startswith("llms-ink-python/")
    assert (c.site, c.url, c.llms_full, c.links.checked) == (None, None, None, 0)
    assert c.parsed.sections[0].links[0].url == "https://llmstxt.org/intro.html"


def test_check_text_base_and_links(stub):
    c = Client().check_text("# x", base="https://llmstxt.org/llms.txt", links=True)
    assert stub.last["query"] == {"base": "https://llmstxt.org/llms.txt", "links": "1"}
    assert c.url == "https://llmstxt.org/llms.txt"
    Client().check_text("# x", links=False)
    assert stub.last["query"] == {}


def test_check_text_problem(stub):
    with pytest.raises(LlmsInkError) as e:
        Client().check_text("  ")
    assert (e.value.status, e.value.code) == (400, "invalid_request")


def test_check_without_parsed_is_none():
    assert CheckResult.from_json({"found": False}).parsed is None


def test_key_argument_is_sent_as_bearer(stub):
    Client(GOOD_KEY).llms("llmstxt.org")
    assert stub.last["headers"]["Authorization"] == f"Bearer {GOOD_KEY}"


def test_key_comes_from_env_and_the_argument_wins(stub, monkeypatch):
    monkeypatch.setenv("LLMS_INK_KEY", GOOD_KEY)
    Client().llms("llmstxt.org")
    assert stub.last["headers"]["Authorization"] == f"Bearer {GOOD_KEY}"
    with pytest.raises(InvalidKey):
        Client("lk_other").llms("llmstxt.org")
    assert stub.last["headers"]["Authorization"] == "Bearer lk_other"


def test_blank_env_key_is_anonymous(stub, monkeypatch):
    monkeypatch.setenv("LLMS_INK_KEY", "  ")
    Client().llms("llmstxt.org")
    assert "Authorization" not in stub.last["headers"]


def test_invalid_key_raises_and_never_falls_back(stub):
    with pytest.raises(InvalidKey) as info:
        Client("lk_revoked").llms("llmstxt.org")
    assert (info.value.status, info.value.code) == (401, "invalid_key")
    assert info.value.detail == "That API key is unknown or revoked."
    assert len(stub.requests) == 1


def test_quota_exceeded_has_retry_after(stub):
    with pytest.raises(QuotaExceeded) as info:
        Client().llms("quota.test")
    assert (info.value.status, info.value.code, info.value.retry_after) == (429, "quota_exceeded", 3600)
    assert isinstance(info.value, LlmsInkError)


def test_rate_limited_has_retry_after(stub):
    with pytest.raises(RateLimited) as info:
        Client().llms("busy.test")
    assert (info.value.code, info.value.retry_after) == ("rate_limited", 12)


def test_other_problems_are_llms_ink_errors(stub):
    with pytest.raises(LlmsInkError) as info:
        Client().llms("login.test")
    assert type(info.value) is LlmsInkError
    assert (info.value.status, info.value.code, info.value.detail) == (422, "unprocessable", "That page needs a login.")
    assert str(info.value) == "That page needs a login."


def test_non_json_errors_keep_the_status(stub):
    with pytest.raises(LlmsInkError) as info:
        Client().llms("html.test")
    assert (info.value.status, info.value.code) == (502, None)
    assert "502" in info.value.detail


def test_unreachable_api():
    with pytest.raises(LlmsInkError, match="Couldn't reach http://127.0.0.1:9") as info:
        Client(base_url="http://127.0.0.1:9", timeout=5).llms("llmstxt.org")
    assert info.value.status is None


def test_base_url_argument_and_trailing_slash(stub, monkeypatch):
    monkeypatch.setenv("LLMS_INK_API", "http://127.0.0.1:9")
    assert Client(base_url=stub.base_url + "/").llms("llmstxt.org").text == LLMS
    monkeypatch.delenv("LLMS_INK_API")
    assert Client().base_url == "https://llms.ink"


def test_retry_after_parsing():
    from llms_ink.client import _retry_after

    assert _retry_after(None) is None
    assert _retry_after("120") == 120
    assert _retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0
    assert _retry_after("soon") is None
