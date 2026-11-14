"""A local stub of the llms.ink API, answering like the real one for a few known links."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlsplit

import pytest

LLMS = "# llms.txt\n\n> A proposal to standardise on using an /llms.txt file.\n\n## Docs\n\n- [Intro](https://llmstxt.org/intro.html)\n"
FULL = "# llms.txt\n\n> A proposal.\n\n## Intro\n\nThe whole page.\n"
GOOD_KEY = "lk_" + "a" * 32


def result(url: str, mode: str) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "url": f"https://{url}/",
        "kind": "site",
        "source": "native",
        "mode": mode,
        "title": "llms.txt",
        "text": LLMS if mode == "llms" else FULL,
        "tokens": 42,
        "pages": 1,
        "model": None,
        "cached": True,
        "generatedAt": "2026-11-14T00:00:00.000Z",
    }
    if url.startswith("youtu.be"):
        body.update(
            kind="video",
            source="generated",
            model="gpt",
            media={
                "duration": 61.5,
                "hasVideo": True,
                "hasAudio": True,
                "thumbnail": "https://i.ytimg.com/vi/x/hq.jpg",
                "downloads": ["mp4", "m4a"],
                "transcript": {"source": "captions", "segments": [{"start": 0, "end": 2.5, "text": "Hello"}]},
            },
        )
    return body


CHECK = {
    "site": "https://llmstxt.org",
    "url": "https://llmstxt.org/llms.txt",
    "found": True,
    "status": 200,
    "title": "llms.txt",
    "tokens": 300,
    "sections": 2,
    "links": {"total": 3, "checked": 3, "broken": [{"url": "https://llmstxt.org/gone", "status": 404}]},
    "llmsFull": False,
    "issues": [{"level": "error", "code": "broken_link", "line": 9, "message": "https://llmstxt.org/gone answers HTTP 404."}],
    "summary": {"errors": 1, "warnings": 0},
    "checkedAt": "2026-11-14T00:00:00.000Z",
    "parsed": {
        "title": "llms.txt",
        "summary": "A proposal.",
        "details": None,
        "sections": [
            {"name": "Docs", "optional": False, "text": None, "links": [{"title": "Intro", "url": "https://llmstxt.org/intro.html", "notes": "Start here", "line": 7}]},
            {"name": "Optional", "optional": True, "text": "Extra.", "links": []},
        ],
    },
}
CHECK_TEXT = {**CHECK, "site": None, "url": None, "llmsFull": None, "links": {"total": 1, "checked": 0, "broken": []}}

PROBLEMS = {
    "quota.test": (429, "quota_exceeded", "Daily quota of new links used up.", {"Retry-After": "3600"}),
    "busy.test": (429, "rate_limited", "Too many requests this minute.", {"Retry-After": "12"}),
    "login.test": (422, "unprocessable", "That page needs a login.", {}),
}


class Stub:
    def __init__(self) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.base_url = ""

    @property
    def last(self) -> Dict[str, Any]:
        return self.requests[-1]


def handler(stub: Stub):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def send(self, status: int, body: Any, content_type: str = "application/json", headers: Dict[str, str] = {}) -> None:
            data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def problem(self, status: int, code: str, detail: str, headers: Dict[str, str] = {}) -> None:
            body = {"type": f"{stub.base_url}/docs/#errors", "title": "Error", "status": status, "code": code, "detail": detail}
            self.send(status, body, "application/problem+json", headers)

        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            query = {k: v[0] for k, v in parse_qs(parts.query).items()}
            stub.requests.append({"path": parts.path, "query": query, "headers": dict(self.headers)})
            auth = self.headers.get("Authorization")
            if auth and auth != f"Bearer {GOOD_KEY}":
                return self.problem(401, "invalid_key", "That API key is unknown or revoked.")
            url = query.get("url", "")
            if url == "html.test":
                return self.send(502, "<html>Bad gateway</html>", "text/html")
            if url in PROBLEMS:
                status, code, detail, headers = PROBLEMS[url]
                return self.problem(status, code, detail, headers)
            if parts.path == "/api/v0/llms":
                return self.send(200, result(url, query.get("mode", "llms")))
            if parts.path == "/api/v0/check":
                return self.send(200, CHECK)
            self.problem(404, "not_found", "Not found.")

        def do_POST(self) -> None:
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            parts = urlsplit(self.path)
            query = {k: v[0] for k, v in parse_qs(parts.query).items()}
            stub.requests.append({"path": self.path, "query": query, "body": raw, "headers": dict(self.headers)})
            auth = self.headers.get("Authorization")
            if auth and auth != f"Bearer {GOOD_KEY}":
                return self.problem(401, "invalid_key", "That API key is unknown or revoked.")
            if parts.path == "/api/v0/check":
                if not raw.strip():
                    return self.problem(400, "invalid_request", "The body is empty.")
                base = query.get("base")
                return self.send(200, {**CHECK_TEXT, "url": base, "site": base and base.rsplit("/", 1)[0]})
            if self.path != "/mcp":
                return self.problem(404, "not_found", "Not found.")
            try:
                msg = json.loads(raw)
            except ValueError:
                return self.send(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            if "id" not in msg:
                return self.send(202, "")
            answer = lambda result: {"jsonrpc": "2.0", "id": msg["id"], "result": result}  # noqa: E731
            params = msg.get("params", {})
            if msg["method"] == "initialize":
                result = {"protocolVersion": params["protocolVersion"], "capabilities": {"tools": {}}, "serverInfo": {"name": "llms.ink", "version": "0"}}
                return self.send(200, answer(result), headers={"Mcp-Session-Id": "session-1"})
            if msg["method"] == "tools/list":
                return self.send(200, answer({"tools": [{"name": "llms_txt", "inputSchema": {"type": "object"}}]}))
            if msg["method"] == "tools/call":
                url = params["arguments"]["url"]
                if url in PROBLEMS:
                    status, code, detail, headers = PROBLEMS[url]
                    return self.problem(status, code, detail, headers)
                body = answer({"content": [{"type": "text", "text": LLMS}], "isError": False})
                if url == "sse.test":
                    return self.send(200, f"event: message\ndata: {json.dumps(body)}\n\n", "text/event-stream")
                return self.send(200, body)
            self.send(200, {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "Method not found"}})

    return Handler


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch):
    """The stub server, with LLMS_INK_API pointing at it and LLMS_INK_KEY unset."""
    s = Stub()
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(s))
    s.base_url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("LLMS_INK_API", s.base_url)
    monkeypatch.delenv("LLMS_INK_KEY", raising=False)
    yield s
    server.shutdown()
    server.server_close()
