import io
import json
import os
import subprocess
import sys

from llms_ink import __version__
from llms_ink.mcp import Bridge

from .conftest import GOOD_KEY, LLMS

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}


def call(id, url):
    return {"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": "llms_txt", "arguments": {"url": url}}}


def serve(*messages, key=None):
    """Runs the bridge over in-memory stdio; returns its answers by id."""
    stdin = io.BytesIO(b"".join((m if isinstance(m, bytes) else json.dumps(m).encode()) + b"\n" for m in messages))
    stdout = io.BytesIO()
    Bridge(key).serve(stdin, stdout)
    return {a["id"]: a for a in map(json.loads, stdout.getvalue().splitlines())}


def test_forwards_initialize_list_and_call(stub):
    answers = serve(INIT, INITIALIZED, LIST, call(3, "llmstxt.org"))
    assert answers[1]["result"]["protocolVersion"] == "2025-06-18"
    assert answers[2]["result"]["tools"][0]["name"] == "llms_txt"
    assert answers[3]["result"]["content"][0]["text"] == LLMS
    assert len(answers) == 3  # nothing back for the notification

    first, *rest = stub.requests
    headers = {k.lower(): v for k, v in first["headers"].items()}
    assert first["path"] == "/mcp" and json.loads(first["body"]) == INIT
    assert headers["accept"] == "application/json, text/event-stream"
    assert headers["content-type"] == "application/json"
    assert headers["user-agent"] == f"llms-ink-python/{__version__}"
    assert "authorization" not in headers and "mcp-protocol-version" not in headers
    for r in rest:
        headers = {k.lower(): v for k, v in r["headers"].items()}
        assert headers["mcp-protocol-version"] == "2025-06-18"
        assert headers["mcp-session-id"] == "session-1"
        assert "authorization" not in headers


def test_sends_the_key_as_bearer(stub, monkeypatch):
    monkeypatch.setenv("LLMS_INK_KEY", f" {GOOD_KEY} ")
    assert serve(call(1, "llmstxt.org"))[1]["result"]["isError"] is False
    assert stub.last["headers"]["Authorization"] == f"Bearer {GOOD_KEY}"


def test_a_rejected_key_is_an_error_not_anonymous(stub, capsys):
    bad = "lk_" + "b" * 32
    answers = serve(INIT, INITIALIZED, call(2, "llmstxt.org"), key=bad)
    for id in (1, 2):
        error = answers[id]["error"]
        assert error["code"] == -32000
        assert error["message"] == "llms.ink rejected LLMS_INK_KEY: That API key is unknown or revoked. (HTTP 401)"
        assert error["data"] == {"status": 401, "code": "invalid_key", "retryAfter": None}
    assert "rejected LLMS_INK_KEY" in capsys.readouterr().err  # the notification's failure, logged
    assert all(r["headers"]["Authorization"] == f"Bearer {bad}" for r in stub.requests)


def test_problems_carry_retry_after(stub):
    error = serve(call(1, "busy.test"))[1]["error"]
    assert error["message"] == "llms.ink: Too many requests this minute. (HTTP 429) Try again in 12s."
    assert error["data"] == {"status": 429, "code": "rate_limited", "retryAfter": 12}


def test_reads_server_sent_events(stub):
    assert serve(call(7, "sse.test"))[7]["result"]["content"][0]["text"] == LLMS


def test_passes_json_rpc_errors_through(stub):
    answers = serve({"jsonrpc": "2.0", "id": 4, "method": "nope"}, b"{not json")
    assert answers[4]["error"] == {"code": -32601, "message": "Method not found"}
    assert answers[None]["error"] == {"code": -32700, "message": "Parse error"}


def test_unreachable_server(monkeypatch):
    monkeypatch.setenv("LLMS_INK_API", "http://127.0.0.1:9")
    monkeypatch.delenv("LLMS_INK_KEY", raising=False)
    error = serve(LIST)[2]["error"]
    assert error["code"] == -32603
    assert error["message"].startswith("Couldn't reach http://127.0.0.1:9/mcp: ")


def test_runs_over_stdio_as_a_module(stub):
    env = {**os.environ, "LLMS_INK_API": stub.base_url}
    env.pop("LLMS_INK_KEY", None)
    stdin = "".join(json.dumps(m) + "\n" for m in (INIT, INITIALIZED, LIST, call(3, "llmstxt.org")))
    run = subprocess.run([sys.executable, "-m", "llms_ink", "mcp"], input=stdin, env=env, capture_output=True, text=True, timeout=30)
    assert (run.returncode, run.stderr) == (0, "")
    answers = {a["id"]: a for a in map(json.loads, run.stdout.splitlines())}
    assert sorted(answers) == [1, 2, 3]
    assert answers[3]["result"]["content"][0]["text"] == LLMS
    version = subprocess.run([sys.executable, "-m", "llms_ink", "mcp", "--version"], capture_output=True, text=True)
    assert version.stdout == f"llms-ink {__version__}\n"
