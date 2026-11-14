"""A stdio MCP server that forwards every message to the remote llms.ink MCP server (https://llms.ink/mcp).

For MCP clients that only launch local commands, or to pass ``LLMS_INK_KEY`` without configuring headers::

    uvx --from llms-ink llms-ink-mcp
    python -m llms_ink mcp

Each newline-delimited JSON-RPC message on stdin is POSTed to ``<base url>/mcp``; the answers (JSON or
server-sent events) are written to stdout, one per line. Requests run concurrently, so a slow
``tools/call`` doesn't hold up the others. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import urllib.error
import urllib.request
from typing import Any, BinaryIO, Dict, Iterable, List, Optional

from . import __version__
from .client import Client, _problem

ACCEPT = "application/json, text/event-stream"


class Bridge:
    """Forwards JSON-RPC messages to ``<base_url>/mcp``.

    ``key``, ``base_url`` and ``timeout`` work like :class:`llms_ink.Client`'s (``LLMS_INK_KEY``,
    ``LLMS_INK_API``). A rejected key turns every request into a JSON-RPC error; it never falls back to
    anonymous.
    """

    def __init__(self, key: Optional[str] = None, *, base_url: Optional[str] = None, timeout: float = 300.0) -> None:
        client = Client(key, base_url=base_url, timeout=timeout)
        self.key = client.key
        self.url = f"{client.base_url}/mcp"
        self.timeout = timeout
        self.session_id: Optional[str] = None
        self.protocol_version: Optional[str] = None

    def forward(self, message: Any) -> List[Any]:
        """Sends one JSON-RPC message; returns the messages to hand back to the client (none for a
        notification)."""
        is_request = isinstance(message, dict) and "id" in message and "method" in message
        headers = {"Content-Type": "application/json", "Accept": ACCEPT, "User-Agent": f"llms-ink-python/{__version__}"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        request = urllib.request.Request(self.url, data=json.dumps(message).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as res:
                session = res.headers.get("Mcp-Session-Id")
                if session:
                    self.session_id = session
                content_type = res.headers.get("Content-Type", "")
                body = res.read()
        except urllib.error.HTTPError as err:
            raw = err.read()
            answer = _json(raw)
            if isinstance(answer, dict) and answer.get("jsonrpc") == "2.0":
                return [answer]  # a JSON-RPC error sent with an HTTP error status
            problem = _problem(err, raw)
            text = f"llms.ink rejected LLMS_INK_KEY: {problem.detail} (HTTP 401)" if problem.code == "invalid_key" else f"llms.ink: {problem.detail} (HTTP {err.code})"
            if problem.retry_after is not None:
                text += f" Try again in {problem.retry_after}s."
            data = {"status": problem.status, "code": problem.code, "retryAfter": problem.retry_after}
            return [_error(message, -32000, text, data)] if is_request else _log(text)
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as err:
            text = f"Couldn't reach {self.url}: {getattr(err, 'reason', err)}"
            return [_error(message, -32603, text)] if is_request else _log(text)

        if not body.strip():
            return []
        if content_type.split(";")[0].strip().lower() == "text/event-stream":
            answers = [m for m in (_json(data) for data in _sse_data(body.decode("utf-8"))) if m is not None]
        else:
            answer = _json(body)
            if answer is None:
                text = f"{self.url} answered with something other than JSON."
                return [_error(message, -32603, text)] if is_request else _log(text)
            answers = answer if isinstance(answer, list) else [answer]
        if is_request and message.get("method") == "initialize":
            for answer in answers:
                version = answer.get("result", {}).get("protocolVersion") if isinstance(answer, dict) else None
                if isinstance(version, str):
                    self.protocol_version = version
        return answers

    def serve(self, stdin: BinaryIO, stdout: BinaryIO) -> None:
        """Reads messages from ``stdin`` until EOF and writes the answers to ``stdout``; returns once every
        request has been answered."""
        lock = threading.Lock()

        def write(messages: Iterable[Any]) -> None:
            for msg in messages:
                line = json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
                with lock:
                    stdout.write(line)
                    stdout.flush()

        def handle(message: Any) -> None:
            try:
                write(self.forward(message))
            except Exception as err:  # never let one message kill the bridge
                is_request = isinstance(message, dict) and "id" in message and "method" in message
                write([_error(message, -32603, f"llms-ink-mcp: {err}")] if is_request else _log(f"llms-ink-mcp: {err}"))

        workers: List[threading.Thread] = []
        for raw in stdin:
            if not raw.strip():
                continue
            message = _json(raw)
            if message is None:
                write([{"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}])
                continue
            if isinstance(message, dict) and message.get("method") == "initialize":
                handle(message)  # later requests need its protocol version
                continue
            worker = threading.Thread(target=handle, args=(message,))
            worker.start()
            workers.append(worker)
            workers = [w for w in workers if w.is_alive()]
        for worker in workers:
            worker.join()


def _json(raw: Any) -> Any:
    try:
        return json.loads(raw)
    except ValueError:
        return None


def _sse_data(text: str) -> List[str]:
    """The ``data`` of each server-sent event."""
    events: List[str] = []
    data: List[str] = []
    for line in text.splitlines() + [""]:
        if not line:
            if data:
                events.append("\n".join(data))
                data = []
        elif line.startswith("data:"):
            data.append(line[5:][1:] if line[5:].startswith(" ") else line[5:])
    return events


def _error(message: Dict[str, Any], code: int, text: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    error: Dict[str, Any] = {"code": code, "message": text}
    if data:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": message.get("id"), "error": error}


def _log(text: str) -> List[Any]:
    print(text, file=sys.stderr, flush=True)
    return []


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="llms-ink-mcp",
        description="A stdio MCP server for llms.ink: forwards every message to https://llms.ink/mcp.",
        epilog="Uses LLMS_INK_KEY as the API key when set (optional); a rejected key fails, never falls back to anonymous.",
    )
    parser.add_argument("--version", action="version", version=f"llms-ink {__version__}")
    parser.add_argument("--guard", action="store_true", help="Inspect responses locally with the optional guard (setup required).")
    args = parser.parse_args(argv)
    if args.guard:
        from .guard import main as guard_main
        return guard_main(["wrap", "--", sys.executable, "-m", "llms_ink", "mcp"])
    try:
        Bridge().serve(sys.stdin.buffer, sys.stdout.buffer)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
