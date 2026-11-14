"""Bounded stdio proxy for legacy MCP tool servers. Inspection precedes delivery.

Optional trusted local policy restricts outgoing calls on this connection.
This is not a sandbox for the subprocess or an authorization layer for host tools.
Unsolicited server notifications and stderr are suppressed, so they cannot become
an alternate uninspected content path. Unsupported protocol features fail closed.
"""
from __future__ import annotations

import json
import queue
import re
import subprocess
import sys
import threading
import time
from typing import Any, BinaryIO

from .guard import MAX_BYTES, receipt
from .guard_policy import Policy, decode, tool_digest

VERSIONS = {"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
MAX_PENDING = 16
MAX_TOOLS = 512


def parse(raw: bytes) -> dict:
    message = decode(raw)
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        raise ValueError("Invalid message")
    return message


def id_key(value: Any) -> tuple:
    if type(value) is str and len(value) <= 128:
        return (str, value)
    if type(value) is int and abs(value) <= 2**53 - 1:
        return (int, value)
    raise ValueError("Invalid request id")


def error(id: Any, message: str, code: int = -32001) -> dict:
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}


def withheld(id: Any, method: str, reason: str) -> dict:
    message = f"Local guard withheld this response ({reason}). Review the source or use a smaller text response."
    if method == "tools/call":
        return {"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": message}], "isError": True}}
    return error(id, message)


def supported_result(method: str, body: Any) -> bool:
    if not isinstance(body, dict):
        return False
    # Bound traversal as well as bytes; treat every string/key as inspectable.
    work = [(body, 0)]
    count = 0
    while work:
        value, depth = work.pop()
        count += 1
        if depth > 48 or count > 30000:
            return False
        if isinstance(value, dict):
            # No opaque blob or multimodal/resource indirection in this release.
            if value.get("type") in {"image", "audio", "resource_link", "resource"} or "blob" in value:
                return False
            work.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            work.extend((v, depth + 1) for v in value)
    if method == "tools/call":
        content = body.get("content", [])
        if not isinstance(content, list) or any(not isinstance(b, dict) or b.get("type") != "text" or not isinstance(b.get("text"), str) for b in content):
            return False
        if "structuredContent" in body and not isinstance(body["structuredContent"], dict):
            return False
    return True


class Proxy:
    def __init__(self, command: list[str], guard: Any, *, policy: Policy | None = None, request_timeout: float = 120, log: Any = None):
        self.command, self.guard = list(command), guard
        self.policy = policy
        if policy is not None:
            policy.check_command(self.command)
        self.request_timeout = request_timeout
        self.log = log or (lambda data: print(json.dumps(data, separators=(",", ":")), file=sys.stderr, flush=True))
        self.pending: dict[tuple, dict] = {}
        self.tools: dict[str, str] = {}
        self.seen: set[tuple] = set()
        self.cancelled: set[tuple] = set()
        self.state_lock = threading.Lock()
        self.discovery_failed = False
        self.initialized = False
        self.initializing = False
        self.client_eof = False
        self.events: queue.Queue = queue.Queue(maxsize=32)
        self.stop = threading.Event()

    def _reader(self, stream: BinaryIO, source: str) -> None:
        try:
            while not self.stop.is_set():
                raw = stream.readline(MAX_BYTES + 1)
                if not raw:
                    self._event((source, None))
                    return
                if len(raw) > MAX_BYTES:
                    self._event(("fatal", "message_too_large"))
                    return
                if raw.strip():
                    if source == "client":
                        try:
                            msg = parse(raw)
                            if msg.get("method") == "notifications/cancelled":
                                key = id_key(msg.get("params", {}).get("requestId"))
                                with self.state_lock:
                                    self.cancelled.add(key)
                        except (ValueError, TypeError, AttributeError, RecursionError):
                            pass
                    self._event((source, raw))
        except (OSError, ValueError):
            self._event(("fatal", "transport_failure"))

    def _event(self, event: tuple) -> None:
        while not self.stop.is_set():
            try:
                self.events.put(event, timeout=0.1)
                return
            except queue.Full:
                pass

    @staticmethod
    def _write(stream: BinaryIO, message: dict) -> None:
        stream.write(json.dumps(message, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8") + b"\n")
        stream.flush()

    def _client(self, raw: bytes, child: Any, output: BinaryIO) -> None:
        msg = parse(raw)
        method = msg.get("method")
        if not isinstance(method, str):
            raise ValueError("Client responses are not supported")
        params = msg.get("params", {})
        if not isinstance(params, dict):
            raise ValueError("Invalid params")
        if "id" not in msg:
            if method == "notifications/cancelled":
                key = id_key(params.get("requestId"))
                self.pending.pop(key, None)
                with self.state_lock:
                    self.cancelled.discard(key)
                self._write(child.stdin, msg)
            elif method == "notifications/initialized" and self.initialized:
                self._write(child.stdin, msg)
            return
        id = msg["id"]
        key = id_key(id)
        if key in self.seen or len(self.seen) >= 4096:
            raise ValueError("Request ids must be unique within a bounded connection")
        self.seen.add(key)
        with self.state_lock:
            if key in self.cancelled:
                return
        if len(self.pending) >= MAX_PENDING:
            self._write(output, error(id, "Local guard is busy. Retry after pending requests finish."))
            return
        if method == "initialize":
            if self.initialized or self.initializing or params.get("protocolVersion") not in VERSIONS:
                self._write(output, error(id, "Guard supports one legacy MCP initialization per connection.", -32602))
                return
            self.initializing = True
            msg = {**msg, "params": {**params, "capabilities": {}}}
        elif not self.initialized:
            self._write(output, error(id, "Initialize the guarded connection first.", -32600))
            return
        elif method == "tools/call":
            name = params.get("name")
            if type(name) is not str or self.discovery_failed or name not in self.tools:
                self._write(output, error(id, "Discover an inspected tool with tools/list before calling it.", -32602))
                return
            if self.policy is not None:
                arguments = params.get("arguments", {})
                # Unknown metadata/extensions could change execution semantics.
                # Do not forward them, even alongside an otherwise allowed call.
                if (set(msg) != {"jsonrpc", "id", "method", "params"}
                        or set(params) - {"name", "arguments"} or type(arguments) is not dict
                        or not self.policy.allows(name, self.tools[name], arguments)):
                    self.log({"outcome": "denied", "reason": "tool_policy"})
                    self._write(output, error(id, "Local policy denied this tool call. Ask the policy owner to review the required action."))
                    return
                msg = {**msg, "params": {"name": name, "arguments": arguments}}
        elif method not in {"tools/list", "ping"}:
            self._write(output, error(id, "This guard supports tool discovery and calls only.", -32601))
            return
        self.pending[key] = {"id": id, "method": method, "at": time.monotonic()}
        self._write(child.stdin, msg)

    def _server(self, raw: bytes, child: Any, output: BinaryIO) -> None:
        msg = parse(raw)
        if "method" in msg:
            # Sampling/elicitation is not advertised. No server-originated content
            # reaches the client via notifications, logs or reverse requests.
            if "id" in msg:
                id_key(msg["id"])
                self._write(child.stdin, error(msg["id"], "Client requests are unavailable through this guard.", -32601))
            return
        key = id_key(msg.get("id"))
        request = self.pending.pop(key, None)
        if request is None:
            return  # includes responses to requests the client cancelled
        method, id = request["method"], request["id"]
        if ("result" in msg) == ("error" in msg):
            raise ValueError("Invalid response")
        body = msg.get("result", msg.get("error"))
        if not supported_result(method if "result" in msg else "error", body):
            result = receipt("unscanned", "unsupported_content", coverage="none")
        else:
            text = json.dumps(body, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            try:
                result = self.guard.inspect(text)
            except Exception:
                result = receipt("unscanned", "model_unavailable", coverage="none")
        with self.state_lock:
            if key in self.cancelled:
                return
        # Only fixed enum/number fields go to stderr; never log bodies, identifiers,
        # descriptions, upstream exception strings or attacker-supplied metadata.
        self.log({k: result[k] for k in ("outcome", "reason", "tokens", "windows", "elapsedMs") if k in result})
        if result.get("outcome") != "allow" or result.get("coverage") != "complete":
            if method == "tools/list":
                self.discovery_failed = True
            self._write(output, withheld(id, method, result.get("reason", "inspection_failed")))
            if method == "initialize":
                raise ValueError("Initialization was withheld")
            return
        if method == "initialize":
            if "error" in msg or body.get("protocolVersion") not in VERSIONS:
                self._write(output, error(id, "Upstream initialization failed or selected an unsupported version."))
                raise ValueError("Initialization failed")
            msg = {**msg, "result": {**body, "capabilities": {"tools": {"listChanged": False}}}}
            self.initialized, self.initializing = True, False
        elif method == "tools/list" and "result" in msg:
            listed = body.get("tools")
            if not isinstance(listed, list) or len(listed) > MAX_TOOLS:
                self.discovery_failed = True
                self._write(output, withheld(id, method, "invalid_tool_list"))
                return
            updates = {}
            changed = False
            for tool in listed:
                if (not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not NAME.fullmatch(tool["name"])
                        or not isinstance(tool.get("inputSchema"), dict)
                        or ("description" in tool and not isinstance(tool["description"], str))
                        or ("outputSchema" in tool and not isinstance(tool["outputSchema"], dict))):
                    self.discovery_failed = True
                    self._write(output, withheld(id, method, "invalid_tool_definition"))
                    return
                name = tool["name"]
                digest = tool_digest(tool)
                if name in updates:
                    changed = True
                if name in self.tools and self.tools[name] != digest:
                    self.tools.pop(name)
                    changed = True
                updates[name] = digest
            if self.discovery_failed or changed or len(self.tools.keys() | updates.keys()) > MAX_TOOLS:
                self.discovery_failed = True
                self._write(output, withheld(id, method, "tool_definition_changed"))
                return
            self.tools.update(updates)
            if self.policy is not None:
                permitted = [tool for tool in listed if self.policy.exposes(tool["name"], updates[tool["name"]])]
                msg = {**msg, "result": {**body, "tools": permitted}}
        self._write(output, msg)

    def run(self, stdin: BinaryIO, stdout: BinaryIO) -> int:
        if self.policy is not None:
            self.policy.check_command(self.command)
            self.log({"event": "tool_policy_loaded", "version": 1, "sha256": self.policy.sha256})
        # A subprocess's stderr may be surfaced by a host. Suppress it rather than
        # accidentally creating an uninspected output path.
        child = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        for stream, source in ((stdin, "client"), (child.stdout, "server")):
            threading.Thread(target=self._reader, args=(stream, source), daemon=True).start()
        try:
            while True:
                if self.client_eof and not self.pending:
                    return 0
                if any(time.monotonic() - req["at"] > self.request_timeout for req in self.pending.values()):
                    raise TimeoutError
                try:
                    source, raw = self.events.get(timeout=0.1)
                except queue.Empty:
                    continue
                if source == "fatal":
                    raise ValueError("Invalid transport")
                if raw is None:
                    if source == "client":
                        self.client_eof = True
                    elif self.pending:
                        raise ValueError("Upstream closed during request")
                    else:
                        return 0 if child.wait(timeout=2) == 0 else 2
                elif source == "client":
                    self._client(raw, child, stdout)
                else:
                    self._server(raw, child, stdout)
        except (ValueError, UnicodeError, RecursionError, OSError, TimeoutError, subprocess.TimeoutExpired):
            for req in self.pending.values():
                try:
                    self._write(stdout, error(req["id"], "Guarded connection failed; no further responses were released."))
                except OSError:
                    break
            self.log({"outcome": "unscanned", "reason": "connection_failed"})
            return 2
        finally:
            self.stop.set()
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            child.stdin.close()
            child.stdout.close()
