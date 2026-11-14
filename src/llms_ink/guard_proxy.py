"""Bounded stdio proxy for legacy MCP tool servers. Inspection precedes delivery.

Optional trusted local policy restricts outgoing calls on this connection.
This is not a sandbox for the subprocess or an authorization layer for host tools.
Unsolicited server notifications and stderr are suppressed, so they cannot become
an alternate uninspected content path. Unsupported protocol features fail closed.
"""
from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import signal
import sys
import threading
import time
from typing import Any, BinaryIO
from types import MappingProxyType

from .guard import MAX_BYTES, receipt
from .guard_transport import lines
from .guard_policy import Policy, decode, tool_digest
from .guard_approval import Approval, APPROVAL_SECONDS, APPROVAL_VERSIONS, accepted, supports_approval

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


def transport_metadata_only(params: dict) -> bool:
    """Recognize and discard correlation metadata, never forward it upstream.

    progressToken is MCP transport metadata. Claude Code 2.1.280 also sends
    claudecode/toolUseId. Neither can change the exact tool name or arguments.
    Unknown extensions remain denied rather than acquiring execution semantics.
    """
    if "_meta" not in params:
        return True
    meta = params["_meta"]
    if type(meta) is not dict or set(meta) - {"progressToken", "claudecode/toolUseId"}:
        return False
    if "progressToken" in meta:
        try:
            id_key(meta["progressToken"])
        except ValueError:
            return False
    if "claudecode/toolUseId" in meta:
        value = meta["claudecode/toolUseId"]
        if type(value) is not str or not 1 <= len(value) <= 128:
            return False
    return True


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
    def __init__(self, command: list[str], guard: Any, *, policy: Policy | None = None, require_approval: bool = False, approval_timeout: float = APPROVAL_SECONDS, request_timeout: float = 120, log: Any = None, review_commands: dict | None = None, process_group: bool = False):
        self.command, self.guard = list(command), guard
        self.policy = policy
        if process_group and os.name != 'posix':
            raise RuntimeError('Aggregate gateway process cleanup requires POSIX.')
        self.process_group = process_group
        self.review_commands = MappingProxyType({name: tuple(command) for name, command in (review_commands or {}).items()})
        if require_approval and policy is None:
            raise RuntimeError("Host approval requires an owner-controlled exact tool policy.")
        if not 0 < approval_timeout <= APPROVAL_SECONDS:
            raise ValueError("Invalid approval timeout")
        self.require_approval = require_approval
        self.approval_timeout = approval_timeout
        self.awaiting: dict[tuple, Approval] = {}
        self.client_disconnected = threading.Event()
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
            for raw in lines(stream, self.stop, MAX_BYTES):
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
            if not self.stop.is_set():
                if source == "client": self.client_disconnected.set()
                self._event((source, None))
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
        if "method" not in msg and self.require_approval:
            self._approval_response(msg, child, output)
            return
        method = msg.get("method")
        if not isinstance(method, str):
            raise ValueError("Client responses are not supported")
        params = msg.get("params", {})
        if not isinstance(params, dict):
            raise ValueError("Invalid params")
        if "id" not in msg:
            if method == "notifications/cancelled":
                key = id_key(params.get("requestId"))
                held = next((a for a in self.awaiting.values() if id_key(a.call_id) == key), None)
                if held is not None:
                    self.awaiting.pop(id_key(held.id))
                    self._cancel_form(held, output)
                self.pending.pop(key, None)
                with self.state_lock:
                    self.cancelled.discard(key)
                if held is None:
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
        if len(self.pending) + len(self.awaiting) >= MAX_PENDING:
            self._write(output, error(id, "Local guard is busy. Retry after pending requests finish."))
            return
        if method == "initialize":
            if self.initialized or self.initializing or params.get("protocolVersion") not in VERSIONS:
                self._write(output, error(id, "Guard supports one legacy MCP initialization per connection.", -32602))
                return
            if self.require_approval and not supports_approval(params):
                self._write(output, error(id, "Host approval requires form elicitation on MCP 2025-06-18 or 2025-11-25.", -32602))
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
                        or set(params) - {"name", "arguments", "_meta"} or not transport_metadata_only(params)
                        or type(arguments) is not dict
                        or not self.policy.allows(name, self.tools[name], arguments)):
                    self.log({"outcome": "denied", "reason": "tool_policy"})
                    self._write(output, error(id, "Local policy denied this tool call. Ask the policy owner to review the required action."))
                    return
                msg = {**msg, "params": {"name": name, "arguments": arguments}}
                if self.require_approval:
                    if self.awaiting:
                        self._write(output, error(id, "Another call is awaiting approval. Retry after it finishes."))
                        return
                    try:
                        approval, prompt = Approval.create(msg, list(self.review_commands.get(name, self.command)), self.policy.sha256,
                                                           self.tools[name], time.monotonic(), self.approval_timeout)
                    except ValueError:
                        self._write(output, error(id, "This call is too large for complete approval review. No call was sent."))
                        return
                    self.awaiting[id_key(approval.id)] = approval
                    self.log({"event": "approval_requested"})
                    self._write(output, prompt)
                    return
        elif method not in {"tools/list", "ping"}:
            self._write(output, error(id, "This guard supports tool discovery and calls only.", -32601))
            return
        self.pending[key] = {"id": id, "method": method, "at": time.monotonic()}
        self._write(child.stdin, msg)

    @staticmethod
    def _cancel_form(approval: Approval, output: BinaryIO) -> None:
        Proxy._write(output, {"jsonrpc": "2.0", "method": "notifications/cancelled",
                              "params": {"requestId": approval.id, "reason": "Approval is no longer pending."}})

    def _deny_approval(self, approval: Approval, output: BinaryIO, reason: str) -> None:
        self.log({"outcome": "denied", "reason": reason})
        self._write(output, error(approval.call_id, "This call was not approved. No call was sent."))

    def _expire_approvals(self, output: BinaryIO) -> None:
        for key, approval in list(self.awaiting.items()):
            if time.monotonic() >= approval.expires:
                self.awaiting.pop(key)
                self._cancel_form(approval, output)
                self._deny_approval(approval, output, "approval_expired")

    def _approval_response(self, msg: dict, child: Any, output: BinaryIO) -> None:
        approval = self.awaiting.pop(id_key(msg.get("id")), None)
        if approval is None:
            return  # late, replayed or unsolicited replies never grant authority
        call_key = id_key(approval.call_id)
        with self.state_lock:
            if call_key in self.cancelled or self.client_disconnected.is_set():
                self.log({"outcome": "denied", "reason": "approval_cancelled"})
                return
            if time.monotonic() >= approval.expires:
                self._deny_approval(approval, output, "approval_expired")
                return
            if not accepted(msg):
                self._deny_approval(approval, output, "approval_declined")
                return
            action = parse(approval.action)
            name, arguments = action["params"]["name"], action["params"]["arguments"]
            if (self.discovery_failed or self.tools.get(name) != approval.definition
                    or self.policy is None or not self.policy.allows(name, approval.definition, arguments)):
                self._deny_approval(approval, output, "tool_policy")
                return
            # Check cancellation and dispatch under the same lock used by the
            # transport reader. Cancellation after dispatch cannot undo a side effect.
            self.pending[call_key] = {"id": approval.call_id, "method": "tools/call", "at": time.monotonic()}
            self._write(child.stdin, action)
            self.log({"event": "approval_accepted"})

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
        # JSON-RPC response extensions are not part of the inspected result.
        # Do not let untrusted top-level fields form a second delivery path.
        field = "result" if "result" in msg else "error"
        msg = {"jsonrpc": "2.0", "id": id, field: msg[field]}
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
            if ("error" in msg or body.get("protocolVersion") not in VERSIONS
                    or (self.require_approval and body.get("protocolVersion") not in APPROVAL_VERSIONS)):
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
        child = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=self.process_group)
        readers = []
        for stream, source in ((stdin, "client"), (child.stdout, "server")):
            reader = threading.Thread(target=self._reader, args=(stream, source), daemon=True)
            readers.append(reader); reader.start()
        try:
            while True:
                if self.client_disconnected.is_set():
                    self.awaiting.clear()
                else:
                    self._expire_approvals(stdout)
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
                    elif self.pending or self.awaiting:
                        raise ValueError("Upstream closed during request")
                    else:
                        return 0 if child.wait(timeout=2) == 0 else 2
                elif source == "client":
                    self._client(raw, child, stdout)
                else:
                    self._server(raw, child, stdout)
        except (ValueError, UnicodeError, RecursionError, OSError, TimeoutError, subprocess.TimeoutExpired):
            for req in [*self.pending.values(), *({"id": a.call_id} for a in self.awaiting.values())]:
                try:
                    self._write(stdout, error(req["id"], "Guarded connection failed; no further responses were released."))
                except OSError:
                    break
            self.log({"outcome": "unscanned", "reason": "connection_failed"})
            return 2
        finally:
            self.awaiting.clear()
            self.stop.set()
            for reader in readers: reader.join(timeout=.3)
            if self.process_group:
                # Reap an already-exited leader before signalling its group.
                # macOS can reject a group containing only an unreaped zombie.
                child.poll()
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            else:
                child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                if self.process_group:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    child.kill()
                child.wait()
            if self.process_group:
                # A server can outlive its immediate parent. Reap this owned
                # process group even if the multiplexer already exited.
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            child.stdin.close()
            child.stdout.close()
