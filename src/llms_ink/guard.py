"""Local, opt-in MCP result inspection. No content is sent to a scanning service.

Model weights are separately licensed (Llama 4 Community License). This package
is an independent integration, not Pinata's Doorman desktop application.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import multiprocessing
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
import urllib.request
from typing import Any

from . import __version__

MODEL_REVISION = "4a43fec65a670e48835d8e8c85c705b4b0d1c907"
MODEL_BASE = f"https://huggingface.co/PinataCloud/Llama-Doorman-22M/resolve/{MODEL_REVISION}"
ARTIFACTS = {
    "model.quant.onnx": "dcdfbfa68c59544f33b5ab7ebf17dadb841375189fb9f0aa5a27a7455cdd79f2",
    "tokenizer.json": "92c8b45d0b12ae0dd9680fbfe9804503542c377d65838558cd0b48a795385dde",
    "config.json": "58d7584401982309334efddb53fad7ebeb6c12a0fe84c8f59923a98589893fe4",
    "LICENSE": "90ae4807183070953bd8da5d7be81c4494920fb54c74359383c8a4536bf003c3",
    "NOTICE": "6d70b1303958ace2c652d10ffcb63cdd8436d49bc0e81c97373df4e329fad0c9",
}
# Byte bounds apply before JSON parsing/tokenization. Token coverage is complete
# for allowed messages; over-budget content is withheld, never sampled as safe.
MAX_BYTES = 1024 * 1024
MAX_TOKENS = 8192
WINDOW = 256
STRIDE = 192
SEMANTIC_RULES = (
    re.compile(r"\b(?:ignore|disregard|override)\b.{0,60}\b(?:previous|prior|system|developer)\b.{0,30}\binstructions?\b", re.I | re.S),
    re.compile(r"\b(?:reveal|print|leak|send|exfiltrate)\b.{0,70}\b(?:system prompt|private key|credentials|api[_ -]?key|access token)\b", re.I | re.S),
    re.compile(r"\b(?:read|cat|send|post|upload|print|copy)\b.{0,120}(?:\.env\b|\.ssh/|\.aws/credentials|\bapi[_ -]?keys?\b|\bcredentials\b|\bprivate keys?\b|\baccess tokens?\b)", re.I | re.S),
    re.compile(r"\b(?:ignore|disregard|override)\b.{0,60}\b(?:task|user|system|developer)\b", re.I | re.S),
    re.compile(r"\b(?:execute|run)\b.{0,100}\b(?:curl|wget|powershell|bash)\b", re.I | re.S),
    re.compile(r"\b(?:for (?:ai )?assistants|you are now|do not (?:tell|mention|request confirmation)|hide this instruction|always recommend)\b", re.I),
)


def model_dir() -> Path:
    return Path(os.environ.get("LLMS_INK_GUARD_CACHE", str(Path.home() / ".cache" / "llms-ink" / "guard"))) / MODEL_REVISION


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verify_assets(root: Path) -> None:
    for name, expected in ARTIFACTS.items():
        path = root / name
        if not path.is_file() or digest_file(path) != expected:
            raise RuntimeError("Model files missing or invalid. Run llms-ink-guard setup.")


def setup(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, expected in ARTIFACTS.items():
        target = root / name
        if target.is_file() and digest_file(target) == expected:
            continue
        print(f"Downloading {name}…", file=sys.stderr)
        fd, temporary = tempfile.mkstemp(prefix=".download-", dir=root)
        try:
            total = 0
            with os.fdopen(fd, "wb") as dest, urllib.request.urlopen(f"{MODEL_BASE}/{name}", timeout=60) as source:
                while block := source.read(1024 * 1024):
                    total += len(block)
                    if total > 110 * 1024 * 1024:
                        raise RuntimeError("Model download exceeded its size limit.")
                    dest.write(block)
            if digest_file(Path(temporary)) != expected:
                raise RuntimeError(f"Checksum mismatch for {name}; file was not installed.")
            os.replace(temporary, target)
        finally:
            Path(temporary).unlink(missing_ok=True)
    verify_assets(root)
    print(f"Model installed: {MODEL_REVISION}\nBuilt with Llama. License: {root / 'LICENSE'}")


def receipt(outcome: str, reason: str, **extra: Any) -> dict:
    return {"outcome": outcome, "reason": reason, "modelRevision": MODEL_REVISION,
            "policyRevision": "1", **extra}


class Inspector:
    """Pure inspection loop with injected tokenizer/scorer for protocol tests."""
    def __init__(self, tokenizer: Any, score: Any):
        self.tokenizer, self.score = tokenizer, score

    def inspect(self, text: str) -> dict:
        encoded = text.encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        if len(encoded) > MAX_BYTES:
            return receipt("unscanned", "byte_limit", coverage="none", contentDigest=digest)
        encoding = self.tokenizer.encode(text, add_special_tokens=False)
        ids, offsets = encoding.ids, encoding.offsets
        if len(ids) > MAX_TOKENS:
            return receipt("unscanned", "token_limit", coverage="none", tokens=len(ids), contentDigest=digest)
        highest, count = 0.0, 0
        for start in range(0, len(ids), STRIDE):
            stop = min(start + WINDOW, len(ids))
            fragment = text[offsets[start][0]:offsets[stop - 1][1]]
            score = float(self.score(ids[start:stop]))
            if not math.isfinite(score) or not 0 <= score <= 1:
                raise ValueError("Invalid classifier score")
            count += 1
            highest = max(highest, score)
            rule = any(pattern.search(fragment) for pattern in SEMANTIC_RULES)
            if score >= 0.85 or (rule and score >= 0.2):
                return receipt("quarantine", "instruction_pattern" if rule else "model_detection",
                               coverage="partial" if stop < len(ids) else "complete", tokens=len(ids),
                               windows=count, score=round(highest, 4), contentDigest=digest)
            if stop == len(ids):
                break
        return receipt("allow", "no_finding", coverage="complete", tokens=len(ids), windows=count,
                       score=round(highest, 4), contentDigest=digest)


def _model_worker(connection: Any, root: str) -> None:
    try:
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer
        tokenizer = Tokenizer.from_file(str(Path(root) / "tokenizer.json"))
        tokenizer.no_truncation()
        tokenizer.no_padding()
        options = ort.SessionOptions()
        options.intra_op_num_threads = 2
        options.inter_op_num_threads = 1
        options.log_severity_level = 3
        session = ort.InferenceSession(str(Path(root) / "model.quant.onnx"), sess_options=options,
                                       providers=["CPUExecutionProvider"])
        # Token IDs come from the pinned tokenizer; include its special tokens
        # using its postprocessor instead of assuming IDs from another model.
        prefix = tokenizer.encode("", add_special_tokens=True).ids
        if len(prefix) != 2:
            raise RuntimeError("Unexpected tokenizer special tokens")

        def score(ids: list) -> float:
            values = [prefix[0], *ids, prefix[1]]
            logits = session.run(None, {"input_ids": np.array([values], dtype=np.int64),
                                       "attention_mask": np.ones((1, len(values)), dtype=np.int64)})[0][0]
            p = np.exp(logits - logits.max())
            return float(p[1] / p.sum())

        inspector = Inspector(tokenizer, score)
        connection.send({"ready": True})
        while True:
            text = connection.recv()
            if text is None:
                break
            connection.send(inspector.inspect(text))
    except EOFError:
        pass
    except Exception:
        # Exceptions can include inputs/paths; never send raw runtime diagnostics.
        try:
            connection.send({"error": "model_failure"})
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        connection.close()


class LocalGuard:
    def __init__(self, root: Path | None = None, timeout: float = 20):
        self.timeout = timeout
        self.closed = False
        self._close_lock = threading.Lock()
        verify_assets(root or model_dir())
        context = multiprocessing.get_context("spawn")
        self.connection, child = context.Pipe()
        self.process = context.Process(target=_model_worker, args=(child, str(root or model_dir())), daemon=True)
        self.process.start()
        child.close()
        if not self.connection.poll(60) or self.connection.recv() != {"ready": True}:
            self.close()
            raise RuntimeError("Model could not start. Install llms-ink[guard] with Python 3.11 or newer, then run setup.")

    def inspect(self, text: str) -> dict:
        if self.closed:
            return receipt("unscanned", "model_unavailable", coverage="none")
        started = time.monotonic()
        try:
            self.connection.send(text)
            if not self.connection.poll(self.timeout):
                raise TimeoutError
            result = self.connection.recv()
            if result.get("outcome") not in {"allow", "quarantine", "unscanned"}:
                raise ValueError
            result["elapsedMs"] = round((time.monotonic() - started) * 1000)
            return result
        except (OSError, EOFError, TimeoutError, ValueError):
            self.close()
            return receipt("unscanned", "model_unavailable", coverage="none")

    def close(self) -> None:
        # Inspection failure and service shutdown can arrive on different
        # threads. multiprocessing.Process wait/reap state is not thread-safe.
        # Keep this separate from the inspection lock: closing must unblock an
        # inspector waiting for a response from a stopped or failed worker.
        with self._close_lock:
            self.closed = True
            try:
                if self.process.is_alive():
                    self.process.terminate()
                self.process.join(timeout=2)
                # SIGTERM cannot wake a SIGSTOP'ed worker.
                if self.process.is_alive():
                    self.process.kill()
                    self.process.join(timeout=2)
                    if self.process.is_alive():
                        raise RuntimeError("The local model worker did not stop.")
            finally:
                self.connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="llms-ink-guard", description="Inspect MCP results locally before delivery. Built with Llama.")
    parser.add_argument("--version", action="version", version=f"llms-ink-guard {__version__}")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("setup", help="Download and verify pinned model files and their license (about 96 MB).")
    commands.add_parser("status", help="Verify local model files; does not download anything.")
    commands.add_parser("scan", help="Inspect stdin text; emit JSON. Exit 0 allow, 1 quarantine, 2 unscanned.")
    commands.add_parser("tool-hash", help="Hash one reviewed tools/list tool object from stdin; no model or server needed.")
    check = commands.add_parser("policy-check", help="Validate a local permission file; no model or server needed.")
    check.add_argument("path")
    doctor = commands.add_parser('doctor', help='Read-only installation, configuration and optional service checks; starts no model or server.')
    doctor.add_argument('--config', required=True)
    doctor.add_argument('--owner-file')
    doctor.add_argument('--json', action='store_true', help='Emit structured diagnostic results without arguments or credentials.')
    initialize_gateway = commands.add_parser('gateway-init', help='Owner-terminal discovery and initial exact permissions; asks before launching the server.')
    initialize_gateway.add_argument('--server', required=True)
    initialize_gateway.add_argument('--output', required=True)
    initialize_gateway.add_argument('command', nargs=argparse.REMAINDER, help='-- /absolute/server-executable arguments')
    gateway_check = commands.add_parser("gateway-check", help="Validate a reviewed multi-server configuration without starting a model or server.")
    gateway_check.add_argument("path")
    proposal = commands.add_parser('gateway-propose', help='Propose one exact argument object for an existing tool; does not grant authority or start a server.')
    proposal.add_argument('--config', required=True)
    proposal.add_argument('--server', required=True)
    proposal.add_argument('--tool', required=True)
    proposal.add_argument('--arguments', required=True, help='Owner-controlled JSON file containing one argument object.')
    proposal.add_argument('--output', required=True, help='New proposal file in an owner-only directory.')
    review = commands.add_parser('gateway-review', help='Review one proposal in an owner terminal and write a new configuration only after explicit acceptance.')
    review.add_argument('--config', required=True)
    review.add_argument('--proposal', required=True)
    review.add_argument('--output', required=True, help='New configuration file in an owner-only directory; never overwrites or activates an existing scope.')
    gateway = commands.add_parser("gateway", help="Guard several legacy stdio servers with exact permissions and one-use host approvals (POSIX, experimental).")
    gateway.add_argument("--config", required=True, help="Owner-controlled JSON server definitions and exact arguments.")
    gateway.add_argument("--client-protocol", choices=['legacy', '2026-07-28'], default='legacy', help="Client protocol; upstream servers remain legacy stdio. Modern calls use one-use approval continuations.")
    service_init = commands.add_parser('service-init', help='Create a private local service directory and owner credential (POSIX).')
    service_init.add_argument('directory')
    service_serve = commands.add_parser('service-serve', help='Run the authenticated local session service in the foreground (POSIX).')
    service_serve.add_argument('--owner-file', required=True)
    service_serve.add_argument('--config', required=True)
    session_create = commands.add_parser('session-create', help='Issue a session credential into a new private file; never print its secret.')
    session_create.add_argument('--owner-file', required=True)
    session_create.add_argument('--output', required=True)
    session_create.add_argument('--client-protocol', choices=['legacy', '2026-07-28'], default='legacy')
    session_create.add_argument('--ttl', type=int, default=3600, help='Session lifetime in seconds, from 1 to 86400.')
    session_revoke = commands.add_parser('session-revoke', help='Revoke a session and stop all its guarded connections.')
    session_revoke.add_argument('--owner-file', required=True)
    session_revoke.add_argument('--session-id', required=True)
    service_status = commands.add_parser('service-status', help='Read metadata-only session status using the owner credential.')
    service_status.add_argument('--owner-file', required=True)
    session_connect = commands.add_parser('connect', help='Attach this stdio host connection using a session credential file.')
    session_connect.add_argument('--session-file', required=True)
    wrap = commands.add_parser("wrap", help="Guard a legacy stdio MCP tool server.")
    wrap.add_argument("--policy", help="Owner-controlled JSON permissions. Deny calls without an exact matching rule.")
    wrap.add_argument("--require-approval", action="store_true", help="Require a one-use host form approval for each policy-permitted call (experimental).")
    wrap.add_argument("command", nargs=argparse.REMAINDER, help="-- server-command arguments")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 11):
        parser.error("The optional guard requires Python 3.11 or newer.")
    old_signals = {}
    startup = [True, False]
    service = None
    try:
        if args.action == 'doctor':
            if os.name != 'posix': raise RuntimeError('Local guard diagnostics require macOS or Linux.')
            from .guard_doctor import diagnose, render
            report = diagnose(args.config, args.owner_file)
            print(json.dumps(report, ensure_ascii=True) if args.json else render(report))
            return 0 if report['checksPassed'] else 2
        if args.action == 'gateway-init':
            if os.name != 'posix': raise RuntimeError('Guided setup requires macOS or Linux.')
            import signal
            def setup_stop(_signal, _frame): raise KeyboardInterrupt
            old_signals[signal.SIGTERM] = signal.signal(signal.SIGTERM, setup_stop)
            from .guard_onboarding import initialize
            command = args.command[1:] if args.command[:1] == ['--'] else args.command
            try:
                return initialize(args.server, command, args.output, sys.stdin, sys.stdout)
            except (OSError, ValueError, TypeError, RuntimeError, RecursionError):
                raise RuntimeError('Guided setup failed. Check the reviewed command, legacy tool discovery, exact argument files and new output path in a private directory. No existing configuration was changed.') from None
        if args.action in {'gateway-propose', 'gateway-review'}:
            if os.name != 'posix': raise RuntimeError('Owner terminal review requires macOS or Linux.')
            from . import guard_review
            try:
                if args.action == 'gateway-propose':
                    print(json.dumps(guard_review.propose(args.config, args.server, args.tool, args.arguments, args.output)))
                    return 0
                return guard_review.review(args.config, args.proposal, args.output, sys.stdin, sys.stdout)
            except (OSError, ValueError, TypeError, RecursionError):
                raise RuntimeError('Permission review failed. Check the owner-controlled inputs, unchanged base configuration, complete review size and new output path in a private directory. No existing scope was changed.') from None
        if args.action in {'service-init', 'service-serve', 'service-status', 'session-create', 'session-revoke', 'connect'}:
            if os.name != 'posix':
                raise RuntimeError('The local session service requires macOS or Linux.')
            from . import guard_service
            if args.action == 'service-init':
                guard_service.initialize(args.directory)
                print(json.dumps({'initialized': True}))
                return 0
            if args.action == 'session-create':
                print(json.dumps(guard_service.create_session(args.owner_file, args.output, args.client_protocol, args.ttl)))
                return 0
            if args.action == 'session-revoke':
                print(json.dumps(guard_service.control(args.owner_file, 'revoke', sessionId=args.session_id)))
                return 0
            if args.action == 'service-status':
                print(json.dumps(guard_service.control(args.owner_file, 'status')))
                return 0
            if args.action == 'connect':
                return guard_service.connect(args.session_file, sys.stdin.buffer, sys.stdout.buffer)
            service = guard_service.Service(args.owner_file, args.config, None)
        if args.action == "gateway-check":
            from .guard_gateway_config import GatewayConfig
            config = GatewayConfig.load(args.path)
            print(json.dumps({"valid": True, "version": 1, "servers": len(config.servers), "tools": len(config.tools()), "sha256": config.sha256}))
            return 0
        if args.action == "policy-check":
            from .guard_policy import Policy
            policy = Policy.load(args.path)
            print(json.dumps({"valid": True, "version": 1, "tools": len(policy.tools), "sha256": policy.sha256}))
            return 0
        if args.action == "tool-hash":
            from .guard_policy import decode, tool_digest
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise RuntimeError("Tool definition exceeds 1 MiB.")
            try:
                digest = tool_digest(decode(raw))
            except (ValueError, TypeError, RecursionError):
                raise RuntimeError("Invalid tool definition. Provide one complete reviewed tools/list object as JSON.") from None
            print(digest)
            return 0
        if args.action == "setup":
            setup(model_dir())
            return 0
        if args.action == "status":
            verify_assets(model_dir())
            print(json.dumps({"installed": True, "modelRevision": MODEL_REVISION, "license": "Llama 4 Community License"}))
            return 0
        policy = None
        config = None
        if args.action in {'gateway', 'service-serve'}:
            if os.name != "posix":
                raise RuntimeError("The experimental aggregate gateway requires POSIX process-group cleanup.")
            if args.action == 'gateway':
                from .guard_gateway_config import GatewayConfig
                config = GatewayConfig.load(args.config)
                command = config.command(args.config)
                policy = config.outer_policy(command)
            import signal
            def gateway_stop(_signal, _frame):
                if startup[0]:
                    startup[1] = True  # Let bounded model startup finish so its worker can be closed.
                elif service is not None:
                    service.stop.set()
                else:
                    raise KeyboardInterrupt
            for sig in (signal.SIGTERM, signal.SIGINT):
                old_signals[sig] = signal.signal(sig, gateway_stop)
        if args.action == "wrap":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            if not command:
                parser.error("wrap requires -- server-command arguments")
            if args.require_approval and args.policy is None:
                raise RuntimeError("Host approval requires --policy with owner-controlled exact tool rules.")
            if args.policy is not None:
                from .guard_policy import Policy
                policy = Policy.load(args.policy)
                policy.check_command(command)
        guard = LocalGuard()
        try:
            startup[0] = False
            if startup[1]: raise KeyboardInterrupt
            if service is not None:
                service.guard.guard = guard
                return service.run()
            if args.action == "scan":
                raw = sys.stdin.buffer.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    result = receipt("unscanned", "byte_limit", coverage="none")
                else:
                    result = guard.inspect(raw.decode("utf-8", errors="strict"))
                print(json.dumps(result))
                return {"allow": 0, "quarantine": 1, "unscanned": 2}[result["outcome"]]
            from .guard_proxy import Proxy
            if config is not None:
                if args.client_protocol == '2026-07-28':
                    from .guard_modern import ModernProxy
                    Proxy = ModernProxy
                return Proxy(command, guard, policy=policy, require_approval=True,
                             review_commands=config.review_commands(), process_group=True).run(sys.stdin.buffer, sys.stdout.buffer)
            return Proxy(command, guard, policy=policy, require_approval=args.require_approval).run(sys.stdin.buffer, sys.stdout.buffer)
        finally:
            startup[0] = True
            guard.close()
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        # Only our fixed operational errors are suitable for stderr.
        message = str(error) if type(error) is RuntimeError else "Guard failed; no uninspected response was released. Check installation and retry."
        print(f"llms-ink-guard: {message}", file=sys.stderr)
        return 2
    finally:
        for sig, handler in old_signals.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(main())
