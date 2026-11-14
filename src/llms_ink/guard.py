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
        self.closed = True
        if self.process.is_alive():
            self.process.terminate()
        self.process.join(timeout=2)
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
    wrap = commands.add_parser("wrap", help="Guard a legacy stdio MCP tool server.")
    wrap.add_argument("--policy", help="Owner-controlled JSON permissions. Deny calls without an exact matching rule.")
    wrap.add_argument("command", nargs=argparse.REMAINDER, help="-- server-command arguments")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 11):
        parser.error("The optional guard requires Python 3.11 or newer.")
    try:
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
        if args.action == "wrap":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            if not command:
                parser.error("wrap requires -- server-command arguments")
            if args.policy is not None:
                from .guard_policy import Policy
                policy = Policy.load(args.policy)
                policy.check_command(command)
        guard = LocalGuard()
        try:
            if args.action == "scan":
                raw = sys.stdin.buffer.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    result = receipt("unscanned", "byte_limit", coverage="none")
                else:
                    result = guard.inspect(raw.decode("utf-8", errors="strict"))
                print(json.dumps(result))
                return {"allow": 0, "quarantine": 1, "unscanned": 2}[result["outcome"]]
            from .guard_proxy import Proxy
            return Proxy(command, guard, policy=policy).run(sys.stdin.buffer, sys.stdout.buffer)
        finally:
            guard.close()
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        # Only our fixed operational errors are suitable for stderr.
        message = str(error) if type(error) is RuntimeError else "Guard failed; no uninspected response was released. Check installation and retry."
        print(f"llms-ink-guard: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
