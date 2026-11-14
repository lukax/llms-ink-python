"""Trusted local permissions for one MCP connection; no model-based grants.

Version 1 allows exact argument objects only. It deliberately does not implement
URL/path matching, wildcards, server-supplied annotations or agent approvals.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
import re
import stat

MAX_POLICY_BYTES = 256 * 1024
NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
SHA = re.compile(r"^[a-f0-9]{64}$")


def decode(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("Non-finite JSON")

    value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs, parse_constant=invalid)
    # Also reject overflowed exponents, unsafe integers and unpaired surrogates.
    work = [(value, 0)]
    count = 0
    while work:
        item, depth = work.pop()
        count += 1
        if depth > 48 or count > 30000:
            raise ValueError("JSON structure limit")
        if type(item) is dict:
            work.extend((v, depth + 1) for pair in item.items() for v in pair)
        elif type(item) is list:
            work.extend((v, depth + 1) for v in item)
        elif type(item) is str:
            item.encode("utf-8", errors="strict")
        elif type(item) is float and not math.isfinite(item):
            raise ValueError("Non-finite JSON")
        elif type(item) is int and abs(item) > 2**53 - 1:
            raise ValueError("Unsafe JSON integer")
    return value


def arguments_key(value: dict) -> str:
    # JSON serialization distinguishes bool/int/float, unlike Python equality.
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def tool_digest(tool: dict) -> str:
    if (type(tool) is not dict or type(tool.get("name")) is not str
            or not NAME.fullmatch(tool["name"]) or type(tool.get("inputSchema")) is not dict):
        raise ValueError("Invalid tool definition")
    # Preserve the definition fingerprint used by the original result wrapper.
    return hashlib.sha256(json.dumps(tool, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ToolRule:
    name: str
    definition_sha256: str
    arguments: frozenset[str]


@dataclass(frozen=True)
class Policy:
    command: tuple[str, ...]
    tools: tuple[ToolRule, ...]
    sha256: str

    @classmethod
    def load(cls, path: str) -> Policy:
        try:
            # Refuse devices/FIFOs without blocking, and symlink leaf paths.
            if os.path.islink(path):
                raise ValueError("Symlink")
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_size > MAX_POLICY_BYTES
                        or (os.name == "posix" and info.st_mode & 0o022)):
                    raise ValueError("Unsafe policy file")
                raw = stream.read(MAX_POLICY_BYTES + 1)
            return cls.from_bytes(raw)
        except (OSError, ValueError, TypeError, RecursionError):
            raise RuntimeError("Invalid guard policy. Use a regular, owner-controlled JSON file with version 1 and exact tool rules.") from None

    @classmethod
    def from_bytes(cls, raw: bytes) -> Policy:
        if len(raw) > MAX_POLICY_BYTES:
            raise ValueError("Policy byte limit")
        data = decode(raw)
        if type(data) is not dict or set(data) != {"version", "command", "tools"} or type(data["version"]) is not int or data["version"] != 1:
            raise ValueError("Policy version or fields")
        command, tools = data["command"], data["tools"]
        if (type(command) is not list or not 1 <= len(command) <= 128
                or any(type(x) is not str or "\0" in x or len(x) > 8192 for x in command)
                or not command[0] or not os.path.isabs(command[0])):
            raise ValueError("Policy requires an absolute executable and exact arguments")
        if type(tools) is not dict or len(tools) > 512:
            raise ValueError("Policy tool limit")
        rules = []
        total = 0
        for name, rule in tools.items():
            if (not NAME.fullmatch(name) or type(rule) is not dict
                    or set(rule) != {"definitionSha256", "arguments"}
                    or type(rule["definitionSha256"]) is not str or not SHA.fullmatch(rule["definitionSha256"])):
                raise ValueError("Invalid tool rule")
            arguments = rule["arguments"]
            if type(arguments) is not list or not 1 <= len(arguments) <= 128 or any(type(a) is not dict for a in arguments):
                raise ValueError("Exact argument objects required")
            total += len(arguments)
            if total > 1024:
                raise ValueError("Policy argument limit")
            rules.append(ToolRule(name, rule["definitionSha256"], frozenset(arguments_key(a) for a in arguments)))
        return cls(tuple(command), tuple(rules), hashlib.sha256(raw).hexdigest())

    def check_command(self, command: list[str]) -> None:
        if tuple(command) != self.command:
            raise RuntimeError("Guard policy does not match the server command. No server was started.")

    def exposes(self, name: str, digest: str) -> bool:
        return any(rule.name == name and rule.definition_sha256 == digest for rule in self.tools)

    def allows(self, name: str, digest: str, arguments: dict) -> bool:
        key = arguments_key(arguments)
        return any(rule.name == name and rule.definition_sha256 == digest and key in rule.arguments for rule in self.tools)
