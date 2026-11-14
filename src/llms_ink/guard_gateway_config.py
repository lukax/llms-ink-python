"""Owner-reviewed definitions and exact arguments for an aggregate connection."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from .guard_policy import Policy, decode, tool_digest, MAX_POLICY_BYTES, NAME

SERVER_ID = re.compile(r'^[a-z][a-z0-9-]{0,31}$')
MAX_SERVERS = 8


@dataclass(frozen=True)
class Server:
    name: str
    command: tuple[str, ...]
    definitions: tuple[bytes, ...]
    policy: Policy

    def tools(self):
        return [json.loads(raw) for raw in self.definitions]


@dataclass(frozen=True)
class GatewayConfig:
    servers: tuple[Server, ...]
    sha256: str

    @classmethod
    def load(cls, path: str):
        try:
            if os.path.islink(path): raise ValueError('Symlink')
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_POLICY_BYTES or (os.name == 'posix' and info.st_mode & 0o022):
                    raise ValueError('Unsafe configuration')
                return cls.from_bytes(stream.read(MAX_POLICY_BYTES + 1))
        except (OSError, ValueError, TypeError, RecursionError):
            raise RuntimeError('Invalid gateway configuration. Use an owner-controlled version 1 JSON file with reviewed servers, tool definitions and exact arguments.') from None

    @classmethod
    def from_bytes(cls, raw: bytes):
        if len(raw) > MAX_POLICY_BYTES: raise ValueError('Configuration byte limit')
        data = decode(raw)
        if type(data) is not dict or set(data) != {'version', 'servers'} or type(data['version']) is not int or data['version'] != 1:
            raise ValueError('Configuration version or fields')
        sources = data['servers']
        if type(sources) is not dict or not 1 <= len(sources) <= MAX_SERVERS: raise ValueError('Server count')
        servers, count, arguments = [], 0, 0
        for name, source in sources.items():
            if not SERVER_ID.fullmatch(name) or type(source) is not dict or set(source) != {'command', 'tools'} or type(source['tools']) is not list:
                raise ValueError('Invalid server')
            rules, definitions = {}, []
            for rule in source['tools']:
                if type(rule) is not dict or set(rule) != {'definition', 'arguments'}: raise ValueError('Invalid rule')
                tool = rule['definition']
                fingerprint = tool_digest(tool)
                if tool['name'] in rules or not NAME.fullmatch(name + '__' + tool['name']): raise ValueError('Duplicate or oversized tool name')
                if ('description' in tool and type(tool['description']) is not str) or ('outputSchema' in tool and type(tool['outputSchema']) is not dict):
                    raise ValueError('Invalid definition')
                rules[tool['name']] = {'definitionSha256': fingerprint, 'arguments': rule['arguments']}
                definitions.append(json.dumps(tool, ensure_ascii=True, allow_nan=False).encode())
                count += 1
                if type(rule['arguments']) is not list: raise ValueError('Invalid arguments')
                arguments += len(rule['arguments'])
            if count > 128 or arguments > 1024: raise ValueError('Aggregate tool or argument limit')
            policy = Policy.from_bytes(json.dumps({'version': 1, 'command': source['command'], 'tools': rules}).encode())
            servers.append(Server(name, policy.command, tuple(definitions), policy))
        return cls(tuple(servers), hashlib.sha256(raw).hexdigest())

    def tools(self):
        return [{**tool, 'name': server.name + '__' + tool['name']} for server in self.servers for tool in server.tools()]

    def command(self, path: str):
        return [sys.executable, '-m', 'llms_ink.guard_gateway', '--config', str(Path(path).absolute()), '--sha256', self.sha256]

    def outer_policy(self, command):
        tools = {}
        for server in self.servers:
            for tool in server.tools():
                alias = server.name + '__' + tool['name']
                rule = next(rule for rule in server.policy.tools if rule.name == tool['name'])
                tools[alias] = {'definitionSha256': tool_digest({**tool, 'name': alias}),
                                'arguments': [json.loads(value) for value in sorted(rule.arguments)]}
        return Policy.from_bytes(json.dumps({'version': 1, 'command': command, 'tools': tools}).encode())

    def review_commands(self):
        return {server.name + '__' + tool['name']: server.command for server in self.servers for tool in server.tools()}
