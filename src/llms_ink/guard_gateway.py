"""Internal bounded legacy-MCP multiplexer. Launch through `guard gateway`.

The outer Proxy owns inspection and approval. This process rechecks the frozen
configuration, pins upstream definitions and routes only exact permitted calls.
It is not an inspection boundary by itself or an execution sandbox.
"""
from __future__ import annotations
import argparse
import json
import os
import queue
import select
import signal
import subprocess
import sys
import threading
import time

from .guard import MAX_BYTES
from .guard_transport import lines
from .guard_gateway_config import GatewayConfig
from .guard_policy import tool_digest
from .guard_proxy import parse, id_key, error, MAX_PENDING, MAX_TOOLS
from .guard_approval import APPROVAL_VERSIONS


class Gateway:
    def __init__(self, config, *, request_timeout=90, write_timeout=5):
        self.config = config
        self.servers = {server.name: server for server in config.servers}
        self.children = {}
        self.events = queue.Queue(maxsize=32)
        self.stop = threading.Event()
        self.disconnected = threading.Event()
        self.invalidated = threading.Event()
        self.lock = threading.Lock()
        self.cancelled = set()
        self.seen = set()
        self.groups = {}
        self.pending = {}
        self.serial = 0
        self.version = None
        self.initialized = False
        self.discovered = False
        self.request_timeout = request_timeout
        self.write_timeout = write_timeout
        self.output = None
        self.readers = []

    def _event(self, source, raw):
        while not self.stop.is_set():
            try:
                self.events.put((source, raw), timeout=.1); return
            except queue.Full: pass

    def _reader(self, stream, source):
        try:
            for raw in lines(stream, self.stop, MAX_BYTES):
                if not raw.strip(): continue
                message = parse(raw)
                with self.lock:
                    if source == 'client' and message.get('method') == 'notifications/cancelled':
                        self.cancelled.add(id_key(message.get('params', {}).get('requestId')))
                        if len(self.cancelled) > 4096: raise ValueError('Cancellation count')
                    elif source != 'client' and message.get('method') == 'notifications/tools/list_changed':
                        self.invalidated.set()
                self._event(source, raw)
            if not self.stop.is_set():
                with self.lock:
                    (self.disconnected if source == 'client' else self.invalidated).set()
                self._event(source, None)
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            self.invalidated.set(); self._event('fatal', None)

    def _write(self, stream, message, call_key=None):
        raw = json.dumps(message, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode() + b'\n'
        if len(raw) > MAX_BYTES: raise ValueError('Message size')
        offset, deadline = 0, time.monotonic() + self.write_timeout
        while offset < len(raw):
            if time.monotonic() >= deadline or self.stop.is_set(): raise TimeoutError
            if not select.select([], [stream.fileno()], [], .05)[1]: continue
            try:
                with self.lock:
                    # Once the first byte is sent, cancellation cannot undo dispatch.
                    if offset == 0 and call_key is not None and (self.disconnected.is_set() or self.invalidated.is_set() or call_key in self.cancelled):
                        return False
                    size = os.write(stream.fileno(), raw[offset:])
                if size == 0: raise OSError('Closed transport')
                offset += size
            except BlockingIOError: continue
        return True

    def _request(self, server, group, method, params):
        self.serial += 1
        request_id = f'gateway-{self.serial}'
        self.pending[request_id] = (server, group, method)
        sent = self._write(self.children[server].stdin, {'jsonrpc':'2.0','id':request_id,'method':method,'params':params}, group if method == 'tools/call' else None)
        if not sent: self.pending.pop(request_id, None); self.groups.pop(group, None)

    def _reply(self, key, result, is_error=False):
        group = self.groups.pop(key, None)
        if group is None: return
        self._write(self.output, {'jsonrpc':'2.0','id':group['id'], 'error' if is_error else 'result':result}, key)

    def _start(self):
        for name, server in self.servers.items():
            child = subprocess.Popen(list(server.command), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            self.children[name] = child
            os.set_blocking(child.stdin.fileno(), False)
            reader = threading.Thread(target=self._reader, args=(child.stdout, 'server:' + name), daemon=True)
            self.readers.append(reader); reader.start()

    def _client(self, message):
        method, params = message.get('method'), message.get('params', {})
        if type(method) is not str or type(params) is not dict: raise ValueError('Invalid request')
        if 'id' not in message:
            if method == 'notifications/cancelled':
                key = id_key(params.get('requestId'))
                self.groups.pop(key, None)
                for request_id, (server, group, _) in list(self.pending.items()):
                    if group == key:
                        self.pending.pop(request_id)
                        self._write(self.children[server].stdin, {'jsonrpc':'2.0','method':method,'params':{'requestId':request_id}})
            elif method == 'notifications/initialized' and self.initialized:
                for child in self.children.values(): self._write(child.stdin, {'jsonrpc':'2.0','method':method})
            return
        key = id_key(message['id'])
        if key in self.seen or len(self.seen) >= 4096: raise ValueError('Request id reuse or limit')
        self.seen.add(key)
        if key in self.cancelled: return
        if len(self.groups) >= MAX_PENDING:
            self._write(self.output, error(message['id'], 'Gateway is busy.')); return
        group = {'id':message['id'], 'method':method, 'at':time.monotonic()}
        self.groups[key] = group
        if method == 'initialize':
            if self.version is not None or params.get('protocolVersion') not in APPROVAL_VERSIONS:
                self._reply(key, {'code':-32602,'message':'Gateway requires one MCP 2025-06-18 or 2025-11-25 connection.'}, True); return
            self.version = params['protocolVersion']
            self._start()
            group['remaining'] = set(self.servers)
            for server in self.servers:
                self._request(server, key, method, {'protocolVersion':self.version,'capabilities':{},'clientInfo':{'name':'llms-ink-guard-gateway','version':'1'}})
        elif not self.initialized:
            self._reply(key, {'code':-32600,'message':'Initialize the gateway first.'}, True)
        elif method == 'ping':
            self._reply(key, {})
        elif method == 'tools/list':
            if params or any(g is not group and g['method'] == method for g in self.groups.values()):
                self._reply(key, {'code':-32602,'message':'Gateway discovery is one complete, non-paginated list at a time.'}, True); return
            self.discovered = False
            group.update(remaining=set(self.servers), names={s:set() for s in self.servers}, cursors={s:set() for s in self.servers}, pages={s:0 for s in self.servers})
            for server in self.servers: self._request(server, key, method, {})
        elif method == 'tools/call':
            alias, arguments = params.get('name'), params.get('arguments')
            if not self.discovered or type(alias) is not str or type(arguments) is not dict or set(params) != {'name','arguments'}:
                self._reply(key, {'code':-32602,'message':'Discover a reviewed gateway tool before calling it.'}, True); return
            server, separator, name = alias.partition('__')
            source = self.servers.get(server)
            rule = next((r for r in source.policy.tools if r.name == name), None) if source else None
            if not separator or rule is None or not source.policy.allows(name, rule.definition_sha256, arguments):
                self._reply(key, {'code':-32001,'message':'Gateway policy denied this call.'}, True); return
            self._request(server, key, method, {'name':name,'arguments':arguments})
        else:
            self._reply(key, {'code':-32601,'message':'Gateway supports tool discovery and calls only.'}, True)

    def _server(self, server, message):
        if 'method' in message:
            if message['method'] == 'notifications/tools/list_changed': raise ValueError('Definitions invalidated')
            if 'id' in message:
                id_key(message['id'])
                self._write(self.children[server].stdin, error(message['id'], 'Reverse requests are unavailable through this gateway.', -32601))
            return
        request_id = message.get('id')
        id_key(request_id)
        request = self.pending.get(request_id) if type(request_id) is str else None
        if request is None: return
        owner, key, method = request
        if owner != server: raise ValueError('Response from wrong server')
        self.pending.pop(request_id)
        group = self.groups.get(key)
        if group is None or key in self.cancelled: return
        if ('result' in message) == ('error' in message): raise ValueError('Invalid response')
        body = message.get('result')
        if method == 'tools/call':
            # Never forward uninspected top-level response extensions.
            self._reply(key, message.get('error') if 'error' in message else body, 'error' in message); return
        if type(body) is not dict: raise ValueError('Initialization/discovery failed')
        if method == 'initialize':
            caps = body.get('capabilities')
            if body.get('protocolVersion') != self.version or type(caps) is not dict or type(caps.get('tools')) is not dict:
                raise ValueError('Unsupported server protocol')
        else:
            tools = body.get('tools')
            if type(tools) is not list or len(tools) > MAX_TOOLS: raise ValueError('Tool list limit')
            for tool in tools:
                fingerprint = tool_digest(tool)
                name = tool['name']
                if name in group['names'][server]: raise ValueError('Duplicate tool')
                group['names'][server].add(name)
                if len(group['names'][server]) > MAX_TOOLS: raise ValueError('Tool count')
                expected = next((r for r in self.servers[server].policy.tools if r.name == name), None)
                if expected is not None and fingerprint != expected.definition_sha256: raise ValueError('Tool changed')
            group['pages'][server] += 1
            cursor = body.get('nextCursor')
            if cursor is not None:
                if type(cursor) is not str or not 1 <= len(cursor) <= 256 or cursor in group['cursors'][server] or group['pages'][server] >= 16:
                    raise ValueError('Cursor limit')
                group['cursors'][server].add(cursor)
                self._request(server, key, method, {'cursor':cursor}); return
            if any(rule.name not in group['names'][server] for rule in self.servers[server].policy.tools): raise ValueError('Missing reviewed tool')
        group['remaining'].remove(server)
        if not group['remaining']:
            if method == 'initialize':
                self.initialized = True
                self._reply(key, {'protocolVersion':self.version,'capabilities':{'tools':{'listChanged':False}},'serverInfo':{'name':'llms-ink-guard-gateway','version':'1'}})
            else:
                self.discovered = True
                self._reply(key, {'tools':self.config.tools()})

    def run(self, stdin, stdout):
        self.output = stdout
        os.set_blocking(stdout.fileno(), False)
        reader = threading.Thread(target=self._reader, args=(stdin, 'client'), daemon=True)
        self.readers.append(reader); reader.start()
        try:
            while not self.stop.is_set():
                if self.disconnected.is_set(): return 0
                if self.invalidated.is_set(): raise ValueError('Upstream changed or disconnected')
                if any(time.monotonic()-g['at'] > self.request_timeout for g in self.groups.values()): raise TimeoutError
                try: source, raw = self.events.get(timeout=.1)
                except queue.Empty: continue
                if raw is None:
                    if source == 'client': return 0
                    raise ValueError('Transport failed')
                message = parse(raw)
                if source == 'client': self._client(message)
                else: self._server(source.removeprefix('server:'), message)
            return 0
        except (ValueError, TypeError, OSError, RecursionError, TimeoutError):
            for group in list(self.groups.values()):
                try: self._write(stdout, error(group['id'], 'Gateway connection failed. Reconnect after reviewing the configured servers.'))
                except (OSError, TimeoutError): break
            return 2
        except KeyboardInterrupt:
            return 130
        finally:
            self.stop.set()
            for reader in self.readers: reader.join(timeout=.3)
            for child in self.children.values():
                try: child.terminate()
                except OSError: pass
            for child in self.children.values():
                try: child.wait(timeout=.2)
                except subprocess.TimeoutExpired: child.kill(); child.wait()
                child.stdin.close(); child.stdout.close()


def main():
    parser = argparse.ArgumentParser(description='Internal transport; use llms-ink-guard gateway.')
    parser.add_argument('--config', required=True); parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    try:
        if os.name != 'posix': raise ValueError('POSIX required')
        config = GatewayConfig.load(args.config)
        if config.sha256 != args.sha256: raise ValueError('Configuration changed')
        def terminate(_signal, _frame): raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, terminate)
        return Gateway(config).run(sys.stdin.buffer, sys.stdout.buffer)
    except (ValueError, RuntimeError):
        print('Gateway configuration or transport is unavailable.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
