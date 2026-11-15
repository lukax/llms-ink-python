"""MCP 2026-07-28 client adapter for the exact-policy aggregate gateway.

The upstream aggregate remains legacy stdio. Continuations are random one-use
handles to immutable approvals held in this process, never client-supplied grants.
A stdio connection is a boundary, not an authenticated conversation identity.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import secrets
import threading

from . import __version__
from .guard_approval import supports_approval
from .guard_proxy import Proxy, error, id_key, parse, transport_metadata_only

VERSION = '2026-07-28'
PREFIX = 'io.modelcontextprotocol/'


def encoded(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(',', ':')).encode()


@dataclass(frozen=True)
class Continuation:
    call_id: str
    form_id: str
    params: bytes


class ModernProxy(Proxy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.policy is None or not self.require_approval or not self.process_group:
            raise RuntimeError('Modern protocol requires the exact-policy aggregate gateway and host approval.')
        # A denial writes its response while holding the dispatch lock. Removing
        # that response's routing entry must acquire the same lock recursively.
        self.state_lock = threading.RLock()
        self.serial = 0
        self.external_seen = set()
        self.external_cancelled = set()
        self.routes = {}  # internal ID -> [current external ID or None, method]
        self.external_routes = {}  # external ID key -> internal ID, also read under state_lock
        self.continuations = {}
        self.boot = None
        self.deferred = None
        self.output = None

    def _new_id(self):
        self.serial += 1
        return f'modern-{self.serial}'

    def _record_cancel(self, request_id):
        key = id_key(request_id)
        with self.state_lock:
            if len(self.external_cancelled) >= 4096:
                self.client_disconnected.set()
                return
            self.external_cancelled.add(key)
            internal = self.external_routes.get(key)
            if internal is not None:
                self.cancelled.add(id_key(internal))

    def _bind(self, external, internal):
        with self.state_lock:
            self.external_routes[id_key(external)] = internal
            if id_key(external) in self.external_cancelled:
                self.cancelled.add(id_key(internal))

    def _forget(self, internal):
        self.routes.pop(internal, None)
        self.continuations = {token: c for token, c in self.continuations.items() if c.call_id != internal}
        with self.state_lock:
            self.external_routes = {key: value for key, value in self.external_routes.items() if value != internal}

    def _reply(self, external, body, *, failed=False):
        if not failed:
            body = {**body, 'resultType': 'complete', '_meta': {PREFIX + 'serverInfo': {'name': 'llms-ink-guard', 'version': __version__}}}
        Proxy._write(self.output, {'jsonrpc': '2.0', 'id': external, 'error' if failed else 'result': body})

    def _reject(self, external, message='Request is not supported by this guarded connection.', code=-32602):
        self._reply(external, {'code': code, 'message': message}, failed=True)

    def _write(self, stream, message):
        if stream is not self.output:
            return Proxy._write(stream, message)
        # Only guard-generated forms become MRTR. Upstream reverse requests are
        # refused by Proxy; arbitrary result fields cannot become input requests.
        if message.get('method') == 'elicitation/create':
            approval = self.awaiting[id_key(message['id'])]
            route = self.routes[approval.call_id]
            token = secrets.token_hex(32)
            self.continuations[token] = Continuation(approval.call_id, approval.id, encoded(parse(approval.action)['params']))
            Proxy._write(stream, {'jsonrpc': '2.0', 'id': route[0], 'result': {
                'resultType': 'input_required', 'requestState': token,
                'inputRequests': {'approval': {'method': 'elicitation/create', 'params': message['params']}},
                '_meta': {PREFIX + 'serverInfo': {'name': 'llms-ink-guard', 'version': __version__}},
            }})
            route[0] = None  # The first request is complete; expiry must not answer it twice.
            return
        if 'method' in message:
            return
        internal = message.get('id')
        if internal == self.boot:
            # Initialization is private to the upstream legacy transport.
            if 'error' in message:
                external = self.routes[internal][0]
                self._reply(external, message['error'], failed=True)
                self.deferred = None
            self.routes.pop(internal, None)
            return
        route = self.routes.get(internal)
        if route is None:
            return
        external, method = route
        self._forget(internal)
        if external is None:
            return
        if 'error' in message:
            # Suppress upstream extension data with execution semantics.
            body = message['error']
            self._reply(external, {k: body[k] for k in ('code', 'message') if k in body}, failed=True)
        else:
            body = message['result']
            keys = ('tools',) if method == 'tools/list' else ('content', 'structuredContent', 'isError')
            result = {k: body[k] for k in keys if k in body}
            if method == 'tools/list':
                result.update(ttlMs=0, cacheScope='private')
            self._reply(external, result)

    @staticmethod
    def _cancel_form(approval, output):
        # Modern stdio servers may only send cancellation for subscription streams.
        pass

    def _client(self, raw, child, output):
        self.output = output
        message = parse(raw)
        method, params = message.get('method'), message.get('params', {})
        if 'id' not in message:
            if method == 'notifications/cancelled' and type(params) is dict:
                external = id_key(params.get('requestId'))
                with self.state_lock:
                    internal = self.external_routes.get(external)
                if internal is not None:
                    super()._client(encoded({'jsonrpc': '2.0', 'method': method, 'params': {'requestId': internal}}), child, output)
                    self._forget(internal)
                    if self.deferred is not None and self.deferred['id'] == internal:
                        self.deferred = None
            return
        external = message['id']
        key = id_key(external)
        if key in self.external_seen or len(self.external_seen) >= 4096:
            raise ValueError('Modern request IDs must be unique within a bounded connection')
        self.external_seen.add(key)
        if type(method) is not str or type(params) is not dict or set(message) != {'jsonrpc', 'id', 'method', 'params'}:
            self._reject(external)
            return
        meta = params.get('_meta')
        if type(meta) is not dict:
            self._reject(external, 'MCP 2026-07-28 requires per-request protocol metadata; legacy clients must omit --client-protocol.')
            return
        version = meta.get(PREFIX + 'protocolVersion')
        if type(version) is not str:
            self._reject(external, 'Protocol version must be supplied on every request.')
            return
        if version != VERSION:
            self._reply(external, {'code': -32022, 'message': 'Unsupported protocol version',
                                  'data': {'supported': [VERSION], 'requested': version}}, failed=True)
            return
        caps = meta.get(PREFIX + 'clientCapabilities')
        correlation = {k: v for k, v in meta.items() if k not in {PREFIX + 'protocolVersion', PREFIX + 'clientCapabilities', PREFIX + 'clientInfo'}}
        if type(caps) is not dict or not transport_metadata_only({'_meta': correlation}):
            self._reject(external)
            return
        # clientInfo is self-reported display metadata, never identity or authority.
        clean = {k: v for k, v in params.items() if k != '_meta'}
        if method in {'server/discover', 'ping'}:
            if clean:
                self._reject(external)
                return
            result = {'supportedVersions': [VERSION], 'capabilities': {'tools': {}}, 'ttlMs': 0, 'cacheScope': 'private'} if method == 'server/discover' else {}
            self._reply(external, result)
            return
        if method not in {'tools/list', 'tools/call'}:
            self._reject(external, 'This gateway supports server discovery, tool discovery and approved tool calls on MCP 2026-07-28.', -32601)
            return
        if method == 'tools/list' and clean:
            self._reject(external, 'Aggregate discovery returns the complete configured list; cursors and extensions are not supported.')
            return
        if method == 'tools/call':
            if not supports_approval({'protocolVersion': '2025-11-25', 'capabilities': caps}):
                self._reject(external, 'Declare form elicitation capability on every call and approval continuation.')
                return
            if set(clean) - {'name', 'arguments', 'requestState', 'inputResponses'}:
                self._reject(external)
                return
            if 'requestState' in clean or 'inputResponses' in clean:
                self._resume(external, clean, child, output)
                return
        internal = self._new_id()
        self.routes[internal] = [external, method]
        self._bind(external, internal)
        request = {'jsonrpc': '2.0', 'id': internal, 'method': method, 'params': clean}
        if not self.initialized:
            if self.initializing:
                self._forget(internal)
                self._reject(external, 'Gateway initialization is pending; retry after the current request finishes.')
                return
            self.deferred = request
            self.boot = self._new_id()
            self.routes[self.boot] = [external, 'initialize']
            super()._client(encoded({'jsonrpc': '2.0', 'id': self.boot, 'method': 'initialize', 'params': {
                'protocolVersion': '2025-11-25', 'capabilities': {'elicitation': {'form': {}}},
                'clientInfo': {'name': 'llms-ink-modern-adapter', 'version': __version__},
            }}), child, output)
            return
        super()._client(encoded(request), child, output)

    def _resume(self, external, params, child, output):
        token = params.get('requestState')
        continuation = self.continuations.pop(token, None) if type(token) is str else None
        if continuation is None:
            self._reject(external, 'Approval continuation is missing, expired, consumed or belongs to another connection.')
            return
        internal = continuation.call_id
        # Bind before any dispatch so the reader can record cancellation while
        # this event is being handled. The underlying approval rechecks the lock.
        self._bind(external, internal)
        self.routes[internal][0] = external
        action = {'name': params.get('name'), 'arguments': params.get('arguments', {})}
        responses = params.get('inputResponses')
        if encoded(action) != continuation.params or type(responses) is not dict or set(responses) != {'approval'}:
            self.awaiting.pop(id_key(continuation.form_id), None)
            self._release_approval()
            self._forget(internal)
            self._reject(external, 'Approval continuation did not match the complete reviewed action. No call was sent.')
            return
        super()._approval_response({'jsonrpc': '2.0', 'id': continuation.form_id, 'result': responses['approval']}, child, output)
        if id_key(internal) not in self.pending:
            self._forget(internal)

    def _server(self, raw, child, output):
        self.output = output
        initializing = self.boot is not None and parse(raw).get('id') == self.boot
        super()._server(raw, child, output)
        if initializing and self.initialized:
            self.boot = None
            super()._client(encoded({'jsonrpc': '2.0', 'method': 'notifications/initialized'}), child, output)
            if self.deferred is not None:
                request, self.deferred = self.deferred, None
                super()._client(encoded(request), child, output)

    def run(self, stdin, stdout):
        self.output = stdout
        try:
            return super().run(stdin, stdout)
        finally:
            self.continuations.clear()
            self.routes.clear()
            with self.state_lock:
                self.external_routes.clear()
                self.external_cancelled.clear()
