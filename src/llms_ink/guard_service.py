"""Authenticated owner control and session-bound MCP over private POSIX IPC.

Credentials are capabilities, not human attestations. An owner must isolate the
control credential from agents and upstream processes; same-user code is not
sandboxed by Unix socket permissions. No network listener or credential relay.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import stat
import sys
import threading
import time

from .guard import receipt
from .guard_gateway_config import GatewayConfig
from .guard_modern import ModernProxy
from .guard_policy import decode
from .guard_proxy import Proxy
from .guard_session import SessionScope
from .guard_transport import BoundedWriter

CONTROL_BYTES = 8192
MAX_SESSIONS = 16
MAX_CONNECTIONS = 8
MAX_SESSION_CONNECTIONS = 4
TOKEN = re.compile(r'^[a-f0-9]{64}$')
SESSION_ID = re.compile(r'^[a-f0-9]{32}$')
REJECTED = {'ok': False, 'error': 'Guard service rejected the request.'}


def private_directory(path):
    path = Path(path).absolute()
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('Private owner directory required')
    return path


def read_credential(path, role=None):
    path = Path(path).absolute()
    private_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > CONTROL_BYTES:
            raise ValueError('Private credential required')
        data = decode(stream.read(CONTROL_BYTES + 1))
    expected = {'version', 'role', 'socket', 'token'}
    if type(data) is not dict or data.get('role') not in {'owner', 'session'}:
        raise ValueError('Invalid credential')
    if data['role'] == 'session':
        expected |= {'sessionId', 'protocol', 'policySha256', 'expiresAt'}
    if set(data) != expected or type(data.get('version')) is not int or data['version'] != 1 or (role and data['role'] != role):
        raise ValueError('Invalid credential')
    if type(data['token']) is not str or not TOKEN.fullmatch(data['token']):
        raise ValueError('Invalid credential')
    endpoint = Path(data['socket'])
    if not endpoint.is_absolute() or endpoint.name != 'service.sock' or len(os.fsencode(endpoint)) >= 100:
        raise ValueError('Invalid service socket')
    private_directory(endpoint.parent)
    if data['role'] == 'owner' and endpoint.parent != path.parent:
        raise ValueError('Owner credential and socket must share a private directory')
    if data['role'] == 'session':
        if (type(data['sessionId']) is not str or not SESSION_ID.fullmatch(data['sessionId'])
                or type(data['protocol']) is not str or data['protocol'] not in {'legacy', '2026-07-28'}
                or type(data['policySha256']) is not str or not TOKEN.fullmatch(data['policySha256'])
                or type(data['expiresAt']) is not int or data['expiresAt'] <= 0):
            raise ValueError('Invalid session credential')
    return data


def write_private(path, data):
    path = Path(path).absolute()
    private_directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    # A partial credential is unusable; never replace an existing file or follow
    # a symlink. Leave any failed write for the owner to inspect, not overwrite.
    with os.fdopen(fd, 'wb') as stream:
        stream.write(json.dumps(data, ensure_ascii=True, allow_nan=False).encode() + b'\n')
        stream.flush(); os.fsync(stream.fileno())


def initialize(directory):
    if os.name != 'posix':
        raise RuntimeError('The local session service requires macOS or Linux.')
    directory = Path(directory).absolute()
    directory.mkdir(mode=0o700, parents=False, exist_ok=True)
    private_directory(directory)
    endpoint = directory / 'service.sock'
    if len(os.fsencode(endpoint)) >= 100:
        raise ValueError('Service directory path is too long')
    write_private(directory / 'owner.json', {'version': 1, 'role': 'owner', 'socket': str(endpoint), 'token': secrets.token_hex(32)})


def frame(stream, timeout=10):
    # Socket idle timeouts reset on each read. Use an absolute deadline so a
    # trickling peer cannot keep an authentication slot indefinitely. Read only
    # through this newline; the next bytes belong to the attached MCP stream.
    raw, deadline = bytearray(), time.monotonic() + timeout
    while len(raw) <= CONTROL_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Control deadline')
        if not select.select([stream.fileno()], [], [], remaining)[0]:
            raise TimeoutError('Control deadline')
        try: byte = os.read(stream.fileno(), 1)
        except BlockingIOError: continue
        if not byte:
            raise ValueError('Incomplete control frame')
        raw.extend(byte)
        if byte == b'\n': break
    if len(raw) > CONTROL_BYTES:
        raise ValueError('Invalid control frame')
    data = decode(bytes(raw))
    if type(data) is not dict:
        raise ValueError('Invalid control frame')
    return data


def send(sock, data):
    raw = json.dumps(data, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode() + b'\n'
    if len(raw) > CONTROL_BYTES:
        raise ValueError('Control frame too large')
    sock.sendall(raw)


def open_socket(credential):
    endpoint = Path(credential['socket'])
    private_directory(endpoint.parent)
    info = endpoint.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('Invalid private socket')
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect(str(endpoint))
        return sock
    except BaseException:
        sock.close()
        raise


def control(owner_file, operation, **params):
    credential = read_credential(owner_file, 'owner')
    with open_socket(credential) as sock, sock.makefile('rb', buffering=0) as stream:
        send(sock, {'op': operation, 'token': credential['token'], **params})
        result = frame(stream)
    if result.get('ok') is not True:
        raise RuntimeError('Guard service rejected the request.')
    return result


def create_session(owner_file, output, protocol='legacy', ttl=3600):
    # Validate destination before minting a capability. A failed exclusive write
    # revokes the new session, preserving the caller's existing file.
    private_directory(Path(output).absolute().parent)
    if os.path.lexists(output):
        raise ValueError('Output already exists')
    result = control(owner_file, 'create', protocol=protocol, ttl=ttl)
    grant = result['credential']
    try:
        write_private(output, grant)
    except BaseException:
        try: control(owner_file, 'revoke', sessionId=grant['sessionId'])
        except Exception: pass
        raise
    return {'sessionId': grant['sessionId'], 'expiresAt': grant['expiresAt']}


def attach(session_file):
    credential = read_credential(session_file, 'session')
    sock = open_socket(credential)
    stream = sock.makefile('rb', buffering=0)
    try:
        send(sock, {'op': 'attach', 'sessionId': credential['sessionId'], 'token': credential['token']})
        if frame(stream) != {'ok': True, 'protocol': credential['protocol']}:
            raise RuntimeError('Guard service rejected the session.')
        sock.settimeout(None)
        return sock, stream
    except BaseException:
        stream.close(); sock.close()
        raise


def connect(session_file, stdin, stdout):
    sock, incoming = attach(session_file)
    try:
        writer = BoundedWriter(sock.makefile('wb', buffering=0))
        output = BoundedWriter(stdout)
        try:
            while True:
                ready, _, _ = select.select([stdin.fileno(), sock.fileno()], [], [], .2)
                if sock.fileno() in ready:
                    try: raw = os.read(sock.fileno(), 65536)
                    except BlockingIOError: continue
                    if not raw: return 0
                    output.write(raw)
                if stdin.fileno() in ready:
                    raw = os.read(stdin.fileno(), 65536)
                    if not raw: return 0
                    writer.write(raw)
        finally:
            writer.close()
    finally:
        try: sock.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        incoming.close(); sock.close()


class SharedGuard:
    def __init__(self, guard):
        self.guard = guard
        self.lock = threading.Lock()
        self.closing = threading.Event()

    def inspect(self, text):
        if self.closing.is_set() or not self.lock.acquire(timeout=1):
            return receipt('unscanned', 'model_unavailable', coverage='none')
        try:
            if self.closing.is_set():
                return receipt('unscanned', 'model_unavailable', coverage='none')
            return self.guard.inspect(text)
        finally:
            self.lock.release()

    def close(self):
        self.closing.set()
        # Closing the worker also unblocks an in-flight failed model pipe. All
        # sessions are revoked and their sockets closed before this is invoked.
        if self.guard is not None:
            self.guard.close()
            # SIGTERM cannot wake a stopped model worker. The service owns this
            # process and must reap it before finishing shutdown.
            process = getattr(self.guard, 'process', None)
            if process is not None and process.is_alive():
                process.kill()
                process.join(timeout=2)
                if process.is_alive():
                    raise RuntimeError('The local model worker did not stop.')


@dataclass
class Session:
    id: str
    token_hash: str
    protocol: str
    expires_at: int
    scope: SessionScope
    connections: dict = field(default_factory=dict)
    counts: dict = field(default_factory=dict)


class Service:
    def __init__(self, owner_file, config_file, guard, *, log=None):
        self.owner = read_credential(owner_file, 'owner')
        self.config = GatewayConfig.load(config_file)
        self.command = self.config.command(config_file)
        self.policy = self.config.outer_policy(self.command)
        self.guard = SharedGuard(guard)
        self.log = log or (lambda item: print(json.dumps(item, separators=(',', ':')), file=sys.stderr, flush=True))
        self.sessions = {}
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.slots = threading.BoundedSemaphore(16)
        self.handlers = set()
        self.sockets = set()
        self.listener = None
        self.socket_identity = None
        self.ready = threading.Event()

    @staticmethod
    def token_hash(token):
        if type(token) is not str or not TOKEN.fullmatch(token):
            raise ValueError('Invalid token')
        return hashlib.sha256(token.encode('ascii')).hexdigest()

    def _audit(self, session, event):
        outcome = event.get('outcome')
        if outcome in {'allow', 'quarantine', 'unscanned', 'denied'}:
            with session.scope.lock:
                session.counts[outcome] = session.counts.get(outcome, 0) + 1
        allowed = {k: v for k, v in event.items() if k in {'event', 'outcome', 'reason', 'tokens', 'windows', 'elapsedMs'}}
        self.log(allowed)

    def _revoke(self, session):
        session.scope.revoke()
        for sock, proxy in list(session.connections.items()):
            proxy.stop.set()
            proxy.client_disconnected.set()
            try: sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass

    def _handle(self, sock):
        session = None
        attached = False
        try:
            sock.settimeout(3)
            with sock.makefile('rb', buffering=0) as incoming:
                request = frame(incoming, timeout=3)
                op = request.get('op')
                if op == 'attach':
                    if set(request) != {'op', 'sessionId', 'token'}:
                        raise ValueError('Invalid attach')
                    digest = self.token_hash(request['token'])
                    with self.lock:
                        session = self.sessions.get(request['sessionId']) if type(request['sessionId']) is str else None
                        if (session is None or not secrets.compare_digest(digest, session.token_hash) or not session.scope.valid()
                                or len(session.connections) >= MAX_SESSION_CONNECTIONS
                                or sum(len(s.connections) for s in self.sessions.values()) >= MAX_CONNECTIONS or self.stop.is_set()):
                            raise ValueError('Session unavailable')
                        proxy_type = ModernProxy if session.protocol == '2026-07-28' else Proxy
                        proxy = proxy_type(self.command, self.guard, policy=self.policy, require_approval=True,
                                           review_commands=self.config.review_commands(), process_group=True,
                                           approval_scope=session.scope, log=lambda data: self._audit(session, data))
                        session.connections[sock] = proxy
                    send(sock, {'ok': True, 'protocol': session.protocol})
                    attached = True
                    sock.settimeout(None)
                    with sock.makefile('wb', buffering=0) as outgoing:
                        code = proxy.run(incoming, outgoing)
                    if code != 0:
                        with self.lock:
                            self._revoke(session)
                    return
                digest = self.token_hash(request.get('token'))
                if not secrets.compare_digest(digest, self.token_hash(self.owner['token'])):
                    raise ValueError('Owner authentication failed')
                with self.lock:
                    if self.stop.is_set():
                        raise ValueError('Service stopped')
                    if op == 'create' and set(request) == {'op', 'token', 'protocol', 'ttl'}:
                        ttl = request['ttl']; protocol = request['protocol']
                        if type(ttl) is not int or not 1 <= ttl <= 86400 or protocol not in {'legacy', '2026-07-28'} or len(self.sessions) >= MAX_SESSIONS:
                            raise ValueError('Invalid session parameters')
                        token = secrets.token_hex(32); sid = secrets.token_hex(16)
                        session = Session(sid, self.token_hash(token), protocol, int(time.time()) + ttl, SessionScope(time.monotonic() + ttl))
                        self.sessions[sid] = session
                        grant = {'version': 1, 'role': 'session', 'socket': self.owner['socket'], 'token': token,
                                 'sessionId': sid, 'protocol': protocol, 'policySha256': self.config.sha256, 'expiresAt': session.expires_at}
                        send(sock, {'ok': True, 'credential': grant})
                        self.log({'event': 'session_created'})
                    elif op == 'revoke' and set(request) == {'op', 'token', 'sessionId'}:
                        target = self.sessions.get(request['sessionId']) if type(request['sessionId']) is str else None
                        if target is None: raise ValueError('Unknown session')
                        self._revoke(target)
                        send(sock, {'ok': True})
                        self.log({'event': 'session_revoked'})
                    elif op == 'status' and set(request) == {'op', 'token'}:
                        states = []
                        for s in self.sessions.values():
                            with s.scope.lock:
                                states.append({'sessionId': s.id, 'active': s.scope.valid(), 'expiresAt': s.expires_at,
                                               'connections': len(s.connections), 'approvalPending': s.scope.holder is not None,
                                               'decisions': dict(s.counts)})
                        send(sock, {'ok': True, 'policySha256': self.config.sha256, 'sessions': states})
                    else:
                        raise ValueError('Invalid control operation')
        except (ValueError, TypeError, KeyError, OSError, RuntimeError, RecursionError):
            if not attached:
                try: send(sock, REJECTED)
                except OSError: pass
            self.log({'event': 'service_request_rejected'})
        finally:
            with self.lock:
                if session is not None:
                    session.connections.pop(sock, None)
                self.sockets.discard(sock)
                self.handlers.discard(threading.current_thread())
            sock.close()
            self.slots.release()

    def run(self):
        endpoint = Path(self.owner['socket'])
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener = listener
        try:
            # Never unlink an existing socket: it could be another live service.
            listener.bind(str(endpoint)); os.chmod(endpoint, 0o600)
            info = endpoint.lstat(); self.socket_identity = (info.st_dev, info.st_ino)
            listener.listen(16); listener.settimeout(.2)
            self.ready.set(); self.log({'event': 'service_ready'})
            while not self.stop.is_set():
                with self.lock:
                    for sid, session in list(self.sessions.items()):
                        if not session.scope.valid():
                            self._revoke(session)
                            if not session.connections:
                                self.sessions.pop(sid)
                try: sock, _ = listener.accept()
                except socket.timeout: continue
                if not self.slots.acquire(blocking=False):
                    sock.close(); continue
                thread = threading.Thread(target=self._handle, args=(sock,), daemon=True)
                with self.lock:
                    self.sockets.add(sock); self.handlers.add(thread)
                thread.start()
            return 0
        finally:
            self.close()

    def close(self):
        self.stop.set()
        with self.lock:
            for session in self.sessions.values(): self._revoke(session)
            for sock in self.sockets:
                try: sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass
        self.guard.close()
        deadline = time.monotonic() + 25
        with self.lock:
            handlers = list(self.handlers)
        for thread in handlers:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        if self.listener is not None: self.listener.close()
        endpoint = Path(self.owner['socket'])
        try:
            info = endpoint.lstat()
            if (info.st_dev, info.st_ino) == self.socket_identity: endpoint.unlink()
        except FileNotFoundError: pass
        if any(thread.is_alive() for thread in handlers):
            raise RuntimeError('Service shutdown did not finish; inspect owned processes before restarting.')
