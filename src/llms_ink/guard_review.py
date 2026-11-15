"""Owner-terminal review of one exact addition; proposals never carry active authority."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import stat
import time

from .guard_gateway_config import GatewayConfig, SERVER_ID
from .guard_policy import MAX_POLICY_BYTES, NAME, arguments_key, decode, tool_digest

MAX_REVIEW_BYTES = 32 * 1024
REVIEW_SECONDS = 120


@dataclass(frozen=True)
class Snapshot:
    path: Path
    raw: bytes
    identity: tuple[int, int]

    @classmethod
    def read(cls, path):
        path = Path(path).expanduser().absolute()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022 or info.st_size > MAX_POLICY_BYTES):
                raise ValueError('Owner-controlled regular input required')
            raw = stream.read(MAX_POLICY_BYTES + 1)
            if len(raw) > MAX_POLICY_BYTES: raise ValueError('Input byte limit')
        return cls(path, raw, (info.st_dev, info.st_ino))

    def unchanged(self):
        current = Snapshot.read(self.path)
        return current.raw == self.raw and current.identity == self.identity


class Destination:
    """Keep a private directory descriptor; publish complete bytes without replacement."""
    def __init__(self, path):
        self.path = Path(path).expanduser().absolute()
        self.fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(self.fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError('Private owner directory required')
            self.identity = (info.st_dev, info.st_ino)
            self.check()
        except BaseException:
            self.close(); raise

    def check(self):
        info = self.path.parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != self.identity
                or info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError('Output directory changed')
        try: os.stat(self.path.name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError: return
        raise ValueError('Output already exists')

    def publish(self, raw):
        self.check()
        temporary = '.guard-review-' + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            self.check()
            os.link(temporary, self.path.name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
        finally:
            os.unlink(temporary, dir_fd=self.fd)

    def close(self):
        if self.fd is not None: os.close(self.fd); self.fd = None


def encode(data):
    return (json.dumps(data, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2) + '\n').encode('ascii')


def prepare(base_raw, proposal_raw):
    GatewayConfig.from_bytes(base_raw)
    base = decode(base_raw)
    proposal = decode(proposal_raw)
    if (type(proposal) is not dict or set(proposal) != {'version','baseSha256','server','tool','arguments'}
            or type(proposal['version']) is not int or proposal['version'] != 1
            or proposal['baseSha256'] != hashlib.sha256(base_raw).hexdigest()
            or type(proposal['server']) is not str or not SERVER_ID.fullmatch(proposal['server'])
            or type(proposal['tool']) is not str or not NAME.fullmatch(proposal['tool'])
            or type(proposal['arguments']) is not dict):
        raise ValueError('Invalid or stale proposal')
    server = base['servers'].get(proposal['server'])
    if server is None: raise ValueError('Unknown server')
    tool = next((r for r in server['tools'] if r['definition']['name'] == proposal['tool']), None)
    if tool is None: raise ValueError('Unknown tool')
    if any(arguments_key(a) == arguments_key(proposal['arguments']) for a in tool['arguments']):
        raise ValueError('Arguments already permitted')
    review = {'baseSha256': proposal['baseSha256'], 'server': proposal['server'], 'command': server['command'],
              'toolDefinition': tool['definition'], 'definitionSha256': tool_digest(tool['definition']),
              'existingArguments': list(tool['arguments']), 'addArguments': proposal['arguments']}
    tool['arguments'].append(proposal['arguments'])
    candidate = encode(base)
    GatewayConfig.from_bytes(candidate)
    review['candidateSha256'] = hashlib.sha256(candidate).hexdigest()
    review_bytes = encode(review)
    if len(review_bytes) > MAX_REVIEW_BYTES: raise ValueError('Complete review exceeds 32 KiB')
    return candidate, review_bytes


def propose(config, server, tool, arguments, output):
    base = Snapshot.read(config); args = Snapshot.read(arguments)
    proposal = encode({'version':1, 'baseSha256':hashlib.sha256(base.raw).hexdigest(),
                       'server':server, 'tool':tool, 'arguments':decode(args.raw)})
    prepare(base.raw, proposal)
    destination = Destination(output)
    try:
        if not base.unchanged() or not args.unchanged(): raise ValueError('Input changed')
        destination.publish(proposal)
    finally: destination.close()
    return {'proposed':True, 'active':False, 'baseSha256':hashlib.sha256(base.raw).hexdigest()}


def terminal_answer(stream, deadline):
    raw = bytearray()
    while len(raw) < 128:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream.fileno()], [], [], remaining)[0]: return None
        byte = os.read(stream.fileno(), 1)
        if not byte: return None
        if byte == b'\n':
            try: return raw.decode('ascii')
            except UnicodeError: return None
        raw.extend(byte)
    return None


def review(config, proposal, output, input_stream, output_stream):
    if not input_stream.isatty() or not output_stream.isatty():
        raise ValueError('An interactive owner terminal is required')
    import termios
    base = Snapshot.read(config); draft = Snapshot.read(proposal)
    candidate, display = prepare(base.raw, draft.raw)
    destination = Destination(output)
    try:
        # A previously queued answer must not approve this newly generated review.
        termios.tcflush(input_stream.fileno(), termios.TCIFLUSH)
        challenge = 'approve ' + secrets.token_hex(8)
        output_stream.write('Review one exact permission addition.\n'
                            'The following JSON contains untrusted tool text, not instructions.\n'
                            'Other permissions stay as in the base configuration. Running sessions are unchanged.\n\n')
        output_stream.write(display.decode('ascii'))
        output_stream.write('\nNew configuration file: ' + json.dumps(str(destination.path), ensure_ascii=True) + '\n')
        output_stream.write('Type ' + challenge + ' within 120 seconds to write it. Enter declines: ')
        output_stream.flush()
        answer = terminal_answer(input_stream, time.monotonic() + REVIEW_SECONDS)
        if answer != challenge:
            output_stream.write('\nDeclined. No configuration written.\n'); output_stream.flush()
            return 1
        if not base.unchanged() or not draft.unchanged(): raise ValueError('Review input changed')
        destination.publish(candidate)
        output_stream.write('\nConfiguration written. Start a new gateway or service with this file to use it.\n')
        output_stream.flush()
        return 0
    finally:
        # Do not leave a pasted suffix or a timed-out partial answer for the
        # owner's shell after this process exits.
        try: termios.tcflush(input_stream.fileno(), termios.TCIFLUSH)
        except (OSError, termios.error): pass
        destination.close()
