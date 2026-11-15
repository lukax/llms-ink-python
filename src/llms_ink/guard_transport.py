"""Bounded, stoppable reads for POSIX stdio; retain the legacy Windows fallback."""
import os
import select
import time
from contextlib import nullcontext


class DispatchRevoked(OSError):
    pass


class ClientDisconnected(ConnectionError):
    pass


class BoundedWriter:
    """Complete bounded writes without holding a dispatch lock indefinitely."""
    def __init__(self, stream, timeout=5):
        self.stream, self.timeout = stream, timeout
        os.set_blocking(stream.fileno(), False)

    def write(self, raw):
        return self.write_checked(raw)

    def write_checked(self, raw, guard=None):
        offset, deadline = 0, time.monotonic() + self.timeout
        while offset < len(raw):
            if time.monotonic() >= deadline:
                raise TimeoutError('Transport write timed out')
            if not select.select([], [self.fileno()], [], .05)[1]:
                continue
            try:
                with (guard() if offset == 0 and guard is not None else nullcontext(True)) as allowed:
                    if not allowed:
                        raise DispatchRevoked('Dispatch no longer permitted')
                    count = os.write(self.fileno(), raw[offset:])
            except BlockingIOError:
                continue
            if not count:
                raise OSError('Transport closed')
            offset += count
        return offset

    def flush(self):
        pass

    def fileno(self):
        return self.stream.fileno()

    def close(self):
        self.stream.close()


class ClientWriter(BoundedWriter):
    def write(self, raw):
        try:
            return super().write(raw)
        except (BrokenPipeError, ConnectionResetError) as failure:
            # A client can close before the reader observes EOF. Keep this
            # distinct from losing the upstream action transport.
            raise ClientDisconnected('Client connection closed') from failure


def lines(stream, stop, limit):
    if os.name != 'posix':
        while not stop.is_set():
            raw = stream.readline(limit + 1)
            if not raw: return
            if len(raw) > limit: raise ValueError('Message size')
            yield raw
        return
    fd = stream.fileno()
    os.set_blocking(fd, False)
    buffered = bytearray()
    while not stop.is_set():
        if not select.select([fd], [], [], .1)[0]: continue
        try: chunk = os.read(fd, min(65536, limit + 1))
        except BlockingIOError: continue
        if not chunk:
            if buffered: raise ValueError('Incomplete message')
            return
        buffered.extend(chunk)
        while (end := buffered.find(b'\n')) >= 0:
            if end + 1 > limit: raise ValueError('Message size')
            raw = bytes(buffered[:end + 1]); del buffered[:end + 1]
            yield raw
            if stop.is_set(): return
        if len(buffered) > limit: raise ValueError('Message size')
