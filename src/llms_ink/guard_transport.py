"""Bounded, stoppable reads for POSIX stdio; retain the legacy Windows fallback."""
import os
import select


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
