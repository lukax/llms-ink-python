"""Service-owned session authority and approval coordination, never MCP metadata."""
from contextlib import contextmanager
import threading
import time


class SessionScope:
    def __init__(self, expires):
        self.expires = expires
        self.lock = threading.RLock()
        self.active = True
        self.holder = None

    def valid(self):
        return self.active and time.monotonic() < self.expires

    def reserve(self, owner):
        with self.lock:
            if not self.valid() or self.holder is not None:
                return False
            self.holder = owner
            return True

    def release(self, owner):
        with self.lock:
            if self.holder is owner:
                self.holder = None

    @contextmanager
    def dispatch(self, owner):
        # Revocation and the first dispatch byte have one ordering point. Once
        # dispatch has begun, no session API can promise to undo its effect.
        with self.lock:
            yield self.valid() and self.holder is owner

    def revoke(self):
        with self.lock:
            self.active = False
            self.holder = None
