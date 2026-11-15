"""Trusted PID-1 deadline for the optional offline container profile.

Executed as source with a reviewed in-image Python interpreter (-I -S). This
file has no package imports and must not be used as a general-purpose init.
"""
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def main():
    if os.getpid() != 1 or os.getuid() != 65532 or os.getgid() != 65532:
        return 125
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if (int(status['CapEff'].strip(), 16) != 0 or status['NoNewPrivs'].strip() != '1'
            or status['Seccomp'].strip() != '2'):
        return 125
    libc = ctypes.CDLL(None, use_errno=True)
    # Prevent same-UID children from modifying this process via ptrace/proc.
    if libc.prctl(4, 0, 0, 0, 0) != 0 or libc.prctl(3, 0, 0, 0, 0) != 0:
        return 125
    seconds = int(sys.argv[1])
    command = sys.argv[2:]
    if not 2 <= seconds <= 3600 or not command or not command[0].startswith('/'):
        return 125
    # Namespace members cannot stop PID 1 with SIGSTOP. Handled signals may
    # terminate us early, which also terminates every remaining descendant.
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda *_: os._exit(130))
    deadline = time.monotonic() + seconds
    child = subprocess.Popen(command, close_fds=True, start_new_session=True)
    while time.monotonic() < deadline:
        # Reap adopted grandchildren too; a process-group escape is still in
        # this PID namespace. Leaving PID 1 kills the namespace's processes.
        try:
            while True:
                pid, status = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
                if pid == child.pid:
                    return os.waitstatus_to_exitcode(status) % 256
        except ChildProcessError:
            return 0
        time.sleep(.05)
    return 124


if __name__ == '__main__':
    try:
        result = main()
    except BaseException:
        result = 125
    os._exit(result)
