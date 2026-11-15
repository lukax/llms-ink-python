"""Optional offline upstream runtime with owned cleanup and durable recovery.

The host, Docker daemon/client, and in-image Python interpreter are trusted.
This module does not inspect MCP messages or grant tool permissions.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

PROFILE = 'llms-ink-offline-2'
LABEL = 'ink.guard.lease'
IMAGE = re.compile(r'sha256:[a-f0-9]{64}\Z')
LEASE = re.compile(r'[a-f0-9]{32}\Z')
MAX_LEASES = 64
MAX_BYTES = 262144
INIT = Path(__file__).with_name('guard_container_init.py').read_text()


class ContainerError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def check(condition, code):
    if not condition:
        raise ContainerError(code)


def encode(data):
    return (json.dumps(data, sort_keys=True, ensure_ascii=True, allow_nan=False) + '\n').encode()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        check(key not in result, 'container_state_invalid')
        result[key] = value
    return result


def validate(image, command, seconds):
    check(type(image) is str and bool(IMAGE.fullmatch(image)), 'container_image_invalid')
    check(type(seconds) is int and 2 <= seconds <= 3600, 'container_deadline_invalid')
    check(type(command) in (list, tuple) and 1 <= len(command) <= 128
        and all(type(arg) is str and '\0' not in arg and len(arg.encode()) <= 8192 for arg in command)
        and command[0].startswith('/') and sum(len(arg.encode()) for arg in command) <= 32768,
        'container_command_invalid')


def create_args(image, lease, command, seconds):
    validate(image, command, seconds)
    check(bool(LEASE.fullmatch(lease)), 'container_lease_invalid')
    return ['create', '--pull', 'never', '--name', 'ink-guard-' + lease,
        '--label', LABEL + '=' + lease, '--label', 'ink.guard.profile=' + PROFILE,
        '--interactive', '--network', 'none', '--read-only', '--user', '65532:65532',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true',
        '--ipc', 'private', '--cgroupns', 'private', '--pids-limit', '32',
        '--memory', '256m', '--memory-swap', '256m', '--cpus', '1', '--shm-size', '16m',
        '--ulimit', 'nofile=128:128', '--ulimit', 'core=0:0',
        '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777',
        '--log-driver', 'none', '--no-healthcheck', '--restart', 'no',
        '--stop-signal', 'SIGTERM', '--stop-timeout', '1', '--workdir', '/tmp',
        '--entrypoint', '/usr/local/bin/python3', image, '-I', '-S', '-c', INIT,
        str(seconds), *command]


class Docker:
    def __init__(self, executable, endpoint):
        check(os.path.isabs(executable) and '\0' not in executable, 'container_docker_invalid')
        check(type(endpoint) is str and endpoint.startswith('unix:///') and '\0' not in endpoint
            and len(endpoint) <= 4096, 'container_endpoint_invalid')
        self.executable, self.endpoint = executable, endpoint
        self.prefix = [executable, '--host', endpoint]

    @staticmethod
    def environment():
        return {key: value for key, value in os.environ.items() if key not in {
            'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION'}}

    @staticmethod
    def invoke(command, timeout=10):
        # Bounded output; no raw Docker errors, image metadata or arguments in
        # diagnostics. This subprocess is owned directly, unlike the container.
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, close_fds=True, env=Docker.environment())
        raw = bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                end = time.monotonic() + timeout
                while selector.get_map():
                    remaining = end - time.monotonic()
                    check(remaining > 0, 'container_daemon_timeout')
                    for key, _ in selector.select(min(.1, remaining)):
                        data = os.read(key.fd, 16384)
                        if not data:
                            selector.unregister(key.fd)
                        else:
                            raw.extend(data)
                            check(len(raw) <= MAX_BYTES, 'container_daemon_output_limit')
                check(child.wait(timeout=max(.01, end - time.monotonic())) == 0, 'container_daemon_failed')
            return bytes(raw)
        except subprocess.TimeoutExpired:
            raise ContainerError('container_daemon_timeout') from None
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(); child.stdout.close()

    @classmethod
    def from_context(cls, executable, context):
        check(os.path.isabs(executable) and type(context) is str and 0 < len(context) <= 128
            and not context.startswith('-') and '\0' not in context, 'container_context_invalid')
        records = json.loads(cls.invoke([executable, 'context', 'inspect', context]))
        check(len(records) == 1, 'container_context_invalid')
        return cls(executable, records[0]['Endpoints']['docker']['Host'])

    def call(self, *args):
        # Docker's user config can automatically inject proxy credentials at
        # create time. Resolve the context once, then use an empty CLI config.
        with tempfile.TemporaryDirectory(prefix='ink-container-client-') as config:
            return self.invoke([*self.prefix, '--config', config, *args])

    def json(self, *args):
        return json.loads(self.call(*args))

    def identity(self):
        identity = self.json('info', '--format', '{{json .ID}}')
        check(type(identity) is str and 1 <= len(identity) <= 128, 'container_daemon_identity_invalid')
        return identity

    def inspect(self, cid):
        records = self.json('container', 'inspect', cid)
        check(len(records) == 1, 'container_identity_invalid')
        return records[0]

    def find(self, name):
        ids = self.call('container', 'ls', '--all', '--quiet', '--no-trunc',
            '--filter', 'name=^/' + name + '$').decode().split()
        check(len(ids) <= 1 and all(re.fullmatch('[a-f0-9]{64}', cid) for cid in ids), 'container_identity_invalid')
        return ids[0] if ids else None


def validate_effective(record, image, lease, command, seconds, environment):
    host, config = record['HostConfig'], record['Config']
    check(record['Image'] == image and record['Name'] == '/ink-guard-' + lease
        and config['Labels'].get(LABEL) == lease and config['Labels'].get('ink.guard.profile') == PROFILE,
        'container_identity_changed')
    check(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] and not host['Privileged']
        and config['User'] == '65532:65532' and not record['Mounts']
        and not host['PortBindings'] and not host['PublishAllPorts']
        and host['CapDrop'] == ['ALL'] and not host['CapAdd']
        and host['SecurityOpt'] == ['no-new-privileges=true']
        and host['IpcMode'] == 'private' and host['CgroupnsMode'] == 'private'
        and not host['PidMode'] and not host['UTSMode'] and not host.get('Init')
        and not host['Devices'] and not host['DeviceRequests']
        and host['PidsLimit'] == 32 and host['Memory'] == 268435456 and host['MemorySwap'] == 268435456
        and host['NanoCpus'] == 1000000000 and host['ShmSize'] == 16777216
        and sorted(host['Ulimits'], key=lambda limit: limit['Name']) == [
            {'Name':'core','Hard':0,'Soft':0}, {'Name':'nofile','Hard':128,'Soft':128}]
        and host['Tmpfs'] == {'/tmp': 'rw,noexec,nosuid,nodev,size=16m,mode=1777'}
        and host['RestartPolicy']['Name'] == 'no' and not host['AutoRemove']
        and host['LogConfig']['Type'] == 'none' and config['Healthcheck']['Test'] == ['NONE']
        and config['Entrypoint'] == ['/usr/local/bin/python3']
        and config['Cmd'] == ['-I', '-S', '-c', INIT, str(seconds), *command]
        and config['Env'] == environment, 'container_profile_unavailable')


class Store:
    """Private immutable leases and fsynced phase markers, with kernel locks."""
    def __init__(self, directory):
        self.path = Path(directory).absolute()
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(self.fd)
            check(info.st_uid == os.getuid() and not info.st_mode & 0o077, 'container_state_not_private')
            self.identity = (info.st_dev, info.st_ino)
            self.check()
        except BaseException:
            os.close(self.fd); raise

    def close(self):
        os.close(self.fd)

    def check(self):
        info = self.path.lstat()
        check(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077
            and (info.st_dev, info.st_ino) == self.identity, 'container_state_changed')

    def open(self, name, *, create=False):
        self.check()
        fd = os.open(name, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW
            | (os.O_CREAT | os.O_EXCL if create else 0), 0o600, dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            check(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077
                and info.st_nlink == 1 and info.st_size <= 16384, 'container_state_invalid')
            return fd
        except BaseException:
            os.close(fd); raise

    @contextmanager
    def locked(self):
        try:
            lock = self.open('.lock', create=True)
        except FileExistsError:
            lock = self.open('.lock')
        try:
            # Never wait indefinitely for another owner operation.
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ContainerError('container_state_busy') from None
            self.check()
            yield
        finally:
            os.close(lock)

    def names(self):
        self.check()
        names = os.listdir(self.fd)
        check(len(names) <= MAX_LEASES * 3 + 1, 'container_state_limit')
        for name in names:
            check(name == '.lock' or re.fullmatch(r'[a-f0-9]{32}\.(json|attempted|created)', name),
                'container_state_invalid')
        leases = [name[:-5] for name in names if name.endswith('.json')]
        check(all(name == '.lock' or name.split('.')[0] in leases for name in names), 'container_state_invalid')
        return leases

    def load(self, lease):
        check(bool(LEASE.fullmatch(lease)), 'container_lease_invalid')
        fd = self.open(lease + '.json')
        try:
            raw = os.read(fd, 16385)
            data = json.loads(raw, object_pairs_hook=unique_pairs)
            check(type(data) is dict and set(data) == {'version','lease','profile','docker','endpoint',
                'daemon','image','seconds','commandSha256','guardianPid'} and type(data['version']) is int and data['version'] == 1
                and data['lease'] == lease and data['profile'] == PROFILE
                and type(data['image']) is str and IMAGE.fullmatch(data['image'])
                and type(data['commandSha256']) is str and re.fullmatch('[a-f0-9]{64}', data['commandSha256'])
                and type(data['daemon']) is str and 1 <= len(data['daemon']) <= 128
                and type(data['guardianPid']) is int and data['guardianPid'] > 0
                and type(data['seconds']) is int and 2 <= data['seconds'] <= 3600,
                'container_state_invalid')
            Docker(data['docker'], data['endpoint'])
            return fd, data
        except BaseException:
            os.close(fd); raise

    def reserve(self, data):
        with self.locked():
            names = self.names()
            check(len(names) < MAX_LEASES, 'container_state_limit')
            # Do not silently retry past an unresolved earlier operation.
            for lease in names:
                fd, _ = self.load(lease)
                try:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        continue
                    raise ContainerError('container_recovery_required')
                finally:
                    os.close(fd)
            fd = self.open(data['lease'] + '.json', create=True)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                raw = encode(data)
                check(len(raw) <= 16384, 'container_state_limit')
                with os.fdopen(os.dup(fd), 'wb') as stream:
                    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                os.fsync(self.fd)
                return fd
            except BaseException:
                os.close(fd); raise

    def mark(self, lease, phase):
        fd = self.open(lease + '.' + phase, create=True)
        try:
            os.write(fd, b'1\n'); os.fsync(fd); os.fsync(self.fd)
        finally:
            os.close(fd)

    def marked(self, lease, phase):
        try:
            fd = self.open(lease + '.' + phase)
        except FileNotFoundError:
            return False
        try:
            check(os.read(fd, 3) == b'1\n', 'container_state_invalid')
            return True
        finally:
            os.close(fd)

    def discard(self, lease):
        with self.locked():
            for suffix in ['created', 'attempted', 'json']:
                try:
                    os.unlink(lease + '.' + suffix, dir_fd=self.fd)
                except FileNotFoundError:
                    pass
            os.fsync(self.fd)


def cleanup(store, data, docker):
    check(docker.identity() == data['daemon'], 'container_daemon_changed')
    name = 'ink-guard-' + data['lease']
    cid = docker.find(name)
    if cid is not None:
        record = docker.inspect(cid)
        check(record['Name'] == '/' + name and record['Image'] == data['image']
            and record['Config']['Labels'].get(LABEL) == data['lease']
            and record['Config']['Labels'].get('ink.guard.profile') == PROFILE, 'container_identity_changed')
        docker.call('container', 'rm', '--force', cid)
        check(docker.find(name) is None, 'container_cleanup_unconfirmed')
    else:
        # A timed-out creation can complete after an absence query. Keep its
        # lease until the object is observed and removed; never claim success.
        check(not store.marked(data['lease'], 'attempted') or store.marked(data['lease'], 'created'),
            'container_creation_unconfirmed')
    store.discard(data['lease'])


def owner_closed(fd):
    if not select.select([fd], [], [], 0)[0]:
        return False
    return os.read(fd, 1) == b''


def supervise(args):
    validate(args.image, args.command, args.seconds)
    store, lease_fd, child = None, None, None
    data = None
    result = 2
    closing = [False]
    old = {sig: signal.signal(sig, lambda *_: closing.__setitem__(0, True))
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        store = Store(args.state_dir)
        docker = Docker.from_context(args.docker, args.context)
        check(docker.identity() == args.daemon_id, 'container_daemon_changed')
        image = docker.json('image', 'inspect', args.image)[0]
        check(image['Id'] == args.image and image['Os'] == 'linux' and not image['Config'].get('Volumes'),
            'container_image_unsupported')
        if closing[0] or owner_closed(args.owner_fd):
            return 130
        data = {'version':1, 'lease':uuid.uuid4().hex, 'profile':PROFILE, 'docker':args.docker,
            'endpoint':docker.endpoint, 'daemon':docker.identity(), 'image':args.image,
            'seconds':args.seconds, 'commandSha256':hashlib.sha256(encode(args.command)).hexdigest(),
            'guardianPid':os.getpid()}
        lease_fd = store.reserve(data)
        if closing[0] or owner_closed(args.owner_fd):
            return 130
        store.mark(data['lease'], 'attempted')
        cid = docker.call(*create_args(args.image, data['lease'], args.command, args.seconds)).decode().strip()
        check(bool(re.fullmatch('[a-f0-9]{64}', cid)), 'container_identity_invalid')
        store.mark(data['lease'], 'created')
        validate_effective(docker.inspect(cid), args.image, data['lease'], args.command, args.seconds, image['Config']['Env'])
        if closing[0] or owner_closed(args.owner_fd):
            return 130
        child = subprocess.Popen([*docker.prefix, 'start', '--attach', '--interactive', cid],
            stdin=sys.stdin.buffer, stdout=sys.stdout.buffer, stderr=subprocess.DEVNULL, close_fds=True,
            env=Docker.environment())
        end = time.monotonic() + args.seconds + 10
        while child.poll() is None:
            if closing[0] or owner_closed(args.owner_fd) or time.monotonic() >= end:
                break
            time.sleep(.05)
        result = child.poll() if child.poll() is not None else 130
        if result == 124:
            print('container_deadline_expired', file=sys.stderr)
        elif result == 125:
            print('container_runtime_refused', file=sys.stderr)
        elif result not in (0, 130):
            print('container_server_failed', file=sys.stderr)
    except (ContainerError, OSError, ValueError, TypeError, KeyError, IndexError) as error:
        print(error.code if isinstance(error, ContainerError) else 'container_runtime_failed', file=sys.stderr)
        result = 2
    finally:
        # Release a blocked attach stream before asking the daemon to remove
        # the container. Stopping this CLI alone is never our cleanup proof.
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.wait()
        try:
            if lease_fd is not None:
                cleanup(store, data, docker)
        except (ContainerError, OSError, ValueError, TypeError, KeyError, IndexError):
            print('container_cleanup_unconfirmed: run container-recover before starting another container.', file=sys.stderr)
            result = 2
        if lease_fd is not None:
            os.close(lease_fd)
        if store is not None:
            store.close()
        os.close(args.owner_fd)
        for sig, handler in old.items():
            signal.signal(sig, handler)
    return result


def run(args):
    validate(args.image, args.command, args.seconds)
    # Close the liveness pipe on EOF/cancel/exit. A separate process session
    # survives the gateway's process-group kill and removes the owned container.
    owner_read, owner_write = os.pipe()
    child = None
    timed_out = False
    closing = [False]
    old = {sig: signal.signal(sig, lambda *_: closing.__setitem__(0, True))
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        child = subprocess.Popen([sys.executable, '-m', 'llms_ink.guard_container',
            '--supervise', '--owner-fd', str(owner_read), '--state-dir', args.state_dir,
            '--docker', args.docker, '--context', args.context, '--daemon-id', args.daemon_id,
            '--profile', args.profile, '--image', args.image,
            '--seconds', str(args.seconds), '--', *args.command], stdin=subprocess.PIPE,
            stdout=sys.stdout.buffer, stderr=sys.stderr.buffer, pass_fds=(owner_read,), start_new_session=True)
        os.close(owner_read); owner_read = None
        os.set_blocking(child.stdin.fileno(), False)
        pending = bytearray()
        while child.poll() is None and not closing[0]:
            readers = [sys.stdin.fileno()] if len(pending) < 65536 else []
            writers = [child.stdin.fileno()] if pending else []
            readable, writable, _ = select.select(readers, writers, [], .05)
            if readable:
                raw = os.read(sys.stdin.fileno(), 65536 - len(pending))
                if not raw:
                    break
                pending.extend(raw)
            if writable:
                try:
                    del pending[:os.write(child.stdin.fileno(), pending)]
                except BlockingIOError:
                    pass
                except BrokenPipeError:
                    break
    finally:
        if owner_read is not None:
            os.close(owner_read)
        os.close(owner_write)
        if child is not None:
            try:
                child.stdin.close()
            except OSError:
                pass
            try:
                child.wait(timeout=35)
            except subprocess.TimeoutExpired:
                # Preserve the independent guardian rather than killing the
                # only cleanup worker. Its own daemon calls/deadline are bounded.
                print('container_cleanup_unconfirmed: run container-recover before starting another container.', file=sys.stderr)
                timed_out = True
        for sig, handler in old.items():
            signal.signal(sig, handler)
    return child.returncode if not timed_out and child is not None and child.returncode is not None else 2


def recover(directory):
    store = Store(directory)
    report = {'removed': [], 'active': [], 'unconfirmed': []}
    try:
        # Leases stay locked during cleanup, so another recovery cannot remove
        # or adopt them. New runs see active leases or an unresolved record.
        with store.locked():
            names = store.names()
        for lease in names:
            try:
                fd, data = store.load(lease)
            except FileNotFoundError:
                continue
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    report['active'].append(lease); continue
                try:
                    cleanup(store, data, Docker(data['docker'], data['endpoint']))
                    report['removed'].append(lease)
                except (ContainerError, OSError, ValueError, TypeError, KeyError, IndexError) as error:
                    report['unconfirmed'].append({'lease': lease,
                        'code': error.code if isinstance(error, ContainerError) else 'container_cleanup_unconfirmed'})
            finally:
                os.close(fd)
        return report
    finally:
        store.close()


def add_options(parser):
    parser.add_argument('--state-dir', required=True, help='Existing mode-0700 owner directory for runtime leases.')
    parser.add_argument('--docker', required=True, help='Absolute path to the reviewed Docker CLI.')
    parser.add_argument('--context', required=True, help='Local Docker context; TCP/SSH endpoints are refused.')
    parser.add_argument('--daemon-id', required=True, help='Reviewed Docker daemon ID. A changed daemon is refused.')
    parser.add_argument('--profile', required=True, choices=[PROFILE], help='Explicit reviewed execution profile version.')
    parser.add_argument('--image', required=True, help='Reviewed local sha256 image ID. Never pulled.')
    parser.add_argument('--seconds', required=True, type=int, help='Fixed maximum process lifetime, 2–3600 seconds.')
    parser.add_argument('command', nargs=argparse.REMAINDER, help='-- /absolute/in-container/executable arguments')


def normalize(args):
    if args.command[:1] == ['--']:
        args.command = args.command[1:]
    return args


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--supervise', action='store_true', required=True)
    parser.add_argument('--owner-fd', type=int, required=True)
    add_options(parser)
    args = normalize(parser.parse_args())
    return supervise(args)


if __name__ == '__main__':
    raise SystemExit(main())
