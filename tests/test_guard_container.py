"""Offline runtime ownership, crash recovery, and real guarded MCP traffic."""
import copy
import fcntl
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import time
import uuid

import pytest
from llms_ink import guard_container as runtime

IMAGE = 'sha256:' + 'a' * 64
LIVE_IMAGE = os.environ.get('LLMS_INK_CONTAINER_IMAGE', '')
DOCKER = shutil.which('docker')
CONTEXT = os.environ.get('LLMS_INK_CONTAINER_CONTEXT', 'default')
live = pytest.mark.skipif(os.environ.get('LLMS_INK_GUARD_CONTAINER_TEST') != '1', reason='opt-in local Docker lifecycle test')


def record():
    return {'version':1, 'lease':uuid.uuid4().hex, 'profile':runtime.PROFILE,
        'docker':'/usr/bin/docker', 'endpoint':'unix:///test.sock', 'daemon':'test-daemon',
        'image':IMAGE, 'seconds':10, 'commandSha256':'b' * 64, 'guardianPid':os.getpid()}


@pytest.fixture
def store(tmp_path):
    directory = tmp_path/'state'; directory.mkdir(mode=0o700)
    instance = runtime.Store(directory)
    try:
        yield instance
    finally:
        instance.close()


@pytest.mark.parametrize('image,command,seconds', [
    ('python:latest', ['/python'], 2), ('--privileged', ['/python'], 2),
    (IMAGE, ['relative'], 2), (IMAGE, ['/python', 'x' * 8193], 2),
    (IMAGE, ['/python', '\0'], 2), (IMAGE, ['/python'] * 129, 2),
    (IMAGE, ['/python'], True), (IMAGE, ['/python'], 0), (IMAGE, ['/python'], 3601),
])
def test_invalid_execution_input_refused(image, command, seconds):
    with pytest.raises(runtime.ContainerError): runtime.validate(image, command, seconds)


def test_server_arguments_cannot_add_docker_options():
    args = runtime.create_args(IMAGE, 'a' * 32, ['/python', '--network', 'host'], 2)
    assert args[-4:] == ['2', '/python', '--network', 'host']
    assert args[args.index('--network') + 1] == 'none'
    assert '--init' not in args and '--volume' not in args and '--env' not in args
    assert args[args.index('--pull') + 1] == 'never'


@pytest.mark.parametrize('endpoint', ['tcp://host:2375', 'ssh://host', 'unix://relative', '', 'unix:///x\0'])
def test_remote_daemon_refused(endpoint):
    with pytest.raises(runtime.ContainerError): runtime.Docker('/docker', endpoint)


def test_cli_config_is_empty_and_environment_overrides_are_removed(monkeypatch):
    monkeypatch.setenv('DOCKER_CONTEXT', 'remote'); monkeypatch.setenv('DOCKER_HOST', 'tcp://host:2375')
    assert 'DOCKER_CONTEXT' not in runtime.Docker.environment() and 'DOCKER_HOST' not in runtime.Docker.environment()
    def invoke(command):
        config = Path(command[command.index('--config') + 1])
        assert config.is_dir() and list(config.iterdir()) == [] and config.stat().st_mode & 0o777 == 0o700
        return b'ok'
    monkeypatch.setattr(runtime.Docker, 'invoke', staticmethod(invoke))
    assert runtime.Docker('/docker', 'unix:///test.sock').call('create') == b'ok'


def test_unresolved_lease_blocks_new_execution_and_active_lease_does_not(store):
    first = record(); fd = store.reserve(first)
    second = record(); other = store.reserve(second)
    os.close(other)
    with pytest.raises(runtime.ContainerError, match='container_recovery_required'): store.reserve(record())
    store.discard(second['lease']); os.close(fd)
    with pytest.raises(runtime.ContainerError, match='container_recovery_required'): store.reserve(record())


@pytest.mark.parametrize('kind', ['public', 'symlink', 'hardlink', 'duplicate_json', 'orphan_phase'])
def test_state_tampering_is_refused(store, tmp_path, kind):
    data = record(); fd = store.reserve(data); os.close(fd)
    file = store.path/(data['lease'] + '.json')
    if kind == 'public': file.chmod(0o644)
    elif kind == 'symlink': file.unlink(); file.symlink_to(tmp_path/'elsewhere')
    elif kind == 'hardlink': os.link(file, tmp_path/'linked')
    elif kind == 'duplicate_json': file.write_text('{"version":1,"version":1}')
    else: file.unlink(); store.mark(data['lease'], 'attempted')
    with pytest.raises((runtime.ContainerError, OSError, ValueError)):
        store.reserve(record())


class FakeDocker:
    def __init__(self, data, *, exists=True, daemon='test-daemon', foreign=False, remains=False, unavailable=False):
        self.data, self.exists, self.daemon = data, exists, daemon
        self.foreign, self.remains, self.unavailable = foreign, remains, unavailable
        self.removed = False
    def identity(self):
        if self.unavailable: raise runtime.ContainerError('container_daemon_failed')
        return self.daemon
    def find(self, name): return 'c' * 64 if self.exists else None
    def inspect(self, cid):
        return {'Name':'/ink-guard-' + self.data['lease'], 'Image':IMAGE,
            'Config':{'Labels':{runtime.LABEL:'foreign' if self.foreign else self.data['lease'],
                'ink.guard.profile':runtime.PROFILE}}}
    def call(self, *args):
        assert args == ('container', 'rm', '--force', 'c' * 64)
        self.removed = True; self.exists = self.remains


@pytest.mark.parametrize('failure', ['daemon_changed', 'foreign', 'remains', 'unavailable', 'ambiguous_creation'])
def test_cleanup_failure_keeps_ownership_and_never_claims_absence(store, failure):
    data = record(); fd = store.reserve(data); store.mark(data['lease'], 'attempted')
    docker = FakeDocker(data, daemon='changed' if failure == 'daemon_changed' else 'test-daemon',
        foreign=failure == 'foreign', remains=failure == 'remains', unavailable=failure == 'unavailable',
        exists=failure != 'ambiguous_creation')
    try:
        with pytest.raises(runtime.ContainerError): runtime.cleanup(store, data, docker)
        assert data['lease'] in store.names()
        assert docker.removed == (failure == 'remains')
    finally: os.close(fd)


@pytest.mark.parametrize('exists,attempted,created', [(True, True, False), (False, False, False), (False, True, True)])
def test_confirmed_cleanup_clears_only_owned_lease(store, exists, attempted, created):
    data = record(); fd = store.reserve(data)
    if attempted: store.mark(data['lease'], 'attempted')
    if created: store.mark(data['lease'], 'created')
    try:
        docker = FakeDocker(data, exists=exists); runtime.cleanup(store, data, docker)
        assert store.names() == [] and docker.removed == exists
    finally: os.close(fd)


def wait_for(predicate, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = predicate()
        if result: return result
        time.sleep(.05)
    raise AssertionError('Timed out waiting for the observed lifecycle transition')


def line(process, timeout=15):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        assert selector.select(timeout), 'No fixture output'
    value = process.stdout.readline()
    assert value, process.stderr.read().decode()
    return value


STUBBORN = """import os,signal,time,json
signal.signal(signal.SIGTERM,signal.SIG_IGN)
print('READY',flush=True)
while True: time.sleep(.05)
"""


def command(state, code=STUBBORN, seconds=15, docker=None):
    assert DOCKER and runtime.IMAGE.fullmatch(LIVE_IMAGE), 'Set the pinned local image and Docker path'
    return [sys.executable, '-m', 'llms_ink.guard', 'container-run', '--state-dir', str(state),
        '--docker', docker or DOCKER, '--context', CONTEXT, '--image', LIVE_IMAGE, '--seconds', str(seconds),
        '--profile', runtime.PROFILE, '--daemon-id', runtime.Docker.from_context(DOCKER, CONTEXT).identity(),
        '--', '/usr/local/bin/python3', '-u', '-c', code]


def start(state, **options):
    return subprocess.Popen(command(state, **options), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True)


def lease(state):
    files = list(state.glob('*.json'))
    assert len(files) == 1, files
    return json.loads(files[0].read_text())


def cli(data):
    return runtime.Docker(data['docker'], data['endpoint'])


def ensure_stopped(process, state):
    if process.poll() is None:
        process.terminate()
        try: process.wait(timeout=35)
        except subprocess.TimeoutExpired: process.kill(); process.wait()
    for stream in [process.stdin, process.stdout, process.stderr]: stream.close()
    # Normal tests must clean without recovery. Teardown is only an emergency
    # cleanup path when an assertion failed, and cannot make the test pass.
    if list(state.glob('*.json')):
        for file in state.glob('*.json'):
            data = json.loads(file.read_text())
            try: os.kill(data['guardianPid'], signal.SIGTERM)
            except ProcessLookupError: pass
        time.sleep(.3)
        report = runtime.recover(state)
        assert not report['unconfirmed'], report


@pytest.fixture
def state(tmp_path):
    directory = tmp_path/'runtime'; directory.mkdir(mode=0o700)
    return directory


@live
@pytest.mark.parametrize('ending', ['eof', 'term_group', 'kill_group'])
def test_client_loss_removes_actual_container(state, ending):
    process = start(state)
    try:
        assert line(process) == b'READY\n'; data = lease(state); docker = cli(data)
        cid = docker.find('ink-guard-' + data['lease']); assert cid and docker.inspect(cid)['State']['Running']
        if ending == 'eof': process.stdin.close()
        elif ending == 'term_group': os.killpg(process.pid, signal.SIGTERM)
        else: os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=20)
        wait_for(lambda: not list(state.glob('*.json')))
        assert docker.find('ink-guard-' + data['lease']) is None
    finally: ensure_stopped(process, state)


@live
@pytest.mark.parametrize('recover_early', [False, True])
def test_guardian_crash_has_independent_deadline_and_explicit_recovery(state, recover_early):
    code = STUBBORN.replace("print('READY',flush=True)", "os.kill(1,signal.SIGSTOP)\ntry:\n open('/proc/1/mem','wb')\n raise RuntimeError('parent writable')\nexcept PermissionError: pass\nprint('READY',flush=True)")
    code = code.replace("print('READY',flush=True)", "import subprocess,sys\nsubprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],start_new_session=True)\nprint('READY',flush=True)")
    process = start(state, code=code, seconds=4)
    try:
        assert line(process) == b'READY\n'; data = lease(state); docker = cli(data)
        cid = docker.find('ink-guard-' + data['lease'])
        os.killpg(data['guardianPid'], signal.SIGKILL); process.wait(timeout=10)
        assert list(state.glob('*.json'))
        retry = start(state, seconds=4)
        try:
            assert retry.wait(timeout=10) != 0
            assert b'container_recovery_required' in retry.stderr.read()
        finally:
            for stream in [retry.stdin, retry.stdout, retry.stderr]: stream.close()
        if not recover_early:
            wait_for(lambda: not docker.inspect(cid)['State']['Running'], timeout=8)
            assert docker.inspect(cid)['State']['ExitCode'] == 124
        report = runtime.recover(state)
        assert report == {'removed':[data['lease']], 'active':[], 'unconfirmed':[]}
        assert docker.find('ink-guard-' + data['lease']) is None
    finally: ensure_stopped(process, state)


@live
def test_concurrent_owners_and_recovery_do_not_remove_active_sessions(state):
    first = start(state); second = None
    try:
        assert line(first) == b'READY\n'; second = start(state); assert line(second) == b'READY\n'
        report = runtime.recover(state)
        assert len(report['active']) == 2 and not report['removed'] and not report['unconfirmed']
        first.stdin.close(); first.wait(timeout=20)
        wait_for(lambda: len(list(state.glob('*.json'))) == 1)
        data = lease(state); assert cli(data).inspect(cli(data).find('ink-guard-' + data['lease']))['State']['Running']
        second.stdin.close(); second.wait(timeout=20)
        wait_for(lambda: not list(state.glob('*.json')))
    finally:
        ensure_stopped(first, state)
        if second is not None: ensure_stopped(second, state)


@live
def test_backpressured_output_does_not_prevent_owned_cleanup(state):
    process = start(state, code="import os; print('READY',flush=True)\nwhile True: os.write(1,b'x'*8192)")
    try:
        assert line(process) == b'READY\n'; data = lease(state)
        time.sleep(.2); os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=10)
        wait_for(lambda: not list(state.glob('*.json')))
        assert cli(data).find('ink-guard-' + data['lease']) is None
    finally: ensure_stopped(process, state)


SERVER = '''import json,sys
from pathlib import Path
tool={'name':'act','description':'Record one synthetic event.','inputSchema':{'type':'object','properties':{'destination':{'type':'string'}},'required':['destination'],'additionalProperties':False}}
for raw in sys.stdin:
 m=json.loads(raw)
 if 'id' not in m: continue
 method=m.get('method');params=m.get('params',{})
 if method=='initialize': body={'protocolVersion':params['protocolVersion'],'capabilities':{'tools':{}},'serverInfo':{'name':'fixture','version':'1'}}
 elif method=='tools/list': body={'tools':[tool]}
 elif method=='tools/call':
  with open('/tmp/effects','a') as f:f.write(json.dumps(params)+'\\n')
  body={'content':[{'type':'text','text':'Recorded one synthetic event.'}]}
 else: body={}
 print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':body}),flush=True)
'''
TOOL = {'name':'act','description':'Record one synthetic event.','inputSchema':{'type':'object','properties':{'destination':{'type':'string'}},'required':['destination'],'additionalProperties':False}}


@live
@pytest.mark.parametrize('real_model', [False, pytest.param(True, marks=pytest.mark.skipif(os.environ.get('LLMS_INK_GUARD_MODEL_TEST') != '1', reason='opt-in local model'))])
def test_guarded_mcp_approval_denial_and_cleanup(state, tmp_path, real_model):
    from llms_ink.guard import LocalGuard
    from .test_guard_gateway import connect, ready, call, answer_form
    config = tmp_path/'gateway.json'; config.write_text(json.dumps({'version':1,'servers':{'docs':{
        'command':command(state, code=SERVER, seconds=60), 'tools':[{'definition':TOOL,'arguments':[{'destination':'safe'}]}]}}})); config.chmod(0o600)
    model = LocalGuard() if real_model else None
    connection = connect(config)
    if model is not None: connection.proxy.guard = model
    try:
        assert 'result' in ready(connection)
        data = lease(state); docker = cli(data); cid = docker.find('ink-guard-' + data['lease'])
        def effects():
            return json.loads(docker.call('exec', cid, '/usr/local/bin/python3', '-c',
                "import json; from pathlib import Path; p=Path('/tmp/effects'); print(json.dumps(p.read_text().splitlines() if p.exists() else []))"))
        call(connection, arguments={'destination':'not-reviewed'}); assert 'error' in connection.answer(); assert effects() == []
        call(connection); form = connection.answer(); assert form['method'] == 'elicitation/create'; assert effects() == []
        answer_form(connection, form); assert 'result' in connection.answer(); assert len(effects()) == 1
    finally:
        connection.close()
        if model is not None: model.close()
    wait_for(lambda: not list(state.glob('*.json')))
    assert docker.find('ink-guard-' + data['lease']) is None


@live
def test_discovery_process_group_cleanup_includes_container(state):
    from llms_ink.guard_onboarding import discover
    assert discover(command(state, code=SERVER, seconds=15)) == [TOOL]
    wait_for(lambda: not list(state.glob('*.json')))


def shim(tmp_path, mode):
    marker = tmp_path/'daemon-unavailable'
    file = tmp_path/'docker-shim'
    # Delegates to the real local daemon. Failure injection changes only this
    # owned client; it does not stop/reconfigure Docker or touch other users.
    source = f'''#!{sys.executable}
import subprocess,sys
from pathlib import Path
args=sys.argv[1:]
if Path({str(marker)!r}).exists():
 print('SYNTHETIC_PRIVATE_DAEMON_MESSAGE',file=sys.stderr);raise SystemExit(23)
result=subprocess.run([{DOCKER!r},*args])
if {mode!r}=='lost-create-reply' and 'create' in args: raise SystemExit(24)
raise SystemExit(result.returncode)
'''
    file.write_text(source); file.chmod(0o700)
    return str(file), marker


@live
def test_daemon_unavailable_retains_lease_until_explicit_recovery(state, tmp_path):
    executable, marker = shim(tmp_path, 'availability')
    process = start(state, docker=executable, seconds=5)
    try:
        assert line(process) == b'READY\n'; data = lease(state)
        marker.write_text('synthetic failure')
        process.stdin.close(); assert process.wait(timeout=20) != 0
        error = process.stderr.read()
        assert b'container_cleanup_unconfirmed' in error and b'SYNTHETIC_PRIVATE_DAEMON_MESSAGE' not in error
        assert list(state.glob('*.json'))
        report = runtime.recover(state); assert report['unconfirmed'] and not report['removed']
        marker.unlink()
        report = runtime.recover(state)
        assert report == {'removed':[data['lease']], 'active':[], 'unconfirmed':[]}
        assert cli(data).find('ink-guard-' + data['lease']) is None
    finally:
        marker.unlink(missing_ok=True); ensure_stopped(process, state)


@live
def test_created_container_is_recovered_when_cli_reply_is_lost(state, tmp_path):
    executable, _ = shim(tmp_path, 'lost-create-reply')
    process = start(state, docker=executable)
    try:
        assert process.wait(timeout=20) != 0
        assert b'container_daemon_failed' in process.stderr.read()
        assert list(state.glob('*.json')) == []
        # No upstream code was started; a committed create with a lost reply
        # was found by its pre-recorded name and removed by verified identity.
        assert process.stdout.read() == b''
    finally: ensure_stopped(process, state)


@live
def test_stale_daemon_binding_starts_no_container(state):
    args = command(state)
    args[args.index('--daemon-id') + 1] = 'not-the-reviewed-daemon'
    process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert process.wait(timeout=15) != 0
        assert b'container_daemon_changed' in process.stderr.read()
        assert list(state.glob('*.json')) == [] and process.stdout.read() == b''
    finally: ensure_stopped(process, state)


@live
def test_proxy_credentials_from_cli_config_are_not_forwarded(state, tmp_path, monkeypatch):
    docker = runtime.Docker.from_context(DOCKER, CONTEXT)
    image = docker.json('image','inspect',LIVE_IMAGE)[0]
    config = tmp_path/'client-config'; config.mkdir(mode=0o700)
    (config/'config.json').write_text(json.dumps({'proxies':{'default':{'httpProxy':'http://synthetic-secret.invalid:9999'}}}))
    monkeypatch.setenv('DOCKER_CONFIG', str(config))
    lease_id = uuid.uuid4().hex
    cid = docker.call(*runtime.create_args(LIVE_IMAGE, lease_id, ['/usr/local/bin/python3','-c','print(1)'], 2)).decode().strip()
    try:
        created = docker.inspect(cid)
        runtime.validate_effective(created, LIVE_IMAGE, lease_id, ['/usr/local/bin/python3','-c','print(1)'], 2, image['Config']['Env'])
        assert not any('synthetic-secret' in value for value in created['Config']['Env'])
    finally: docker.call('container','rm','--force',cid)


@live
@pytest.mark.parametrize('ending', ['revoke', 'expire', 'container_expire'])
def test_authenticated_session_end_removes_container(state, tmp_path, ending):
    import tempfile
    import threading
    from llms_ink.guard_service import Service, initialize, control, attach
    from .test_guard_service import Model, Wire, issue
    config = tmp_path/'service-gateway.json'
    config.write_text(json.dumps({'version':1,'servers':{'docs':{
        'command':command(state, code=SERVER, seconds=2 if ending == 'container_expire' else 30),
        'tools':[{'definition':TOOL,'arguments':[{'destination':'safe'}]}]}}})); config.chmod(0o600)
    with tempfile.TemporaryDirectory(prefix='ink-svc-') as directory:
        initialize(directory); owner = Path(directory)/'owner.json'
        service = Service(owner, str(config), Model())
        results = []; thread = threading.Thread(target=lambda: results.append(service.run())); thread.start()
        assert service.ready.wait(3)
        try:
            credential, sid = issue(owner, ttl=5 if ending == 'expire' else 30)
            with Wire(credential) as wire:
                wire.sock.settimeout(8)
                wire.request('initialize',{'protocolVersion':'2025-11-25','capabilities':{'elicitation':{'form':{}}}})
                assert 'result' in wire.response()
                wire.raw({'jsonrpc':'2.0','method':'notifications/initialized'})
                wire.request('tools/list'); assert len(wire.response()['result']['tools']) == 1
                data = lease(state); docker = cli(data)
                assert wire.call('docs__act')['method'] == 'elicitation/create'
                if ending == 'revoke': assert control(owner,'revoke',sessionId=sid)['ok']
                if ending == 'container_expire':
                    failed = wire.response()
                    assert failed['id'] == wire.serial and 'error' in failed and 'result' not in failed
                assert wire.stream.readline() == b''
                with pytest.raises(RuntimeError): attach(credential)
            wait_for(lambda: not list(state.glob('*.json')))
            assert docker.find('ink-guard-' + data['lease']) is None
        finally:
            service.stop.set(); thread.join(timeout=8)
            assert not thread.is_alive() and results == [0]


@live
def test_runtime_access_checks_apply_to_the_actual_server(state, tmp_path, monkeypatch):
    sentinel = tmp_path/'owner-only'; sentinel.write_text('synthetic'); sentinel.chmod(0o600)
    monkeypatch.setenv('INK_RUNTIME_SYNTHETIC_SECRET','owner value')
    code = '''import errno,json,os,socket
from pathlib import Path
checks={'uid':os.getuid()==65532,'gid':os.getgid()==65532,
 'owner_environment_absent':'INK_RUNTIME_SYNTHETIC_SECRET' not in os.environ,
 'owner_file_absent':not Path(SENTINEL).exists(),'docker_socket_absent':not Path('/var/run/docker.sock').exists()}
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
checks['no_capabilities']=all(int(status[key].strip(),16)==0 for key in ['CapEff','CapPrm','CapBnd','CapAmb'])
checks['no_new_privileges']=status['NoNewPrivs'].strip()=='1';checks['seccomp']=status['Seccomp'].strip()=='2'
checks['no_non_loopback_link_up']=all(name=='lo' or not int(Path('/sys/class/net',name,'flags').read_text(),16)&1 for _,name in socket.if_nameindex())
checks['no_ipv4_route']=not Path('/proc/net/route').read_text().splitlines()[1:]
try: Path('/var/tmp/ink-write').write_text('synthetic');checks['read_only_root']=False
except OSError as error: checks['read_only_root']=error.errno==errno.EROFS
try: os.setuid(0);checks['no_root']=False
except PermissionError: checks['no_root']=True
print(json.dumps(checks),flush=True)
'''.replace('SENTINEL', repr(str(sentinel)))
    process = start(state, code=code)
    try:
        checks = json.loads(line(process)); assert all(checks.values()), checks
        assert process.wait(timeout=15) == 0
        assert not list(state.glob('*.json'))
    finally: ensure_stopped(process, state)


@live
def test_image_declared_volume_is_refused_before_server_execution(state):
    docker = runtime.Docker.from_context(DOCKER, CONTEXT)
    cid = docker.call(*runtime.create_args(LIVE_IMAGE, uuid.uuid4().hex,
        ['/usr/local/bin/python3','-c','print("MUST_NOT_RUN")'], 2)).decode().strip()
    derived = None; process = None
    try:
        derived = docker.call('commit','--change','VOLUME /data',cid).decode().strip()
        assert runtime.IMAGE.fullmatch(derived) and derived != LIVE_IMAGE
        args = command(state); args[args.index('--image') + 1] = derived
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert process.wait(timeout=15) != 0
        assert b'container_image_unsupported' in process.stderr.read()
        assert process.stdout.read() == b'' and not list(state.glob('*.json'))
    finally:
        if process is not None: ensure_stopped(process, state)
        docker.call('container','rm','--force',cid)
        if derived is not None: docker.call('image','rm',derived)
