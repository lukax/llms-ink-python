"""Authenticated local sessions: real sockets, MCP streams and effect journals."""
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time

import pytest

from llms_ink.guard_service import Service, initialize, create_session, control, attach, read_credential, open_socket, frame, send, SharedGuard
from llms_ink.guard_session import SessionScope
from llms_ink.guard_transport import BoundedWriter
from llms_ink.guard_proxy import Proxy
from .test_guard import FakeGuard
from .test_guard_gateway import config_file, effects, ARGS
from .test_guard_approval import accept
from .test_guard_modern import META, continuation

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Private local IPC requires POSIX')


class Model(FakeGuard):
    def close(self):
        self.release.set()


@contextmanager
def service(tmp_path, modes=None, model=None):
    path,_=config_file(tmp_path,modes)
    script=tmp_path/'server.py'
    script.write_text(script.read_text().replace("Path(journal+'.pid').write_text(str(os.getpid()))", "Path(journal+'.pid').write_text(str(os.getpid()))\nwith open(journal+'.pids','a') as f:f.write(str(os.getpid())+'\\n')"))
    with tempfile.TemporaryDirectory(prefix='ink-svc-') as directory:
        initialize(directory); owner=Path(directory)/'owner.json'; logs=[]
        instance=Service(owner,str(path),model or Model(),log=logs.append)
        result=[]
        def run():
            try: result.append(instance.run())
            except BaseException as exc: result.append(exc)
        thread=threading.Thread(target=run);thread.start()
        assert instance.ready.wait(3),result
        try:yield instance,owner,logs
        finally:
            instance.stop.set();thread.join(timeout=8);assert not thread.is_alive(),result
            assert result==[0],result
            for pidfile in tmp_path.glob('*.pids'):
                for pid in pidfile.read_text().splitlines():
                    with pytest.raises(ProcessLookupError):os.kill(int(pid),0)
            assert not (Path(directory)/'service.sock').exists()


def issue(owner,name='a',protocol='legacy',ttl=60):
    output=owner.parent/(name+'.json')
    info=create_session(owner,output,protocol,ttl)
    return output,info['sessionId']


class Wire:
    def __init__(self,path):
        self.protocol=read_credential(path)['protocol'];self.sock,self.stream=attach(path)
        self.sock.settimeout(4);self.serial=0
    def raw(self,message):send(self.sock,message)
    def request(self,method,params=None):
        self.serial+=1
        if self.protocol!='legacy':params={'_meta':META,**(params or {})}
        self.raw({'jsonrpc':'2.0','id':self.serial,'method':method,'params':params or {}})
        return self.serial
    def response(self):return frame(self.stream)
    def ready(self):
        if self.protocol=='legacy':
            self.request('initialize',{'protocolVersion':'2025-11-25','capabilities':{'elicitation':{'form':{}}}})
            assert 'result' in self.response()
            self.raw({'jsonrpc':'2.0','method':'notifications/initialized'})
        self.request('tools/list');assert len(self.response()['result']['tools'])==2
    def call(self,name='mail__act',arguments=ARGS):
        self.request('tools/call',{'name':name,'arguments':arguments});return self.response()
    def approve(self,prompt,name='mail__act'):
        if self.protocol=='legacy':self.raw(accept(prompt))
        else:self.request('tools/call',continuation(prompt,name=name))
        return self.response()
    def close(self):
        try:self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        self.stream.close();self.sock.close()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()


@pytest.mark.parametrize('protocol',['legacy','2026-07-28'])
def test_same_session_shares_approval_queue_and_other_sessions_are_independent(tmp_path,protocol):
    with service(tmp_path) as (svc,owner,logs):
        first,sid=issue(owner,protocol=protocol);second,other=issue(owner,'b',protocol=protocol)
        with Wire(first) as a,Wire(first) as b,Wire(second) as c:
            a.ready();b.ready();c.ready();prompt=a.call()
            assert 'error' in b.call('docs__act')
            independent=c.call('docs__act');assert 'result' in c.approve(independent,'docs__act')
            assert len(effects(tmp_path,'docs'))==1 and not effects(tmp_path,'mail')
            status=control(owner,'status')['sessions'];assert next(s for s in status if s['sessionId']==sid)['approvalPending']
            assert 'result' in a.approve(prompt);assert len(effects(tmp_path,'mail'))==1
            fresh=b.call('docs__act');assert 'result' in b.approve(fresh,'docs__act')
            assert len(effects(tmp_path,'docs'))==2
        encoded=json.dumps(logs)
        for path in (owner,first,second):assert read_credential(path)['token'] not in encoded
        assert 'destination' not in encoded and str(tmp_path) not in encoded


def test_owner_and_session_credentials_have_separate_authority(tmp_path):
    with service(tmp_path) as (_,owner,_):
        credential,sid=issue(owner);session=read_credential(credential);master=read_credential(owner)
        requests=[{'op':'status','token':session['token']},
                  {'op':'create','token':session['token'],'protocol':'legacy','ttl':60},
                  {'op':'revoke','token':session['token'],'sessionId':sid},
                  {'op':'attach','token':master['token'],'sessionId':sid},
                  {'op':'attach','token':'0'*64,'sessionId':sid}]
        for request in requests:
            with open_socket(master) as sock,sock.makefile('rb',buffering=0) as stream:
                send(sock,request);assert frame(stream)=={'ok':False,'error':'Guard service rejected the request.'}
        assert not list(tmp_path.glob('*.pids'))
        assert len(control(owner,'status')['sessions'])==1


@pytest.mark.parametrize('protocol',['legacy','2026-07-28'])
def test_revoke_stops_all_connections_and_rejects_reattach(tmp_path,protocol):
    with service(tmp_path) as (svc,owner,_):
        file,sid=issue(owner,protocol=protocol)
        with Wire(file) as a,Wire(file) as b:
            a.ready();b.ready();a.call()
            assert control(owner,'revoke',sessionId=sid)['ok']
            assert a.stream.readline()==b'' and b.stream.readline()==b''
            with pytest.raises(RuntimeError):attach(file)
            assert not effects(tmp_path,'mail')


@pytest.mark.parametrize('protocol',['legacy','2026-07-28'])
def test_cancel_and_disconnect_release_only_their_own_pending_slot(tmp_path,protocol):
    with service(tmp_path) as (_,owner,_):
        file,_=issue(owner,protocol=protocol)
        with Wire(file) as a,Wire(file) as b:
            a.ready();b.ready();prompt=a.call()
            initial=a.serial
            a.raw({'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':initial}})
            if protocol=='legacy':assert a.response()['method']=='notifications/cancelled'
            a.request('ping');assert 'result' in a.response()
            second=b.call();assert 'result' in b.approve(second)
            a.call();a.close()
            deadline=time.monotonic()+3
            while time.monotonic()<deadline and control(owner,'status')['sessions'][0]['approvalPending']:time.sleep(.02)
            final=b.call();assert 'result' in b.approve(final)
            assert len(effects(tmp_path,'mail'))==2


def test_session_expiry_revokes_pending_calls_and_does_not_reset_on_attach(tmp_path):
    with service(tmp_path) as (_,owner,_):
        file,_=issue(owner,ttl=1)
        with Wire(file) as wire:
            wire.ready();wire.call();assert wire.stream.readline()==b''
            with pytest.raises(RuntimeError):attach(file)
            assert not effects(tmp_path,'mail')


def test_upstream_failure_revokes_peer_connection_approval(tmp_path):
    with service(tmp_path,{'docs':'notify'}) as (_,owner,_):
        file,_=issue(owner)
        with Wire(file) as a,Wire(file) as b:
            a.ready();b.ready();b.call();(tmp_path/'docs.control').touch()
            # A failure in either aggregate ends the entire authenticated session.
            deadline=time.monotonic()+4
            while time.monotonic()<deadline:
                states=control(owner,'status')['sessions']
                if not states or not states[0]['active']:break
                time.sleep(.02)
            assert not states or not states[0]['active']
            assert not effects(tmp_path,'mail')
            with pytest.raises(RuntimeError):attach(file)


def test_mcp_cannot_switch_to_owner_control_or_supply_a_new_session(tmp_path):
    with service(tmp_path) as (_,owner,_):
        file,_=issue(owner,protocol='2026-07-28')
        with Wire(file) as wire:
            wire.ready();wire.request('create',{'token':read_credential(owner)['token'],'protocol':'legacy','ttl':60})
            assert 'error' in wire.response()
            wire.request('tools/call',{'name':'mail__act','arguments':ARGS,'sessionId':'arbitrary'})
            assert 'error' in wire.response()
            assert len(control(owner,'status')['sessions'])==1 and not effects(tmp_path,'mail')


@pytest.fixture
def short_directory():
    with tempfile.TemporaryDirectory(prefix='ink-private-') as directory:
        yield Path(directory)


def test_private_files_no_overwrite_no_symlink_and_no_secret_stdout(short_directory,capsys):
    directory=short_directory;initialize(directory)
    owner=directory/'owner.json';original=owner.read_bytes()
    assert owner.stat().st_mode & 0o777==0o600
    with pytest.raises(FileExistsError):initialize(directory)
    assert owner.read_bytes()==original
    link=directory/'linked.json';link.symlink_to(owner)
    with pytest.raises(OSError):read_credential(link)
    owner.chmod(0o644)
    with pytest.raises(ValueError):read_credential(owner)
    owner.chmod(0o600);directory.chmod(0o755)
    with pytest.raises(ValueError):read_credential(owner)
    assert not capsys.readouterr().out


def test_existing_session_destination_is_never_replaced_or_minted(tmp_path):
    with service(tmp_path) as (_,owner,_):
        existing=owner.parent/'existing';existing.write_text('keep')
        with pytest.raises(ValueError):create_session(owner,existing)
        assert existing.read_text()=='keep' and not control(owner,'status')['sessions']


def test_existing_socket_is_not_removed_by_second_server(tmp_path):
    with service(tmp_path) as (_,owner,_):
        another=Service(owner,str(tmp_path/'gateway.json'),Model(),log=lambda _:None)
        with pytest.raises(OSError):another.run()
        assert control(owner,'status')['ok']


def test_changed_config_cannot_start_new_upstreams(tmp_path):
    with service(tmp_path) as (_,owner,_):
        file,_=issue(owner);path=tmp_path/'gateway.json';path.write_text(path.read_text()+' ')
        with Wire(file) as wire:
            wire.request('initialize',{'protocolVersion':'2025-11-25','capabilities':{'elicitation':{}}})
            assert 'error' in wire.response()
        assert not list(tmp_path.glob('*.pids'))


def test_stalled_output_is_bounded():
    read,write=os.pipe()
    with os.fdopen(read,'rb') as incoming,os.fdopen(write,'wb') as output:
        writer=BoundedWriter(output,timeout=.1);started=time.monotonic()
        with pytest.raises(TimeoutError):writer.write(b'x'*1048576)
        assert time.monotonic()-started<1


def test_scope_revocation_precedes_dispatch_and_release_is_owner_specific():
    scope=SessionScope(time.monotonic()+60);a,b=object(),object()
    assert scope.reserve(a);scope.release(b);assert not scope.reserve(b)
    scope.revoke()
    with scope.dispatch(a) as allowed:assert not allowed
    assert not scope.reserve(a)


def test_shared_model_serializes_and_busy_is_unknown_without_calling_model():
    model=Model();shared=SharedGuard(model)
    shared.lock.acquire()
    try:
        result=shared.inspect('SECRET');assert result['outcome']=='unscanned' and result['coverage']=='none'
        assert model.seen==[]
    finally:shared.lock.release()
    shared.close();assert shared.inspect('SECOND')['outcome']=='unscanned'


@pytest.mark.parametrize('message',[{}, {'op':'status','token':[]}, {'op':'attach','sessionId':{},'token':'0'*64}, {'op':'create','protocol':'legacy','ttl':True}])
def test_malformed_control_requests_do_not_spawn_or_leak(tmp_path,message):
    with service(tmp_path) as (_,owner,logs):
        credential=read_credential(owner)
        with open_socket(credential) as sock,sock.makefile('rb',buffering=0) as stream:
            send(sock,message);assert frame(stream)['ok'] is False
        assert not list(tmp_path.glob('*.pids'))
        assert credential['token'] not in json.dumps(logs)


@pytest.mark.skipif(os.environ.get('LLMS_INK_GUARD_MODEL_TEST')!='1',reason='opt-in installed real model')
def test_real_model_cli_sessions_connect_revoke_and_sigterm(tmp_path):
    config,_=config_file(tmp_path)
    cli=[sys.executable,'-m','llms_ink.guard']
    with tempfile.TemporaryDirectory(prefix='ink-cli-') as directory:
        root=Path(directory);owner=root/'owner.json';file=root/'session.json'
        initialized=subprocess.run([*cli,'service-init',directory],capture_output=True,text=True,timeout=5)
        assert initialized.returncode==0 and json.loads(initialized.stdout)=={'initialized':True}
        p=subprocess.Popen([*cli,'service-serve','--owner-file',str(owner),'--config',str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        bridge=None
        try:
            deadline=time.monotonic()+30
            while time.monotonic()<deadline:
                if p.poll() is not None:pytest.fail('Service failed startup: '+p.stderr.read().decode())
                if (root/'service.sock').exists():
                    try:
                        if control(owner,'status')['ok']:break
                    except OSError:pass
                time.sleep(.05)
            else:pytest.fail('Service startup deadline')
            created=subprocess.run([*cli,'session-create','--owner-file',str(owner),'--output',str(file)],capture_output=True,text=True,timeout=5)
            assert created.returncode==0;sid=json.loads(created.stdout)['sessionId']
            grant=read_credential(file);assert grant['token'] not in created.stdout+created.stderr
            bridge=subprocess.Popen([*cli,'connect','--session-file',str(file)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            replies=queue.Queue()
            def reader():
                for raw in bridge.stdout:replies.put(json.loads(raw))
            thread=threading.Thread(target=reader,daemon=True);thread.start()
            def wire(message):bridge.stdin.write(json.dumps(message).encode()+b'\n');bridge.stdin.flush()
            wire({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','capabilities':{'elicitation':{}}}})
            assert 'result' in replies.get(timeout=15)
            wire({'jsonrpc':'2.0','method':'notifications/initialized'})
            wire({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}});assert len(replies.get(timeout=15)['result']['tools'])==2
            wire({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'mail__act','arguments':ARGS}})
            prompt=replies.get(timeout=10);wire(accept(prompt));assert 'result' in replies.get(timeout=15)
            wire({'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'docs__act','arguments':ARGS}});assert replies.get(timeout=10)['method']=='elicitation/create'
            revoked=subprocess.run([*cli,'session-revoke','--owner-file',str(owner),'--session-id',sid],capture_output=True,text=True,timeout=8)
            assert revoked.returncode==0 and json.loads(revoked.stdout)=={'ok':True}
            assert bridge.wait(timeout=5)==0
            second,_=issue(owner,'modern',protocol='2026-07-28')
            with Wire(second) as modern:
                modern.ready();assert modern.call('docs__act')['result']['resultType']=='input_required'
                p.terminate();assert p.wait(timeout=8)==0
                assert not (root/'service.sock').exists()
            assert len(effects(tmp_path,'mail'))==1 and not effects(tmp_path,'docs')
            for name in ('docs','mail'):
                with pytest.raises(ProcessLookupError):os.kill(int((tmp_path/(name+'.jsonl.pid')).read_text()),0)
            stdout,stderr=p.communicate(timeout=2)
            assert stdout==b''
            logs=stderr.decode();assert str(tmp_path) not in logs and 'destination' not in logs
            for credential in (owner,file,second):assert read_credential(credential)['token'] not in logs
        finally:
            if bridge is not None:
                if bridge.poll() is None:bridge.terminate();bridge.wait(timeout=5)
                bridge.stdin.close();thread.join(timeout=2);bridge.stdout.close();bridge.stderr.close()
            if p.poll() is None:p.terminate();p.wait(timeout=8)
            p.stdout.close();p.stderr.close()


@pytest.mark.skipif(os.environ.get('LLMS_INK_GUARD_GO_TEST')!='1',reason='opt-in official SDK and installed model')
def test_official_go_sdk_uses_host_issued_session_credentials(tmp_path):
    from llms_ink.guard import LocalGuard
    with service(tmp_path,model=LocalGuard()) as (_,owner,_):
        file,_=issue(owner,protocol='2026-07-28')
        result=subprocess.run(['go','run','.',sys.executable,str(file),'session'],cwd=Path(__file__).parent/'interop'/'modern-go',capture_output=True,text=True,timeout=180)
        assert result.returncode==0,result.stderr
        assert 'Official MCP Go SDK:' in result.stdout
        assert len(effects(tmp_path,'mail'))==1 and not effects(tmp_path,'docs')


def test_service_restart_does_not_accept_old_session_capabilities(tmp_path):
    config,_=config_file(tmp_path)
    with tempfile.TemporaryDirectory(prefix='ink-restart-') as directory:
        initialize(directory);owner=Path(directory)/'owner.json'
        first=Service(owner,str(config),Model(),log=lambda _:None);thread=threading.Thread(target=first.run);thread.start();assert first.ready.wait(3)
        file,_=issue(owner);first.stop.set();thread.join(timeout=5);assert not thread.is_alive()
        second=Service(owner,str(config),Model(),log=lambda _:None);thread=threading.Thread(target=second.run);thread.start();assert second.ready.wait(3)
        try:
            with pytest.raises(RuntimeError):attach(file)
            assert not control(owner,'status')['sessions'] and not list(tmp_path.glob('*.pids'))
        finally:second.stop.set();thread.join(timeout=5);assert not thread.is_alive()


def test_observed_upstream_disconnect_revokes_scope_before_event_handling(tmp_path):
    config,_=config_file(tmp_path)
    from llms_ink.guard_gateway_config import GatewayConfig
    compiled=GatewayConfig.load(str(config));command=compiled.command(str(config))
    scope=SessionScope(time.monotonic()+60)
    proxy=Proxy(command,Model(),policy=compiled.outer_policy(command),require_approval=True,process_group=True,approval_scope=scope,log=lambda _:None)
    read,write=os.pipe();os.close(write)
    with os.fdopen(read,'rb') as stream:proxy._reader(stream,'server')
    assert not scope.valid()


def test_connection_and_session_caps_are_enforced_without_upstream_start(tmp_path,monkeypatch):
    from llms_ink import guard_service
    monkeypatch.setattr(guard_service,'MAX_SESSIONS',2)
    monkeypatch.setattr(guard_service,'MAX_CONNECTIONS',3)
    monkeypatch.setattr(guard_service,'MAX_SESSION_CONNECTIONS',2)
    with service(tmp_path) as (_,owner,_):
        first,_=issue(owner);second,_=issue(owner,'b')
        with pytest.raises(RuntimeError):issue(owner,'c')
        with Wire(first),Wire(first),Wire(second):
            with pytest.raises(RuntimeError):attach(first)
            with pytest.raises(RuntimeError):attach(second)
            assert sum(s['connections'] for s in control(owner,'status')['sessions'])==3
        assert not list(tmp_path.glob('*.pids'))


def test_slow_authentication_has_a_deadline_and_does_not_block_owner(tmp_path):
    with service(tmp_path) as (_,owner,_):
        credential=read_credential(owner)
        with open_socket(credential) as sock,sock.makefile('rb',buffering=0) as stream:
            sock.sendall(b'{')
            def trickle():
                for _ in range(10):
                    time.sleep(.35)
                    try:sock.sendall(b' ')
                    except OSError:return
            thread=threading.Thread(target=trickle);thread.start();started=time.monotonic()
            try:
                assert control(owner,'status')['ok']
                assert frame(stream)['ok'] is False
                assert time.monotonic()-started<3.8
            finally:thread.join(timeout=4)
        assert not list(tmp_path.glob('*.pids'))


@pytest.mark.parametrize('payload',[b'{"op":"status","op":"create"}\n',b'{"op":"status","token":NaN}\n',b'x'*8193+b'\n'])
def test_ambiguous_and_oversized_control_frames_are_refused(tmp_path,payload):
    with service(tmp_path) as (_,owner,_):
        with open_socket(read_credential(owner)) as sock,sock.makefile('rb',buffering=0) as stream:
            sock.sendall(payload);assert frame(stream)['ok'] is False
        assert not list(tmp_path.glob('*.pids'))


@pytest.mark.parametrize('change',['cancel','expire','revoke'])
def test_stalled_dispatch_rechecks_authority_at_first_byte(tmp_path,change):
    from types import SimpleNamespace
    from llms_ink.guard_gateway_config import GatewayConfig
    from llms_ink.guard_policy import tool_digest
    path,_=config_file(tmp_path);config=GatewayConfig.load(str(path));command=config.command(str(path))
    scope=SessionScope(time.monotonic()+60)
    proxy=Proxy(command,Model(),policy=config.outer_policy(command),require_approval=True,process_group=True,approval_scope=scope,log=lambda _:None,approval_timeout=.15 if change=='expire' else 60)
    proxy.initialized=True;proxy.tools={tool['name']:tool_digest(tool) for tool in config.tools()}
    read,write=os.pipe();os.set_blocking(write,False);os.set_blocking(read,False)
    with os.fdopen(read,'rb',buffering=0) as reader,os.fdopen(write,'wb',buffering=0) as writer:
        filled=0
        while True:
            try:filled+=os.write(write,b'x'*4096)
            except BlockingIOError:break
        child=SimpleNamespace(stdin=BoundedWriter(writer,timeout=2));output=io.BytesIO()
        proxy._client(json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'mail__act','arguments':ARGS}}).encode(),child,output)
        prompt=json.loads(output.getvalue());output.seek(0);output.truncate()
        thread=threading.Thread(target=proxy._approval_response,args=(accept(prompt),child,output));thread.start()
        time.sleep(.03)
        if change=='cancel':proxy._record_cancel(1)
        elif change=='revoke':scope.revoke()
        else:time.sleep(.2)
        drained=bytearray()
        while len(drained)<filled:drained.extend(os.read(read,filled-len(drained)))
        thread.join(timeout=2);assert not thread.is_alive()
        assert bytes(drained)==b'x'*filled
        with pytest.raises(BlockingIOError):os.read(read,4096)
        assert 'error' in json.loads(output.getvalue()) and scope.holder is None


@pytest.mark.skipif(os.environ.get('LLMS_INK_GUARD_MODEL_TEST')!='1',reason='opt-in installed real model and POSIX fault injection')
def test_service_shutdown_reaps_a_stopped_real_model_during_inspection(tmp_path):
    import signal
    from llms_ink.guard import LocalGuard
    model=LocalGuard()
    try:
        with service(tmp_path,model=model) as (svc,owner,_):
            file,_=issue(owner)
            with Wire(file) as wire:
                wire.ready();prompt=wire.call()
                os.kill(model.process.pid,signal.SIGSTOP)
                pid,status=os.waitpid(model.process.pid,os.WUNTRACED)
                assert pid==model.process.pid and os.WIFSTOPPED(status)
                wire.raw(accept(prompt))
                deadline=time.monotonic()+3
                while time.monotonic()<deadline and not effects(tmp_path,'mail'):time.sleep(.02)
                assert len(effects(tmp_path,'mail'))==1
                svc.stop.set();assert wire.stream.readline()==b''
        assert not model.process.is_alive()
        with pytest.raises(ProcessLookupError):os.kill(model.process.pid,0)
    finally:
        if model.process.is_alive():model.process.kill();model.process.join(timeout=2)
        model.close()


def test_normal_disconnect_during_inspection_does_not_revoke_peer_approval(tmp_path):
    with service(tmp_path) as (svc,owner,_):
        script=tmp_path/'server.py';script.write_text(script.read_text().replace("'Recorded by '+name","'DELAY_SCAN'"))
        file,sid=issue(owner)
        with Wire(file) as a,Wire(file) as b:
            a.ready();b.ready();prompt=a.call();a.raw(accept(prompt))
            assert svc.guard.guard.started.wait(3)
            peer=b.call('docs__act');a.close();svc.guard.guard.release.set()
            assert 'result' in b.approve(peer,'docs__act')
            assert next(s for s in control(owner,'status')['sessions'] if s['sessionId']==sid)['active']
            assert len(effects(tmp_path,'docs'))==1
