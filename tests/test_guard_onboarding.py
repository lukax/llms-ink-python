"""Real terminal setup, discovery-only subprocesses and read-only diagnostics."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

import pytest
from llms_ink import guard, guard_doctor as doctor, guard_onboarding as setup
from llms_ink.guard_gateway_config import GatewayConfig
from .test_guard_gateway import config_file, connect, ready, call, answer_form, effects
from .test_guard_review import Terminal

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX owner terminal and process groups')


def fixture(tmp_path, mode='normal'):
    _, data = config_file(tmp_path, {'docs': mode})
    script = tmp_path/'server.py'
    script.write_text(script.read_text().replace('m=json.loads(raw)', "m=json.loads(raw)\n with open(journal+'.requests','a') as f:f.write(json.dumps(m)+'\\n')"))
    args = tmp_path/'args.json'; args.write_text('{"destination":"safe"}'); args.chmod(0o600)
    return data['servers']['docs']['command'], args, tmp_path/'initial.json'


class Wizard(Terminal):
    def __init__(self, command, output):
        import pty
        self.master, slave = pty.openpty()
        self.process = subprocess.Popen([sys.executable, '-m', 'llms_ink.guard', 'gateway-init', '--server', 'docs', '--output', str(output), '--', *command], stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave); self.output = b''
    def answer(self, raw):
        self.output = b''; self.send(raw + b'\n')
    def challenge(self, verb):
        raw = self.until(b'Enter declines: ')
        return re.search(rb'Type (' + verb + rb' [a-f0-9]{16}) within', raw)[1]
    def choose(self, args):
        self.until(b'Tool number to permit (Enter finishes): '); self.answer(b'1')
        self.until(b'Absolute path to exact argument JSON file: '); self.answer(os.fsencode(args))
        self.until(b'Tool number to permit (Enter finishes): ')
    def launch(self):
        self.answer(self.challenge(b'launch'))


def stopped(tmp_path):
    pid = int((tmp_path/'docs.jsonl.pid').read_text())
    with pytest.raises(ProcessLookupError): os.kill(pid, 0)


@pytest.mark.parametrize('real_model', [False, pytest.param(True, marks=pytest.mark.skipif(os.environ.get('LLMS_INK_GUARD_MODEL_TEST') != '1', reason='opt-in installed model'))])
def test_first_configuration_then_fresh_action_approval(tmp_path, real_model):
    command, args, output = fixture(tmp_path)
    wizard = Wizard(command, output)
    model = None
    try:
        assert not (tmp_path/'docs.jsonl.pid').exists()
        wizard.launch(); wizard.choose(args); stopped(tmp_path)
        wizard.answer(b'')
        challenge = wizard.challenge(b'approve')
        assert b'"definition"' in wizard.output and b'"destination": "safe"' in wizard.output
        assert not output.exists() and not effects(tmp_path, 'docs')
        wizard.answer(challenge); wizard.until(b'Configuration written.')
        assert wizard.process.wait(timeout=5) == 0
        assert output.stat().st_mode & 0o777 == 0o600
        config = GatewayConfig.load(str(output)); assert len(config.tools()) == 1
        messages = [json.loads(line) for line in (tmp_path/'docs.jsonl.requests').read_text().splitlines()]
        assert [m['method'] for m in messages] == ['initialize', 'notifications/initialized', 'tools/list']
        model = guard.LocalGuard() if real_model else None
        connection = connect(output)
        if model is not None: connection.proxy.guard = model
        try:
            ready(connection); call(connection); form = connection.answer()
            assert form['method'] == 'elicitation/create' and not effects(tmp_path, 'docs')
            answer_form(connection, form); assert 'result' in connection.answer()
            assert len(effects(tmp_path, 'docs')) == 1
            call(connection, arguments={'destination': 'not-reviewed'}); assert 'error' in connection.answer()
            assert len(effects(tmp_path, 'docs')) == 1
        finally: connection.close()
    finally:
        wizard.close()
        if model is not None: model.close()


@pytest.mark.parametrize('stage', ['launch', 'selection', 'approval'])
def test_declining_each_stage_creates_no_authority(tmp_path, stage):
    command, args, output = fixture(tmp_path); wizard = Wizard(command, output)
    try:
        if stage == 'launch': wizard.challenge(b'launch'); wizard.answer(b'')
        else:
            wizard.launch()
            if stage == 'selection': wizard.until(b'Tool number to permit (Enter finishes): '); wizard.answer(b'')
            else: wizard.choose(args); wizard.answer(b''); wizard.challenge(b'approve'); wizard.answer(b'')
        assert wizard.process.wait(timeout=5) == 1
        assert not output.exists() and not effects(tmp_path, 'docs')
        if stage == 'launch': assert not (tmp_path/'docs.jsonl.pid').exists()
        else: stopped(tmp_path)
    finally: wizard.close()


def test_multiple_exact_arguments_and_escaped_full_definition(tmp_path):
    command, args, output = fixture(tmp_path)
    toolfile = tmp_path/'tool.json'; tool = json.loads(toolfile.read_text())
    tool['description'] = 'SECRET_DESCRIPTION\x1b[2J\u202e'; toolfile.write_text(json.dumps(tool))
    second = tmp_path/'第二.json'; second.write_text('{"destination":"second"}')
    wizard = Wizard(command, output)
    try:
        wizard.launch(); wizard.choose(args)
        wizard.answer(b'1'); wizard.until(b'Absolute path to exact argument JSON file: ')
        assert b'\\u001b' in wizard.output and b'\\u202e' in wizard.output and b'\x1b' not in wizard.output
        wizard.answer(os.fsencode(second)); wizard.until(b'Tool number to permit (Enter finishes): '); wizard.answer(b'')
        wizard.answer(wizard.challenge(b'approve')); wizard.until(b'Configuration written.')
        assert wizard.process.wait(timeout=5) == 0
        assert json.loads(output.read_text())['servers']['docs']['tools'][0]['arguments'] == [{'destination': 'safe'}, {'destination': 'second'}]
    finally: wizard.close()


@pytest.mark.parametrize('change', ['arguments', 'replacement', 'output'])
def test_review_refuses_stale_arguments_and_existing_output(tmp_path, change):
    command, args, output = fixture(tmp_path); wizard = Wizard(command, output)
    try:
        wizard.launch(); wizard.choose(args); wizard.answer(b''); challenge = wizard.challenge(b'approve')
        if change == 'arguments': args.write_text('{"destination":"changed"}')
        elif change == 'replacement':
            replacement = tmp_path/'replacement'; replacement.write_bytes(args.read_bytes()); replacement.replace(args)
        else: output.write_text('existing')
        wizard.answer(challenge); wizard.until(b'Guided setup failed.')
        assert wizard.process.wait(timeout=5) == 2
        assert output.read_text() == 'existing' if change == 'output' else not output.exists()
        stopped(tmp_path)
    finally: wizard.close()


@pytest.mark.parametrize('mode', ['version', 'duplicate', 'missing', 'cursor-loop', 'init-stall'])
def test_failed_discovery_is_bounded_and_reaps_the_server(tmp_path, monkeypatch, mode):
    command, _, _ = fixture(tmp_path, mode)
    monkeypatch.setattr(setup, 'DISCOVERY_SECONDS', .5)
    with pytest.raises((ValueError, TimeoutError)): setup.discover(command)
    stopped(tmp_path); assert not effects(tmp_path, 'docs')


def test_pagination_does_not_dispatch_a_tool_call(tmp_path):
    command, _, _ = fixture(tmp_path, 'page')
    assert setup.discover(command)[0]['name'] == 'act'
    stopped(tmp_path); assert not effects(tmp_path, 'docs')
    messages = [json.loads(line) for line in (tmp_path/'docs.jsonl.requests').read_text().splitlines()]
    assert [m['method'] for m in messages] == ['initialize', 'notifications/initialized', 'tools/list', 'tools/list']
    assert messages[-1]['params'] == {'cursor': 'next'}


@pytest.mark.parametrize('fault', ['reverse', 'id', 'duplicate-key', 'oversized', 'flood', 'unterminated'])
def test_untrusted_discovery_protocol_never_reaches_owner_terminal(tmp_path, monkeypatch, fault):
    command, _, _ = fixture(tmp_path)
    substitutions = {
        'reverse': "print(json.dumps({'jsonrpc':'2.0','id':9,'method':'elicitation/create','params':{'message':'SECRET_REVERSE'}}),flush=True)",
        'id': "print(json.dumps({'jsonrpc':'2.0','id':True,'result':{}}),flush=True)",
        'duplicate-key': "print('{\"jsonrpc\":\"2.0\",\"id\":1,\"id\":1,\"result\":{}}',flush=True)",
        'oversized': "print('x'*300000,flush=True)",
        'flood': "print(('{}\\n'*70),flush=True)",
        'unterminated': "sys.stdout.write('{');sys.stdout.flush();time.sleep(60)",
    }
    script = tmp_path/'server.py'; script.write_text(script.read_text().replace("if method=='initialize':", "if method=='initialize':\n  " + substitutions[fault]))
    monkeypatch.setattr(setup, 'DISCOVERY_SECONDS', .5)
    with pytest.raises((ValueError, TimeoutError)): setup.discover(command)
    stopped(tmp_path); assert not effects(tmp_path, 'docs')


@pytest.mark.parametrize('stop_child', [False, True])
def test_sigterm_during_discovery_reaps_child_and_writes_nothing(tmp_path, stop_child):
    import time
    command, _, output = fixture(tmp_path, 'init-stall'); wizard = Wizard(command, output)
    try:
        wizard.launch()
        deadline = time.monotonic()+5
        while not (tmp_path/'docs.jsonl.pid').exists() and time.monotonic()<deadline: time.sleep(.01)
        assert (tmp_path/'docs.jsonl.pid').exists()
        if stop_child: os.kill(int((tmp_path/'docs.jsonl.pid').read_text()), signal.SIGSTOP)
        wizard.process.terminate()
        assert wizard.process.wait(timeout=5) == 130
        stopped(tmp_path); assert not output.exists()
    finally: wizard.close()


def test_no_pipe_initialization_or_implicit_model_start(tmp_path, monkeypatch, capsys):
    command, _, output = fixture(tmp_path)
    monkeypatch.setattr(guard, 'LocalGuard', lambda: pytest.fail('Started model'))
    assert guard.main(['gateway-init', '--server', 'docs', '--output', str(output), '--', *command]) == 2
    assert not output.exists() and not (tmp_path/'docs.jsonl.pid').exists()
    assert 'Guided setup failed.' in capsys.readouterr().err


def test_doctor_reports_missing_setup_without_running_commands_or_leaking_arguments(tmp_path, monkeypatch):
    path, data = config_file(tmp_path)
    data['servers']['docs']['command'].append('PRIVATE_COMMAND_ARGUMENT')
    data['servers']['docs']['tools'][0]['arguments'] = [{'destination': 'PRIVATE_DESTINATION'}]
    path.write_text(json.dumps(data))
    monkeypatch.setattr(doctor, 'model_dir', lambda: tmp_path/'missing-model')
    monkeypatch.setattr(importlib.util, 'find_spec', lambda _: None)
    report = doctor.diagnose(path)
    raw = json.dumps(report)
    assert report['checksPassed'] is False
    assert report['service']['status'] == 'not_checked'
    assert report['coverage']['hostConnection'] == 'not_verified'
    assert report['configuredServers'][0]['exactCalls'] == 1
    assert 'PRIVATE_' not in raw and not list(tmp_path.glob('*.pid'))
    assert {c['check'] for c in report['checks'] if c['status']=='fail'} == {'model_dependencies', 'model_files'}


def test_doctor_does_not_turn_local_checks_into_a_coverage_claim(tmp_path, monkeypatch):
    path, _ = config_file(tmp_path)
    monkeypatch.setattr(doctor, 'verify_assets', lambda _: None)
    monkeypatch.setattr(importlib.util, 'find_spec', lambda _: object())
    report = doctor.diagnose(path)
    assert report['checksPassed'] is True and report['service']['status'] == 'not_checked'
    assert report['coverage']['nativeHostTools'] == 'not_covered'
    assert report['coverage']['toolDefinitionsAndModelExecution'] == 'not_executed'
    assert not list(tmp_path.glob('*.pid'))


@pytest.mark.parametrize('fault', ['symlink', 'public', 'fifo', 'invalid', 'executable', 'empty'])
def test_doctor_catches_configuration_and_executable_failures(tmp_path, monkeypatch, fault):
    path, data = config_file(tmp_path)
    if fault == 'symlink':
        link=tmp_path/'alias';link.symlink_to(path);path=link
    elif fault == 'public': path.chmod(0o666)
    elif fault == 'fifo': path.unlink();os.mkfifo(path)
    elif fault == 'invalid': path.write_text('{"PRIVATE_SECRET":0}')
    elif fault == 'executable':
        data['servers']['docs']['command'][0]=str(tmp_path/'missing');path.write_text(json.dumps(data))
    else:
        for server in data['servers'].values():server['tools']=[]
        path.write_text(json.dumps(data))
    monkeypatch.setattr(doctor, 'verify_assets', lambda _: None)
    monkeypatch.setattr(importlib.util, 'find_spec', lambda _: object())
    report=doctor.diagnose(path)
    assert not report['checksPassed'] and 'PRIVATE_SECRET' not in json.dumps(report)
    assert not list(tmp_path.glob('*.pid'))


def test_doctor_compares_running_policy_without_issuing_or_revoking_sessions(tmp_path, monkeypatch):
    from .test_guard_service import service, issue
    from llms_ink.guard_service import control
    monkeypatch.setattr(doctor, 'verify_assets', lambda _: None)
    monkeypatch.setattr(importlib.util, 'find_spec', lambda _: object())
    with service(tmp_path) as (_, owner, _):
        issue(owner)
        before=control(owner, 'status')
        path=tmp_path/'gateway.json'
        report=doctor.diagnose(path, owner)
        assert report['checksPassed'] and report['service']['status']=='matching'
        assert json.loads(owner.read_text())['token'] not in json.dumps(report) and before==control(owner, 'status')
        path.write_bytes(path.read_bytes()+b' ')
        changed=doctor.diagnose(path, owner)
        assert not changed['checksPassed'] and changed['service']['status']=='different_configuration'
        assert before==control(owner, 'status')
    unavailable=doctor.diagnose(path, owner)
    assert not unavailable['checksPassed'] and unavailable['service']['status']=='unavailable'


def test_prequeued_exact_launch_answer_is_discarded(tmp_path, monkeypatch):
    import pty
    import secrets
    import select
    import threading
    command, _, output = fixture(tmp_path)
    master, slave = pty.openpty()
    monkeypatch.setattr(secrets, 'token_hex', lambda size: 'a'*(size*2))
    monkeypatch.setattr(setup, 'PROMPT_SECONDS', .05)
    # A real terminal drains rendered output. Without this reader, a long
    # checkout path can fill a small PTY buffer before the input deadline starts.
    stop = threading.Event()
    def drain():
        while not stop.is_set():
            if select.select([master], [], [], .05)[0]:
                try: os.read(master, 65536)
                except OSError: return
    reader = threading.Thread(target=drain)
    reader.start()
    try:
        os.write(master, b'launch aaaaaaaaaaaaaaaa\n')
        with os.fdopen(os.dup(slave), 'r') as stdin, os.fdopen(os.dup(slave), 'w') as stdout:
            assert setup.initialize('docs', command, output, stdin, stdout) == 1
        assert not output.exists() and not (tmp_path/'docs.jsonl.pid').exists()
    finally:
        stop.set(); reader.join(timeout=1)
        os.close(master); os.close(slave)
        assert not reader.is_alive()


@pytest.mark.parametrize('fault', ['duplicate', 'not-object', 'oversized-review', 'symlink-arguments', 'overflow-selection', 'wrong-challenge'])
def test_incomplete_or_unreviewed_initial_scope_is_never_written(tmp_path, fault):
    command, args, output = fixture(tmp_path)
    if fault == 'not-object': args.write_text('[]')
    if fault == 'oversized-review': args.write_text(json.dumps({'text': 'x'*32768}))
    if fault == 'symlink-arguments':
        alias=tmp_path/'alias.json';alias.symlink_to(args);args=alias
    wizard=Wizard(command, output)
    try:
        wizard.launch()
        if fault == 'overflow-selection':
            wizard.until(b'Tool number to permit (Enter finishes): ');wizard.answer(b'1'*140)
        elif fault in {'duplicate', 'wrong-challenge'}:
            wizard.choose(args)
            if fault == 'duplicate':
                wizard.answer(b'1');wizard.until(b'Absolute path to exact argument JSON file: ');wizard.answer(os.fsencode(args))
            else:
                wizard.answer(b'');wizard.challenge(b'approve');wizard.answer(b'approve 0000000000000000')
        else:
            wizard.until(b'Tool number to permit (Enter finishes): ');wizard.answer(b'1')
            wizard.until(b'Absolute path to exact argument JSON file: ');wizard.answer(os.fsencode(args))
        assert wizard.process.wait(timeout=5) == (1 if fault == 'wrong-challenge' else 2)
        assert not output.exists() and not effects(tmp_path, 'docs');stopped(tmp_path)
    finally:wizard.close()


def test_destination_checked_before_launch_and_failure_message_is_sanitized(tmp_path):
    command, _, output = fixture(tmp_path);output.write_text('KEEP')
    wizard=Wizard(command, output)
    try:
        raw=wizard.until(b'Guided setup failed.')
        assert wizard.process.wait(timeout=5)==2
        assert output.read_text()=='KEEP' and not (tmp_path/'docs.jsonl.pid').exists()
        assert b'Traceback' not in raw
    finally:wizard.close()


def test_doctor_cli_json_exit_status_without_model_or_server_start(tmp_path, monkeypatch, capsys):
    path,_=config_file(tmp_path)
    monkeypatch.setattr(guard, 'LocalGuard', lambda: pytest.fail('Model started'))
    monkeypatch.setattr(doctor, 'model_dir', lambda: tmp_path/'missing-model')
    assert guard.main(['doctor', '--config', str(path), '--json'])==2
    report=json.loads(capsys.readouterr().out)
    assert report['checksPassed'] is False and not list(tmp_path.glob('*.pid'))


def test_doctor_human_output_distinguishes_unverified_host(tmp_path, monkeypatch, capsys):
    path,_=config_file(tmp_path)
    monkeypatch.setattr(doctor, 'verify_assets', lambda _: None)
    monkeypatch.setattr(importlib.util, 'find_spec', lambda _: object())
    assert guard.main(['doctor', '--config', str(path)])==0
    output=capsys.readouterr().out
    assert 'NOT CHECKED  running_service' in output
    assert 'Host connection and Claude authentication are not verified.' in output
    assert 'docs: act; exact calls: 1' in output
    assert 'No model or server was started.' in output


def test_interrupt_during_process_creation_keeps_handle_for_cleanup(tmp_path, monkeypatch):
    command,_,_=fixture(tmp_path)
    original=setup.subprocess.Popen; children=[]
    def interrupted_start(*args, **kwargs):
        child=original(*args, **kwargs);children.append(child)
        os.kill(os.getpid(), signal.SIGINT)
        return child
    monkeypatch.setattr(setup.subprocess, 'Popen', interrupted_start)
    original_handler=signal.getsignal(signal.SIGINT)
    try:
        with pytest.raises(KeyboardInterrupt):setup.discover(command)
        assert len(children)==1 and children[0].poll() is not None
        assert signal.getsignal(signal.SIGINT)==original_handler
        with pytest.raises(ProcessLookupError):os.kill(children[0].pid,0)
        assert not effects(tmp_path,'docs')
    finally:
        for child in children:
            if child.poll() is None:
                os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
