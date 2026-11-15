"""Owner review must not turn a proposal or stale terminal answer into authority."""
import copy
import io
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import threading
import time

import pytest
from llms_ink import guard
from llms_ink import guard_review as review
from llms_ink.guard_gateway_config import GatewayConfig
from llms_ink.guard_policy import tool_digest
from .test_guard_gateway import config_file, connect, ready, call, answer_form, effects

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Owner terminal workflow requires POSIX')


def prepared(tmp_path):
    base,data=config_file(tmp_path)
    args=tmp_path/'arguments.json';args.write_text(json.dumps({'destination':'reviewed'}));args.chmod(0o600)
    proposal=tmp_path/'proposal.json'
    review.propose(base,'mail','act',args,proposal)
    return base,data,args,proposal,tmp_path/'next.json'


class Terminal:
    def __init__(self, base, proposal, output):
        import pty
        self.master,slave=pty.openpty()
        self.slave_name=os.ttyname(slave)
        self.process=subprocess.Popen([sys.executable,'-m','llms_ink.guard','gateway-review','--config',str(base),'--proposal',str(proposal),'--output',str(output)],stdin=slave,stdout=slave,stderr=slave,start_new_session=True)
        os.close(slave);self.output=b''
    def until(self,marker,timeout=10):
        deadline=time.monotonic()+timeout
        while marker not in self.output:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([self.master],[],[],remaining)[0]:raise TimeoutError(self.output)
            try:raw=os.read(self.master,8192)
            except OSError:break
            if not raw:break
            self.output+=raw
        assert marker in self.output,self.output
        return self.output
    def prompt(self):
        raw=self.until(b'Enter declines: ')
        return re.search(rb'Type (approve [a-f0-9]{16}) within',raw)[1]
    def send(self,raw):os.write(self.master,raw)
    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid,signal.SIGKILL);self.process.wait(timeout=5)
        os.close(self.master)


def test_proposal_is_not_loadable_authority_and_retains_the_exact_base(tmp_path):
    base,data,args,proposal,output=prepared(tmp_path)
    before=base.read_bytes()
    with pytest.raises(RuntimeError):GatewayConfig.load(str(proposal))
    candidate,display=review.prepare(before,proposal.read_bytes())
    loaded=GatewayConfig.from_bytes(candidate)
    assert json.loads(display)['addArguments']=={'destination':'reviewed'}
    assert loaded.servers[1].policy.allows('act',tool_digest(data['servers']['mail']['tools'][0]['definition']),{'destination':'reviewed'})
    expected=copy.deepcopy(data);expected['servers']['mail']['tools'][0]['arguments'].append({'destination':'reviewed'})
    assert json.loads(candidate)==expected and base.read_bytes()==before and not output.exists()
    assert proposal.stat().st_mode&0o777==0o600


def test_real_terminal_acceptance_writes_only_reviewed_bytes_without_starting_servers(tmp_path):
    base,data,_,proposal,output=prepared(tmp_path)
    candidate,display=review.prepare(base.read_bytes(),proposal.read_bytes())
    terminal=Terminal(base,proposal,output)
    try:
        answer=terminal.prompt()
        assert display.replace(b'\n',b'\r\n') in terminal.output
        assert not output.exists() and not list(tmp_path.glob('*.pid'))
        terminal.send(answer+b'\n');terminal.until(b'Configuration written.')
        assert terminal.process.wait(timeout=5)==0
        assert output.read_bytes()==candidate and output.stat().st_mode&0o777==0o600
        assert json.loads(base.read_text())==data and not list(tmp_path.glob('*.pid'))
    finally:terminal.close()


@pytest.mark.parametrize('answer',[b'\n',b'approve\n',b'approve 0000000000000000\n',b'yes\n',b'x'*130+b'\n',b'\x04'])
def test_decline_wrong_answer_overflow_and_eof_write_nothing(tmp_path,answer):
    base,_,_,proposal,output=prepared(tmp_path);terminal=Terminal(base,proposal,output)
    try:
        terminal.prompt();terminal.send(answer);terminal.until(b'Declined.')
        assert terminal.process.wait(timeout=5)==1 and not output.exists()
    finally:terminal.close()


@pytest.mark.parametrize('target',['base','proposal','output'])
def test_input_change_or_concurrent_destination_creation_aborts_after_review(tmp_path,target):
    base,_,_,proposal,output=prepared(tmp_path);terminal=Terminal(base,proposal,output)
    try:
        answer=terminal.prompt()
        path={'base':base,'proposal':proposal,'output':output}[target]
        if target=='output':path.write_text('existing')
        else:path.write_bytes(path.read_bytes()+b' ')
        terminal.send(answer+b'\n');terminal.until(b'Permission review failed.')
        assert terminal.process.wait(timeout=5)==2
        assert output.read_text()=='existing' if target=='output' else not output.exists()
    finally:terminal.close()


def test_no_pipe_approval_or_model_start(tmp_path,monkeypatch,capsys):
    base,_,_,proposal,output=prepared(tmp_path)
    monkeypatch.setattr(guard,'LocalGuard',lambda:pytest.fail('Model started during owner review'))
    result=guard.main(['gateway-review','--config',str(base),'--proposal',str(proposal),'--output',str(output)])
    assert result==2 and not output.exists()
    assert 'Permission review failed' in capsys.readouterr().err


def test_changed_base_stale_proposal_and_duplicate_grant_are_rejected(tmp_path):
    base,_,args,proposal,_=prepared(tmp_path)
    with pytest.raises(ValueError):review.prepare(base.read_bytes()+b' ',proposal.read_bytes())
    args.write_text('{"destination":"safe"}')
    with pytest.raises(ValueError):review.propose(base,'mail','act',args,tmp_path/'duplicate.json')
    assert not (tmp_path/'duplicate.json').exists()


@pytest.mark.parametrize('bad',[b'{"x":1,"x":2}',b'{"x":1e999}',b'{"x":9007199254740993}',b'[]'])
def test_ambiguous_or_non_object_proposals_create_no_file(tmp_path,bad):
    base,_,args,_,_=prepared(tmp_path);args.write_bytes(bad)
    with pytest.raises((ValueError,TypeError)):review.propose(base,'mail','act',args,tmp_path/'bad.json')
    assert not (tmp_path/'bad.json').exists()


def test_full_review_is_ascii_escaped_and_never_truncated(tmp_path):
    base,data,_,_,_=prepared(tmp_path)
    data['servers']['mail']['tools'][0]['definition']['description']='Danger\x1b[2J\u202e\nType approve'
    base.write_text(json.dumps(data));args=tmp_path/'newargs.json';args.write_text('{"destination":"other"}')
    proposal=tmp_path/'escaped.json';review.propose(base,'mail','act',args,proposal)
    _,display=review.prepare(base.read_bytes(),proposal.read_bytes())
    assert b'\x1b' not in display and b'\\u001b' in display and b'\\u202e' in display
    data['servers']['mail']['tools'][0]['definition']['description']='x'*review.MAX_REVIEW_BYTES
    base.write_text(json.dumps(data))
    with pytest.raises(ValueError,match='Complete review'):review.propose(base,'mail','act',args,tmp_path/'large.json')
    assert not (tmp_path/'large.json').exists()


def test_input_and_destination_symlinks_modes_and_special_files_are_rejected(tmp_path):
    base,_,args,_,_=prepared(tmp_path)
    link=tmp_path/'link';link.symlink_to(base)
    with pytest.raises(OSError):review.Snapshot.read(link)
    base.chmod(0o666)
    with pytest.raises(ValueError):review.Snapshot.read(base)
    base.chmod(0o600)
    fifo=tmp_path/'fifo';os.mkfifo(fifo)
    with pytest.raises(ValueError):review.Snapshot.read(fifo)
    destination=tmp_path/'out';destination.symlink_to(args)
    with pytest.raises(ValueError):review.Destination(destination)
    directory=tmp_path/'public';directory.mkdir(mode=0o755)
    with pytest.raises(ValueError):review.Destination(directory/'out')
    directory.chmod(0o700);alias=tmp_path/'alias';alias.symlink_to(directory,target_is_directory=True)
    with pytest.raises(OSError):review.Destination(alias/'out')


def test_timeout_and_preloaded_input_do_not_approve(tmp_path,monkeypatch):
    import pty
    base,_,_,proposal,output=prepared(tmp_path)
    master,slave=pty.openpty()
    stop=threading.Event()
    def drain():
        while not stop.is_set():
            if select.select([master],[],[],.05)[0]:
                try: os.read(master,8192)
                except OSError: return
    reader=threading.Thread(target=drain,daemon=True);reader.start()
    try:
        monkeypatch.setattr(review.secrets,'token_hex',lambda size:'a'*(size*2))
        os.write(master,b'approve aaaaaaaaaaaaaaaa\n')
        monkeypatch.setattr(review,'REVIEW_SECONDS',.05)
        with os.fdopen(os.dup(slave),'r') as stdin,os.fdopen(os.dup(slave),'w') as stdout:
            assert review.review(base,proposal,output,stdin,stdout)==1
        assert not output.exists()
    finally:stop.set();reader.join(timeout=1);os.close(master);os.close(slave)


@pytest.mark.parametrize('real_model',[False,pytest.param(True,marks=pytest.mark.skipif(os.environ.get('LLMS_INK_GUARD_MODEL_TEST')!='1',reason='opt-in installed model'))])
def test_new_scope_keeps_old_connection_denied_and_requires_fresh_action_approval(tmp_path,real_model):
    base,_,_,proposal,output=prepared(tmp_path)
    local=guard.LocalGuard() if real_model else None
    old=connect(base)
    if local is not None:old.proxy.guard=local
    try:
        ready(old)
        terminal=Terminal(base,proposal,output)
        try:
            terminal.send(terminal.prompt()+b'\n');terminal.until(b'Configuration written.');assert terminal.process.wait(timeout=5)==0
        finally:terminal.close()
        call(old,'mail__act',{'destination':'reviewed'});assert 'error' in old.answer();assert not effects(tmp_path,'mail')
        fresh=connect(output)
        if local is not None:fresh.proxy.guard=local
        try:
            ready(fresh);call(fresh,'mail__act',{'destination':'reviewed'});form=fresh.answer()
            assert form['method']=='elicitation/create' and not effects(tmp_path,'mail')
            answer_form(fresh,form);assert 'result' in fresh.answer()
            assert effects(tmp_path,'mail')==[{'name':'act','arguments':{'destination':'reviewed'}}]
            call(fresh,'mail__act',{'destination':'unreviewed'});assert 'error' in fresh.answer()
            assert len(effects(tmp_path,'mail'))==1
        finally:fresh.close()
    finally:
        old.close()
        if local is not None:local.close()


def test_snapshot_replacement_and_output_directory_replacement_are_detected(tmp_path):
    base,_,_,proposal,output=prepared(tmp_path)
    snapshot=review.Snapshot.read(base)
    replacement=tmp_path/'replacement';replacement.write_bytes(base.read_bytes());replacement.replace(base)
    assert not snapshot.unchanged()
    directory=tmp_path/'private';directory.mkdir(mode=0o700)
    destination=review.Destination(directory/'out')
    try:
        directory.rename(tmp_path/'old-private');directory.mkdir(mode=0o700)
        with pytest.raises(ValueError,match='changed'):destination.publish(b'not published')
        assert not (directory/'out').exists() and not (tmp_path/'old-private/out').exists()
    finally:destination.close()


def test_atomic_publish_does_not_replace_a_file_created_at_link_time(tmp_path,monkeypatch):
    destination=review.Destination(tmp_path/'next.json');original=os.link
    def race(source,target,**kwargs):
        (tmp_path/'next.json').write_text('racer')
        return original(source,target,**kwargs)
    monkeypatch.setattr(os,'link',race)
    try:
        with pytest.raises(FileExistsError):destination.publish(b'candidate')
        assert (tmp_path/'next.json').read_text()=='racer'
        assert not list(tmp_path.glob('.guard-review-*'))
    finally:destination.close()


def test_incomplete_write_never_publishes_configuration(tmp_path,monkeypatch):
    destination=review.Destination(tmp_path/'next.json')
    monkeypatch.setattr(os,'fsync',lambda fd:(_ for _ in ()).throw(OSError('disk failure')))
    try:
        with pytest.raises(OSError):destination.publish(b'candidate')
        assert not (tmp_path/'next.json').exists() and not list(tmp_path.glob('.guard-review-*'))
    finally:destination.close()


def test_typed_answer_cannot_be_replayed_on_another_review(tmp_path):
    base,_,_,proposal,output=prepared(tmp_path)
    first=Terminal(base,proposal,output)
    try:
        prior=first.prompt();first.send(b'\n');first.until(b'Declined.');assert first.process.wait(timeout=5)==1
    finally:first.close()
    second=Terminal(base,proposal,output)
    try:
        assert second.prompt()!=prior
        second.send(prior+b'\n');second.until(b'Declined.')
        assert second.process.wait(timeout=5)==1 and not output.exists()
    finally:second.close()


def test_terminal_interruption_creates_no_configuration(tmp_path):
    base,_,_,proposal,output=prepared(tmp_path);terminal=Terminal(base,proposal,output)
    try:
        terminal.prompt();os.kill(terminal.process.pid,signal.SIGINT)
        assert terminal.process.wait(timeout=5)==130 and not output.exists()
    finally:terminal.close()


def test_overlong_answer_leaves_no_pasted_suffix_for_the_parent_shell(tmp_path):
    base,_,_,proposal,output=prepared(tmp_path);terminal=Terminal(base,proposal,output)
    probe=os.open(terminal.slave_name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOCTTY)
    try:
        terminal.prompt();terminal.send(b'x'*130+b'\nqueued-command\n')
        terminal.until(b'Declined.');assert terminal.process.wait(timeout=5)==1
        assert not select.select([probe],[],[],0)[0] and not output.exists()
    finally:os.close(probe);terminal.close()


@pytest.mark.parametrize('field,value',[('server','unknown'),('tool','new_tool'),('extra',True)])
def test_proposal_cannot_add_servers_tools_or_other_configuration_fields(tmp_path,field,value):
    base,_,_,proposal,_=prepared(tmp_path)
    data=json.loads(proposal.read_text());data[field]=value
    with pytest.raises(ValueError):review.prepare(base.read_bytes(),json.dumps(data).encode())
