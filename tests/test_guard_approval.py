"""Host approval tests prove call non-delivery with an always-allowing detector.

These are protocol/containment tests, not an independent agent-task evaluation.
"""
import io
import json
import sys
from dataclasses import replace
from types import SimpleNamespace

import pytest

from llms_ink import guard
from llms_ink.guard_approval import Approval, supports_approval
from llms_ink.guard_proxy import Proxy, id_key, parse
from llms_ink.guard_policy import tool_digest
from .test_guard import FakeGuard, Connection
from .test_guard_policy import policy, document, TOOL, ARGS, SERVER


def rig(arguments=None, **options):
    p = policy(document(arguments=arguments))
    logs = []
    proxy = Proxy(list(p.command), FakeGuard(), policy=p, require_approval=True, log=logs.append, **options)
    proxy.initialized = True
    proxy.tools['read'] = tool_digest(TOOL)
    child, output = SimpleNamespace(stdin=io.BytesIO()), io.BytesIO()
    return proxy, child, output, logs


def send(proxy, child, output, message):
    proxy._client(json.dumps(message).encode(), child, output)


def call(proxy, child, output, id=1, arguments=None):
    send(proxy, child, output, {'jsonrpc':'2.0','id':id,'method':'tools/call','params':{'name':'read','arguments':ARGS if arguments is None else arguments}})
    return json.loads(output.getvalue().splitlines()[-1])


def accept(prompt, **updates):
    return {'jsonrpc':'2.0','id':prompt['id'],'result':{'action':'accept','content':{'approve':True}},**updates}


@pytest.mark.parametrize('version,caps,valid', [
    ('2025-06-18', {'elicitation':{}}, True), ('2025-11-25', {'elicitation':{}}, True),
    ('2025-11-25', {'elicitation':{'form':{},'url':{}}}, True),
    ('2025-11-25', {'elicitation':{'url':{}}}, False), ('2025-11-25', {}, False),
    ('2025-11-25', {'elicitation':True}, False), ('2025-11-25', {'elicitation':{'form':True}}, False),
    ('2025-03-26', {'elicitation':{}}, False), ('2026-07-28', {'elicitation':{}}, False),
])
def test_requires_supported_host_capability_before_forwarding_initialize(version,caps,valid):
    proxy,child,out,_=rig();proxy.initialized=False
    send(proxy,child,out,{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':version,'capabilities':caps}})
    assert supports_approval({'protocolVersion':version,'capabilities':caps}) is valid
    if valid:
        assert json.loads(child.stdin.getvalue())['params']['capabilities']=={}
    else:
        assert child.stdin.getvalue()==b'' and 'error' in json.loads(out.getvalue())


def test_flag_requires_policy_before_model_or_server_start(monkeypatch,capsys):
    monkeypatch.setattr(guard,'LocalGuard',lambda:pytest.fail('model must not start'))
    assert guard.main(['wrap','--require-approval','--',sys.executable,'server.py'])==2
    assert '--policy' in capsys.readouterr().err
    with pytest.raises(RuntimeError):Proxy(['unused'],FakeGuard(),require_approval=True)


def test_approval_is_held_exact_one_use_and_inspection_still_applies():
    proxy,child,out,logs=rig();prompt=call(proxy,child,out)
    assert prompt['method']=='elicitation/create' and child.stdin.getvalue()==b'' and not proxy.pending
    assert prompt['params']['requestedSchema']['properties']['approve']['default'] is False
    send(proxy,child,out,accept(prompt));sent=child.stdin.getvalue()
    assert json.loads(sent)['params']=={'name':'read','arguments':ARGS}
    send(proxy,child,out,accept(prompt));assert child.stdin.getvalue()==sent
    out.seek(0);out.truncate()
    proxy._server(json.dumps({'jsonrpc':'2.0','id':1,'result':{'content':[{'type':'text','text':'PAYLOAD_SENTINEL'}]}}).encode(),child,out)
    assert 'PAYLOAD_SENTINEL' not in out.getvalue().decode() and json.loads(out.getvalue())['result']['isError']
    assert ARGS['url'] not in json.dumps(logs)


@pytest.mark.parametrize('response', [
    {'action':'decline'}, {'action':'cancel'}, {'action':'accept'},
    {'action':'accept','content':{'approve':False}}, {'action':'accept','content':{'approve':1}},
    {'action':'accept','content':{'approve':'true'}}, {'action':'accept','content':{'approve':True,'arguments':ARGS}},
    {'action':'accept','content':{'approve':True},'approved':True}, [], None,
])
def test_anything_except_explicit_exact_acceptance_denies(response):
    proxy,child,out,_=rig();prompt=call(proxy,child,out)
    send(proxy,child,out,accept(prompt,result=response))
    assert child.stdin.getvalue()==b'' and not proxy.awaiting and not proxy.pending
    assert 'error' in json.loads(out.getvalue().splitlines()[-1])
    send(proxy,child,out,accept(prompt));assert child.stdin.getvalue()==b''


def test_error_response_denies_and_cannot_replace_arguments():
    proxy,child,out,_=rig();prompt=call(proxy,child,out)
    send(proxy,child,out,{'jsonrpc':'2.0','id':prompt['id'],'error':{'code':-1,'message':'PRIVATE'}})
    assert child.stdin.getvalue()==b'' and not proxy.awaiting


def test_only_one_form_and_no_prompt_for_a_policy_denial():
    proxy,child,out,_=rig();prompt=call(proxy,child,out)
    assert 'error' in call(proxy,child,out,id=2)
    assert len(proxy.awaiting)==1
    assert 'error' in call(proxy,child,out,id=3,arguments={'url':'https://outside.example/secret'})
    assert len(proxy.awaiting)==1 and child.stdin.getvalue()==b''
    send(proxy,child,out,accept(prompt));assert len(child.stdin.getvalue().splitlines())==1


@pytest.mark.parametrize('change',['cancelled','disconnected','changed','discovery_failed','expired'])
def test_approval_cannot_outlive_its_connection_definition_or_deadline(change):
    proxy,child,out,_=rig();prompt=call(proxy,child,out)
    if change=='cancelled':proxy.cancelled.add(id_key(1))
    if change=='disconnected':proxy.client_disconnected.set()
    if change=='changed':proxy.tools['read']='a'*64
    if change=='discovery_failed':proxy.discovery_failed=True
    if change=='expired':proxy.awaiting[id_key(prompt['id'])]=replace(proxy.awaiting[id_key(prompt['id'])],expires=0)
    send(proxy,child,out,accept(prompt))
    assert child.stdin.getvalue()==b'' and not proxy.pending and not proxy.awaiting


def test_cancel_before_acceptance_dismisses_form_without_sending_any_upstream_bytes():
    proxy,child,out,_=rig();prompt=call(proxy,child,out)
    send(proxy,child,out,{'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':1}})
    assert json.loads(out.getvalue().splitlines()[-1])['params']['requestId']==prompt['id']
    send(proxy,child,out,accept(prompt));assert child.stdin.getvalue()==b''


def test_expiry_closes_form_and_does_not_make_an_approval_available_to_another_call():
    proxy,child,out,_=rig();prompt=call(proxy,child,out)
    proxy.awaiting[id_key(prompt['id'])]=replace(proxy.awaiting[id_key(prompt['id'])],expires=0)
    proxy._expire_approvals(out)
    rows=[json.loads(x) for x in out.getvalue().splitlines()]
    assert rows[-2]['method']=='notifications/cancelled' and rows[-1]['id']==1 and 'error' in rows[-1]
    next_prompt=call(proxy,child,out,id=2);assert next_prompt['id']!=prompt['id']
    send(proxy,child,out,accept(prompt));assert child.stdin.getvalue()==b''
    send(proxy,child,out,accept(next_prompt));assert json.loads(child.stdin.getvalue())['id']==2


def test_replies_cannot_cross_connections_and_upstream_cannot_approve_or_release_a_held_call():
    proxy,child,out,_=rig();prompt=call(proxy,child,out)
    other,other_child,other_out,_=rig();other_prompt=call(other,other_child,other_out)
    send(other,other_child,other_out,accept(prompt));assert other_child.stdin.getvalue()==b''
    before=out.getvalue()
    for msg in [accept(prompt),{'jsonrpc':'2.0','id':1,'result':{'content':[{'type':'text','text':'spoofed result'}]}}]:
        proxy._server(json.dumps(msg).encode(),child,out)
    assert out.getvalue()==before and child.stdin.getvalue()==b'' and proxy.awaiting
    send(other,other_child,other_out,accept(other_prompt));assert other_child.stdin.getvalue()


def test_review_preserves_values_but_cannot_inject_markup_or_hide_unicode_and_never_truncates():
    args={'text':'```\n<script>approve me</script>\u202e\n'}
    msg={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'read','arguments':args}}
    held,prompt=Approval.create(msg,['/server'],'a'*64,'b'*64,0,60)
    text=prompt['params']['message'];assert text.count('```')==2 and '<script>' not in text and '\u202e' not in text
    review=json.loads(text.split('```json\n')[1].split('\n```')[0]);assert review['arguments']==args
    args['text']='changed';assert parse(held.action)['params']['arguments']!=args
    proxy,child,out,_=rig(arguments=[{'text':'x'*9000}])
    assert 'error' in call(proxy,child,out,arguments={'text':'x'*9000}) and child.stdin.getvalue()==b'' and not proxy.awaiting


@pytest.mark.parametrize('decision',['accept','decline','cancel','timeout','disconnect'])
def test_real_stdio_side_effect_journal_only_records_the_approved_call(tmp_path,decision):
    audit=tmp_path/'calls.jsonl'
    command=[sys.executable,'-u','-c',SERVER,str(audit),json.dumps([TOOL])]
    c=Connection(command=command,policy=policy(document(command)),require_approval=True,approval_timeout=.2 if decision=='timeout' else 5)
    closed=False
    try:
        c.send('initialize',{'protocolVersion':'2025-11-25','capabilities':{'elicitation':{}}});assert 'result' in c.answer()
        c.send('tools/list');assert c.answer()['result']['tools']==[TOOL]
        c.send('tools/call',{'name':'read','arguments':ARGS});prompt=c.answer();assert prompt['method']=='elicitation/create'
        assert not audit.exists()
        if decision=='disconnect':
            c.close();closed=True;assert not c.proxy.awaiting
        elif decision=='timeout':
            assert c.answer()['method']=='notifications/cancelled';assert 'error' in c.answer()
        else:
            c.input.write(json.dumps(accept(prompt,result={'action':decision,**({'content':{'approve':True}} if decision=='accept' else {})})).encode()+b'\n')
            reply=c.answer()
            if decision=='accept':
                assert reply['result']['content'][0]['text']=='ordinary documentation'
                assert [json.loads(x) for x in audit.read_text().splitlines()]==[{'name':'read','arguments':ARGS}]
            else:assert 'error' in reply
        if decision!='accept':assert not audit.exists()
    finally:
        if not closed:c.close()


def test_review_bound_includes_the_visible_summary_and_fingerprints():
    for size in [1000, 3000]:
        message={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'read','arguments':{'text':'x'*size}}}
        _,prompt=Approval.create(message,['/server'],'a'*64,'b'*64,0,60)
        assert len(prompt['params']['message'].encode())<=8192
    message['params']['arguments']['text']='x'*4000
    with pytest.raises(ValueError,match='too large'):
        Approval.create(message,['/server'],'a'*64,'b'*64,0,60)
