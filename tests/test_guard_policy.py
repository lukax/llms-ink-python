"""Authorization tests use an allowing detector and prove upstream non-delivery."""
import io
import json
import os
import sys
from types import SimpleNamespace

import pytest

from llms_ink import guard
from llms_ink.guard_policy import Policy, tool_digest
from llms_ink.guard_proxy import Proxy, parse
from .test_guard import Connection, FakeGuard

TOOL = {"name": "read", "description": "Read a documentation page", "inputSchema": {"type": "object"}}
ARGS = {"url": "https://docs.example/reference", "format": "text"}


def document(command=None, arguments=None):
    return {"version": 1, "command": command or [sys.executable, "server.py"], "tools": {
        "read": {"definitionSha256": tool_digest(TOOL), "arguments": [dict(ARGS)] if arguments is None else arguments}
    }}


def policy(data=None):
    return Policy.from_bytes(json.dumps(document() if data is None else data).encode())


def dispatch(params, extra=None, permitted=None):
    logs = []
    detector = FakeGuard()
    p = permitted or policy()
    proxy = Proxy(list(p.command), detector, policy=p, log=logs.append)
    proxy.initialized = True
    proxy.tools.update({"read": tool_digest(TOOL), "send_mail": "a" * 64})
    child, output = SimpleNamespace(stdin=io.BytesIO()), io.BytesIO()
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params, **(extra or {})}
    proxy._client(json.dumps(msg).encode(), child, output)
    return proxy, child.stdin.getvalue(), output.getvalue(), detector, logs


@pytest.mark.parametrize("params,extra", [
    ({"name": "send_mail", "arguments": {"recipient": "outside@example.com"}}, None),
    ({"name": "read", "arguments": {**ARGS, "url": "https://outside.example/secret"}}, None),
    ({"name": "read", "arguments": {**ARGS, "url": ARGS["url"] + "?secret=value"}}, None),
    ({"name": "read", "arguments": {**ARGS, "url": "https://docs.example/reference/../private"}}, None),
    ({"name": "read", "arguments": {**ARGS, "url": "https://docs.example/%72eference"}}, None),
    ({"name": "read", "arguments": {**ARGS, "url": "https://dоcs.example/reference"}}, None),
    ({"name": "read", "arguments": {**ARGS, "execute": True}}, None),
    ({"name": "read", "arguments": {"url": ARGS["url"]}}, None),
    ({"name": "read", "arguments": ARGS, "_meta": {"approved": True}}, None),
    ({"name": "read", "arguments": ARGS, "task": {}}, None),
    ({"name": "read", "arguments": ARGS}, {"approved": True}),
    ({"name": "read", "arguments": []}, None),
    ({"name": "read", "arguments": None}, None),
    ({"name": "read"}, None),
    ({"name": ["read"], "arguments": ARGS}, None),
])
def test_denied_call_never_reaches_upstream_or_detector(params, extra):
    proxy, upstream, response, detector, logs = dispatch(params, extra)
    assert upstream == b"" and not proxy.pending and not detector.seen
    assert "error" in json.loads(response)
    assert "outside" not in str(logs) and "secret" not in str(logs)


def test_exact_call_is_forwarded_without_order_sensitivity():
    proxy, upstream, response, detector, _ = dispatch({"name": "read", "arguments": dict(reversed(list(ARGS.items())))})
    assert json.loads(upstream)["params"] == {"name": "read", "arguments": ARGS}
    assert response == b"" and len(proxy.pending) == 1 and not detector.seen


def test_omitted_arguments_normalized_only_when_empty_object_allowed():
    _, upstream, response, _, _ = dispatch({"name": "read"}, permitted=policy(document(arguments=[{}])))
    assert json.loads(upstream)["params"]["arguments"] == {} and response == b""


@pytest.mark.parametrize("value", [True, 1.0, "1", [1], {"value": 1}])
def test_argument_types_cannot_substitute_for_integer(value):
    p = policy(document(arguments=[{"limit": 1}]))
    _, upstream, response, _, _ = dispatch({"name": "read", "arguments": {"limit": value}}, permitted=p)
    assert upstream == b"" and "error" in json.loads(response)


@pytest.mark.parametrize("raw", [
    b'{"jsonrpc":"2.0","id":1,"id":2}',
    b'{"jsonrpc":"2.0","params":{"arguments":{"url":"a","url":"b"}}}',
    b'{"jsonrpc":"2.0","params":{"arguments":{"n":1e999}}}',
    b'{"jsonrpc":"2.0","params":{"arguments":{"n":9007199254740993}}}',
    b'{"jsonrpc":"2.0","params":{"arguments":{"s":"\\ud800"}}}',
])
def test_ambiguous_or_nonportable_json_is_rejected(raw):
    with pytest.raises(ValueError):
        parse(raw)


@pytest.mark.parametrize("change", [
    lambda d: d.update(version=True), lambda d: d.update(version=2),
    lambda d: d.update(approval=True), lambda d: d.update(command=["python", "server.py"]),
    lambda d: d["tools"]["read"].update(arguments="*"),
    lambda d: d["tools"]["read"].update(arguments=[None]),
    lambda d: d["tools"]["read"].update(arguments=[]),
    lambda d: d["tools"]["read"].update(definitionSha256="*"),
    lambda d: d["tools"]["read"].update(readOnlyHint=True),
])
def test_invalid_policies_fail_closed(change):
    data = document(); change(data)
    with pytest.raises(ValueError):
        policy(data)


def test_empty_policy_denies_every_tool():
    p = policy({**document(), "tools": {}})
    assert not p.allows("read", tool_digest(TOOL), ARGS)


def test_snapshot_cannot_be_changed_by_mutating_source_or_file(tmp_path):
    data = document()
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data))
    p = Policy.load(str(path))
    data["tools"]["read"]["arguments"][0]["url"] = "https://outside.example"
    path.write_text(json.dumps(data))
    assert p.allows("read", tool_digest(TOOL), ARGS)
    assert not p.allows("read", tool_digest(TOOL), data["tools"]["read"]["arguments"][0])
    with pytest.raises(AttributeError):
        p.tools = ()


def test_command_mismatch_prevents_model_and_server_start(tmp_path, monkeypatch, capsys):
    path = tmp_path / "policy.json"; path.write_text(json.dumps(document()))
    monkeypatch.setattr(guard, "LocalGuard", lambda: pytest.fail("model must not start"))
    assert guard.main(["wrap", "--policy", str(path), "--", sys.executable, "other.py"]) == 2
    assert "No server was started" in capsys.readouterr().err


def test_policy_check_and_tool_hash_do_not_start_model(tmp_path, monkeypatch, capsys):
    path = tmp_path / "policy.json"; path.write_text(json.dumps(document()))
    monkeypatch.setattr(guard, "LocalGuard", lambda: pytest.fail("model must not start"))
    assert guard.main(["policy-check", str(path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["valid"] and out["tools"] == 1 and "url" not in str(out)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(TOOL).encode())))
    assert guard.main(["tool-hash"]) == 0
    assert capsys.readouterr().out.strip() == tool_digest(TOOL)


def test_missing_or_malformed_policy_is_sanitized_before_model_start(tmp_path, monkeypatch, capsys):
    path = tmp_path / "SECRET_POLICY_NAME"
    monkeypatch.setattr(guard, "LocalGuard", lambda: pytest.fail("model must not start"))
    for content in [None, '{"SECRET_CONTENT":', '{"version":1,"version":1}', "x" * 262145]:
        if content is not None: path.write_text(content)
        assert guard.main(["wrap", "--policy", str(path), "--", sys.executable, "server.py"]) == 2
        out = capsys.readouterr()
        assert not out.out and "SECRET" not in out.err and "Invalid guard policy" in out.err


def test_empty_explicit_policy_path_cannot_disable_permissions(monkeypatch, capsys):
    monkeypatch.setattr(guard, "LocalGuard", lambda: pytest.fail("model must not start"))
    assert guard.main(["wrap", "--policy", "", "--", sys.executable, "server.py"]) == 2
    assert "Invalid guard policy" in capsys.readouterr().err


@pytest.mark.skipif(os.name != "posix", reason="POSIX file semantics")
def test_policy_file_rejects_symlink_fifo_and_group_write(tmp_path):
    path = tmp_path / "policy.json"; path.write_text(json.dumps(document()))
    link = tmp_path / "link"; link.symlink_to(path)
    fifo = tmp_path / "fifo"; os.mkfifo(fifo)
    for target in [link, fifo, tmp_path]:
        with pytest.raises(RuntimeError): Policy.load(str(target))
    path.chmod(0o660)
    with pytest.raises(RuntimeError): Policy.load(str(path))


SERVER = r'''
import json,sys
tools = json.loads(sys.argv[2])
for line in sys.stdin:
    m=json.loads(line)
    if 'id' not in m: continue
    method=m.get('method')
    if method=='initialize':
        result={'protocolVersion':'2025-11-25','capabilities':{},'serverInfo':{'name':'fixture','version':'1'}}
    elif method=='tools/list': result={'tools':tools}
    elif method=='tools/call':
        with open(sys.argv[1], 'a') as audit: audit.write(json.dumps(m['params'])+'\n')
        result={'content':[{'type':'text','text':'ordinary documentation'}]}
    else: result={}
    print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':result}),flush=True)
'''


@pytest.mark.parametrize("changed_definition", [False, True])
def test_real_stdio_denial_cannot_trigger_upstream_side_effect(tmp_path, changed_definition):
    audit = tmp_path / "calls.jsonl"
    tool = {**TOOL, **({"description": "changed definition"} if changed_definition else {})}
    mail = {"name": "send_mail", "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": True}}
    command = [sys.executable, "-u", "-c", SERVER, str(audit), json.dumps([tool, mail])]
    p = policy(document(command))
    c = Connection(command=command, policy=p)
    try:
        c.send("initialize", {"protocolVersion": "2025-11-25"}); assert "result" in c.answer()
        c.send("tools/list"); listed = c.answer()["result"]["tools"]
        assert listed == ([] if changed_definition else [TOOL])
        for name, args in [("send_mail", {"recipient": "outside@example.com"}), ("read", {**ARGS, "url": "https://outside.example/secret"})]:
            c.send("tools/call", {"name": name, "arguments": args}); assert "error" in c.answer()
        assert not audit.exists()
        c.send("tools/call", {"name": "read", "arguments": ARGS})
        response = c.answer()
        if changed_definition:
            assert "error" in response and not audit.exists()
        else:
            assert response["result"]["content"][0]["text"] == "ordinary documentation"
            assert [json.loads(line) for line in audit.read_text().splitlines()] == [{"name": "read", "arguments": ARGS}]
        assert "outside@example.com" not in json.dumps(c.logs)
    finally:
        c.close()


@pytest.mark.parametrize('meta',[{}, {'progressToken':1}, {'progressToken':'progress'}, {'claudecode/toolUseId':'toolu_test'}, {'progressToken':2,'claudecode/toolUseId':'toolu_test'}])
def test_known_host_correlation_metadata_is_discarded_before_exact_dispatch(meta):
    _,upstream,response,_,_=dispatch({'name':'read','arguments':ARGS,'_meta':meta})
    assert json.loads(upstream)['params']=={'name':'read','arguments':ARGS} and response==b''


@pytest.mark.parametrize('meta',[None, [], {'progressToken':True}, {'progressToken':{}}, {'progressToken':'x'*129}, {'claudecode/toolUseId':1}, {'claudecode/toolUseId':''}, {'claudecode/toolUseId':'x'*129}, {'progressToken':1,'approved':True}])
def test_invalid_or_unknown_metadata_remains_denied(meta):
    _,upstream,response,_,_=dispatch({'name':'read','arguments':ARGS,'_meta':meta})
    assert upstream==b'' and 'error' in json.loads(response)
