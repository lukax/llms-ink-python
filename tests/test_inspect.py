import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from dataclasses import FrozenInstanceError
import pytest
from llms_ink import Client, InspectionReceipt, LlmsInkError
KEY='lk_'+'a'*32

def receipt(text):
    return dict(detection='no_finding',coverage='complete',recommendation='continue',reason='no_finding',modelRevision='4a43fec65a670e48835d8e8c85c705b4b0d1c907',policyRevision='llms-ink-inspect-1',preprocessingRevision='utf8-json-stringify-1',contentDigest=hashlib.sha256(text.encode()).hexdigest(),inputTokens=5,inspectedTokens=5,windows=1,enforced=False)

@pytest.fixture
def server():
    s=dict(requests=[],status=200,patch={},raw=None)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_POST(self):
            body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            s['requests'].append((self.path,dict(self.headers),body))
            data=receipt(body['content']);data.update(s['patch'])
            self.send_response(s['status']);self.send_header('Content-Type','application/json');self.send_header('Retry-After','42')
            if s['status']==307:self.send_header('Location','/leak')
            self.end_headers();self.wfile.write(s['raw'] if s['raw'] is not None else json.dumps(data).encode())
    http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=http.serve_forever,daemon=True).start()
    s['client']=Client(key=KEY,base_url=f'http://127.0.0.1:{http.server_address[1]}')
    yield s
    http.shutdown();http.server_close()

def test_exact_unicode_receipt(server):
    s=server;text='\ufeff café 🌙\r\n';s['patch']={'secret':'not copied'}
    r=s['client'].inspect(text)
    assert isinstance(r,InspectionReceipt) and r.recommendation=='continue'
    path,headers,body=s['requests'][0]
    assert path=='/api/v0/inspect' and headers['Authorization']==f'Bearer {KEY}'
    assert body==dict(format='text',content=text)
    assert headers['User-Agent'].startswith('llms-ink-python/')
    assert r.content_digest==hashlib.sha256(text.encode()).hexdigest() and not hasattr(r,'secret')
    with pytest.raises(FrozenInstanceError):r.detection='flagged'

@pytest.mark.parametrize('text',['','\ud800','\n'*66000,7])
def test_bad_input_never_sent(server,text):
    with pytest.raises(ValueError):server['client'].inspect(text)
    assert not server['requests']

def test_key_and_transport(monkeypatch):
    monkeypatch.delenv('LLMS_INK_KEY',raising=False)
    with pytest.raises(LlmsInkError):Client().inspect('x')
    with pytest.raises(ValueError):Client(key=KEY,base_url='http://example.com').inspect('x')

@pytest.mark.parametrize('status,patch',[(200,dict(detection='flagged',recommendation='withhold',reason='instruction_pattern')),(422,dict(detection='unknown',coverage='none',recommendation='withhold',reason='token_limit',inputTokens=9000,inspectedTokens=0,windows=0)),(503,dict(detection='unknown',coverage='none',recommendation='withhold',reason='model_failure',inspectedTokens=0,windows=0))])
def test_withhold(server,status,patch):
    server.update(status=status,patch=patch)
    assert server['client'].inspect('x').recommendation=='withhold' and len(server['requests'])==1

@pytest.mark.parametrize('patch',[dict(contentDigest='0'*64),dict(policyRevision='future'),dict(enforced=True),dict(inputTokens=True),dict(inputTokens=9000),dict(coverage='partial'),dict(inspectedTokens=4),dict(windows=0),dict(reason='safe'),dict(recommendation='withhold')])
def test_invalid_receipt(server,patch):
    server['patch']=patch
    with pytest.raises(LlmsInkError):server['client'].inspect('x')

@pytest.mark.parametrize('raw',[b'x'*16385,b'<html>',b'',b'[]',b'null'])
def test_invalid_response(server,raw):
    server['raw']=raw
    with pytest.raises(LlmsInkError):server['client'].inspect('x')

def test_problem_without_retry(server):
    server.update(status=429,raw=b'{"code":"inspection_quota","detail":"Wait."}')
    with pytest.raises(LlmsInkError) as err:server['client'].inspect('x')
    assert err.value.status==429 and err.value.code=='inspection_quota' and err.value.retry_after==42
    assert len(server['requests'])==1

def test_redirect_not_forwarded(server):
    server['status']=307
    with pytest.raises(LlmsInkError):server['client'].inspect('x')
    assert len(server['requests'])==1

def test_environment_origin_ignored(monkeypatch):
    import llms_ink.inspect as module
    monkeypatch.setenv('LLMS_INK_API','https://untrusted.test');seen=[]
    monkeypatch.setattr(module,'inspect_text',lambda text,key,base,timeout:seen.append((base,timeout)))
    Client(key=KEY).inspect('x')
    assert seen==[('https://llms.ink',65.0)]

def test_shared_receipt_conformance():
    from pathlib import Path
    from llms_ink.inspect import _receipt
    cases=json.loads((Path(__file__).parent/'fixtures/inspect-receipts-v1.json').read_text())['cases']
    for c in cases:
        if c['valid']:
            assert _receipt(c['receipt'],c['digest'],c['status']), c['name']
        else:
            with pytest.raises(LlmsInkError): _receipt(c['receipt'],c['digest'],c['status'])
