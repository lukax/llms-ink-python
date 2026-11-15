"""Offline MCP example: count supplied text without files or network requests."""
import json
import sys

TOOL = {'name':'text_stats', 'description':'Count characters, words and lines in supplied text.',
    'inputSchema':{'type':'object','properties':{'text':{'type':'string','maxLength':65536}},
                  'required':['text'],'additionalProperties':False}}

while True:
    raw = sys.stdin.buffer.readline(131073)
    if not raw:
        break
    if len(raw) > 131072:
        raise SystemExit(2)
    message = json.loads(raw)
    if 'id' not in message:
        continue
    method, params = message.get('method'), message.get('params', {})
    if method == 'initialize':
        result = {'protocolVersion':params['protocolVersion'], 'capabilities':{'tools':{}},
                  'serverInfo':{'name':'offline-text-example','version':'1'}}
    elif method == 'tools/list':
        result = {'tools':[TOOL]}
    elif method == 'tools/call':
        arguments = params.get('arguments', {})
        if (params.get('name') != 'text_stats' or set(arguments) != {'text'}
                or type(arguments['text']) is not str or len(arguments['text']) > 65536):
            print(json.dumps({'jsonrpc':'2.0','id':message['id'],
                'error':{'code':-32602,'message':'Expected text_stats with bounded text.'}}), flush=True)
            continue
        text = arguments['text']
        counts = {'characters':len(text),'words':len(text.split()),'lines':len(text.splitlines())}
        result = {'content':[{'type':'text','text':json.dumps(counts)}], 'structuredContent':counts}
    else:
        print(json.dumps({'jsonrpc':'2.0','id':message['id'],
            'error':{'code':-32601,'message':'Unsupported method.'}}), flush=True)
        continue
    print(json.dumps({'jsonrpc':'2.0','id':message['id'],'result':result}), flush=True)
