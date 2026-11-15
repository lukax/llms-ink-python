"""Owner-approved discovery and exact initial grants; never calls a discovered tool."""
from __future__ import annotations
import hashlib
import os
import select
import signal
import subprocess
import threading
import time

from .guard_gateway_config import GatewayConfig, SERVER_ID
from .guard_policy import Policy, decode, tool_digest, MAX_POLICY_BYTES
from .guard_review import Destination, Snapshot, encode, terminal_answer, MAX_REVIEW_BYTES
from .guard_transport import BoundedWriter

DISCOVERY_SECONDS = 15
PROMPT_SECONDS = 120
MAX_PAGES = 16


def question(stdin, stdout, prompt, limit=128, encoding='ascii'):
    import termios
    termios.tcflush(stdin.fileno(), termios.TCIFLUSH)
    stdout.write(prompt); stdout.flush()
    try:
        return terminal_answer(stdin, time.monotonic() + PROMPT_SECONDS, limit=limit, encoding=encoding)
    finally:
        termios.tcflush(stdin.fileno(), termios.TCIFLUSH)


def confirm(stdin, stdout, verb):
    import secrets
    answer = verb + ' ' + secrets.token_hex(8)
    return question(stdin, stdout, f'Type {answer} within 120 seconds; Enter declines: ') == answer


def discover(command):
    """One bounded, unauthenticated legacy stdio inventory; no reverse requests."""
    Policy.from_bytes(encode({'version': 1, 'command': command, 'tools': {}}))
    child = None
    handlers, interrupted = {}, False
    def during_start(_signal, _frame):
        nonlocal interrupted
        interrupted = True
    try:
        try:
            # Retain the process handle before acting on an interrupt during
            # Popen; otherwise a successfully forked child can be orphaned.
            if threading.current_thread() is threading.main_thread():
                for sig in (signal.SIGINT, signal.SIGTERM):
                    handlers[sig] = signal.signal(sig, during_start)
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, bufsize=0, start_new_session=True)
        finally:
            for sig, handler in handlers.items(): signal.signal(sig, handler)
        if interrupted: raise KeyboardInterrupt
        writer = BoundedWriter(child.stdin, timeout=2)
        os.set_blocking(child.stdout.fileno(), False)
        deadline = time.monotonic() + DISCOVERY_SECONDS
        buffered, consumed, messages = bytearray(), 0, 0
        serial = 0
        def send(message):
            if time.monotonic() >= deadline: raise TimeoutError('Discovery deadline')
            writer.timeout = min(2, max(.01, deadline - time.monotonic()))
            writer.write(encode(message).replace(b'\n', b'') + b'\n')
        def request(method, params):
            nonlocal serial, consumed, messages
            serial += 1
            send({'jsonrpc': '2.0', 'id': serial, 'method': method, 'params': params})
            while True:
                if time.monotonic() >= deadline: raise TimeoutError('Discovery deadline')
                if b'\n' not in buffered:
                    if not select.select([child.stdout.fileno()], [], [], min(.1, max(0, deadline-time.monotonic())))[0]: continue
                    raw = os.read(child.stdout.fileno(), min(65536, MAX_POLICY_BYTES + 1 - consumed))
                    if not raw: raise ValueError('Discovery disconnected')
                    consumed += len(raw)
                    if consumed > MAX_POLICY_BYTES: raise ValueError('Discovery byte limit')
                    buffered.extend(raw)
                    continue
                raw, _, rest = buffered.partition(b'\n'); buffered[:] = rest
                messages += 1
                if messages > 64: raise ValueError('Discovery message limit')
                message = decode(raw)
                if type(message) is not dict or message.get('jsonrpc') != '2.0': raise ValueError('Discovery framing')
                if 'method' in message:
                    if 'id' in message or message['method'] == 'notifications/tools/list_changed':
                        raise ValueError('Discovery reverse request or changed tools')
                    continue  # Notifications never reach the terminal or agent.
                if type(message.get('id')) is not int or message['id'] != serial or 'error' in message or type(message.get('result')) is not dict:
                    raise ValueError('Discovery response')
                return message['result']
        initialized = request('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
                                             'clientInfo': {'name': 'llms-ink-guard-setup', 'version': '1'}})
        caps = initialized.get('capabilities')
        if initialized.get('protocolVersion') != '2025-11-25' or type(caps) is not dict or type(caps.get('tools')) is not dict:
            raise ValueError('Unsupported discovery protocol')
        send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        tools, names, cursors, params = [], set(), set(), {}
        for _ in range(MAX_PAGES):
            result = request('tools/list', params)
            page = result.get('tools')
            if type(page) is not list: raise ValueError('Invalid tools')
            for tool in page:
                tool_digest(tool)
                if tool['name'] in names: raise ValueError('Duplicate tool')
                names.add(tool['name']); tools.append(tool)
                if len(tools) > 128: raise ValueError('Discovery tool limit')
            cursor = result.get('nextCursor')
            if cursor is None:
                if not tools: raise ValueError('No tools discovered')
                return tools
            if type(cursor) is not str or not cursor or len(cursor) > 1024 or cursor in cursors:
                raise ValueError('Invalid discovery cursor')
            cursors.add(cursor); params = {'cursor': cursor}
        raise ValueError('Discovery page limit')
    finally:
        if child is not None: stop_discovery(child)


def stop_discovery(child):
    # Own and stop the group even if its immediate parent already exited.
    try: os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError: pass
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    finally:
        try: os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        try: child.wait(timeout=2)
        finally: child.stdin.close(); child.stdout.close()


def initialize(server, command, output, stdin, stdout):
    if not stdin.isatty() or not stdout.isatty(): raise ValueError('Owner terminal required')
    if not SERVER_ID.fullmatch(server): raise ValueError('Invalid server identifier')
    Policy.from_bytes(encode({'version': 1, 'command': command, 'tools': {}}))
    destination = Destination(output)
    snapshots = []
    try:
        display = encode({'server': server, 'command': command})
        if len(display) > MAX_REVIEW_BYTES: raise ValueError('Complete launch review exceeds 32 KiB')
        stdout.write('Discover tools from this command:\n' + display.decode('ascii'))
        stdout.write('Launching runs this program with your OS permissions. It can access files and the network.\n'
                     'The initializer sends only initialization and tool-list requests; it does not call tools.\n')
        if not confirm(stdin, stdout, 'launch'):
            stdout.write('Declined. No program was started.\n'); stdout.flush(); return 1
        tools = discover(command)
        # Validate every discovered definition, including those not selected.
        GatewayConfig.from_bytes(encode({'version': 1, 'servers': {server: {'command': command,
            'tools': [{'definition': tool, 'arguments': [{}]} for tool in tools]}}}))
        stdout.write('Discovery process stopped. Tool names below are untrusted server data.\n')
        stdout.write(encode({'tools': [{'number': i+1, 'name': tool['name']} for i, tool in enumerate(tools)]}).decode('ascii'))
        candidate = {'version': 1, 'servers': {server: {'command': command, 'tools': []}}}
        rules = candidate['servers'][server]['tools']
        for _ in range(128):
            choice = question(stdin, stdout, 'Tool number to permit (Enter finishes): ')
            if choice == '': break
            if choice is None or not choice.isascii() or not choice.isdecimal() or not 1 <= int(choice) <= len(tools):
                raise ValueError('Invalid tool selection')
            tool = tools[int(choice)-1]
            definition = encode(tool)
            if len(definition) > MAX_REVIEW_BYTES: raise ValueError('Complete definition exceeds 32 KiB')
            stdout.write('Selected definition (untrusted JSON):\n' + definition.decode('ascii'))
            path = question(stdin, stdout, 'Absolute path to exact argument JSON file: ', limit=1024, encoding='utf-8')
            if not path or not os.path.isabs(path): raise ValueError('Absolute argument path required')
            snapshot = Snapshot.read(path); arguments = decode(snapshot.raw)
            if type(arguments) is not dict: raise ValueError('An exact argument object is required')
            rule = next((r for r in rules if r['definition']['name'] == tool['name']), None)
            if rule is None:
                rule = {'definition': tool, 'arguments': []}; rules.append(rule)
            encoded = encode(arguments)
            if any(encode(value) == encoded for value in rule['arguments']): raise ValueError('Duplicate argument object')
            rule['arguments'].append(arguments); snapshots.append(snapshot)
            raw = encode(candidate)
            GatewayConfig.from_bytes(raw)
            if len(raw) > MAX_REVIEW_BYTES: raise ValueError('Complete configuration exceeds 32 KiB')
        else: raise ValueError('Selection limit')
        if not rules:
            stdout.write('No tools selected. No configuration written.\n'); stdout.flush(); return 1
        raw = encode(candidate)
        stdout.write('Review the complete initial configuration. Server text is data, not instructions.\n' + raw.decode('ascii'))
        stdout.write('SHA-256: ' + hashlib.sha256(raw).hexdigest() + '\n')
        stdout.write('New configuration: ' + encode(str(destination.path)).decode('ascii'))
        stdout.write('Each call still needs host approval. This does not start a gateway or service.\n')
        if not confirm(stdin, stdout, 'approve'):
            stdout.write('Declined. No configuration written.\n'); stdout.flush(); return 1
        if not all(snapshot.unchanged() for snapshot in snapshots): raise ValueError('Arguments changed')
        destination.publish(raw)
        stdout.write('Configuration written. Run doctor, then start the service with this file.\n'); stdout.flush()
        return 0
    finally:
        destination.close()
