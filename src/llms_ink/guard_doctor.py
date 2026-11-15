"""Read-only local checks; no server/model execution, downloads or credential output."""
from __future__ import annotations
import importlib.util
import os
import stat
import sys

from . import __version__
from .guard import MODEL_REVISION, model_dir, verify_assets
from .guard_gateway_config import GatewayConfig
from .guard_review import Snapshot


def diagnose(config_path, owner_file=None):
    checks = []
    def add(name, passed, detail):
        checks.append({'check': name, 'status': 'pass' if passed else 'fail', 'detail': detail})
    supported = sys.platform in {'darwin', 'linux'} and sys.version_info >= (3, 11)
    add('platform', supported, 'Supported platform and Python version.' if supported else 'Requires macOS/Linux and Python 3.11 or newer.')
    dependencies = {name: importlib.util.find_spec(name) is not None for name in ('onnxruntime', 'tokenizers', 'numpy')}
    add('model_dependencies', all(dependencies.values()), 'Optional model dependencies are available; inference was not tested.' if all(dependencies.values()) else 'Install llms-ink[guard] in this Python environment. Missing: ' + ', '.join(name for name, present in dependencies.items() if not present))
    try:
        verify_assets(model_dir()); model_ok = True
    except (OSError, RuntimeError, ValueError): model_ok = False
    add('model_files', model_ok, 'Pinned model files verified.' if model_ok else 'Run llms-ink-guard setup to download/repair the pinned model files.')
    config = None
    try:
        snapshot = Snapshot.read(config_path)
        config = GatewayConfig.from_bytes(snapshot.raw)
        add('configuration', True, 'Owner-controlled configuration parsed; this does not verify tool behavior or executable bytes.')
    except (OSError, ValueError, TypeError, RuntimeError, RecursionError):
        add('configuration', False, 'Use a regular owner-controlled gateway JSON file; run gateway-init for a first configuration.')
    inventory = []
    if config is not None:
        for server in config.servers:
            try:
                info = os.stat(server.command[0])
                available = stat.S_ISREG(info.st_mode) and os.access(server.command[0], os.X_OK)
            except OSError: available = False
            add('executable:' + server.name, available, 'Executable is available; it was not started.' if available else 'Executable is missing or not executable. Review the configured command.')
            inventory.append({'server': server.name, 'tools': [rule.name for rule in server.policy.tools],
                              'exactCalls': sum(len(rule.arguments) for rule in server.policy.tools)})
        add('permitted_calls', any(item['exactCalls'] for item in inventory), 'Only listed exact calls can be permitted; every aggregate call also requires host approval.')
    service = {'status': 'not_checked'}
    if owner_file is not None:
        from .guard_service import control
        try:
            result = control(owner_file, 'status')
            if (result.get('ok') is not True or type(result.get('policySha256')) is not str
                    or type(result.get('sessions')) is not list): raise ValueError('Invalid service status')
            matching = config is not None and result['policySha256'] == config.sha256
            add('running_service', matching, 'The running service pins this configuration.' if matching else 'The service uses another configuration. Stop it, start a new service with the reviewed file, and issue fresh sessions.')
            service = {'status': 'matching' if matching else 'different_configuration'}
        except (OSError, ValueError, TypeError, RuntimeError, RecursionError):
            add('running_service', False, 'Cannot verify the service. Check the private owner file and start service-serve; no session was created or revoked.')
            service = {'status': 'unavailable'}
    else:
        checks.append({'check': 'running_service', 'status': 'not_checked', 'detail': 'Pass --owner-file to compare a running service with this configuration.'})
    return {'version': 1, 'guardVersion': __version__, 'checksPassed': all(c['status'] != 'fail' for c in checks),
            'checks': checks, 'dependencies': dependencies, 'modelRevision': MODEL_REVISION,
            'configurationSha256': config.sha256 if config else None, 'configuredServers': inventory, 'service': service,
            'coverage': {'scope': 'Configured legacy stdio MCP tools routed through a gateway or service only.',
                         'hostConnection': 'not_verified', 'claudeAuthentication': 'not_verified',
                         'nativeHostTools': 'not_covered', 'directRemoteHttpTransport': 'not_supported',
                         'processOrNetworkIsolation': 'not_verified',
                         'toolDefinitionsAndModelExecution': 'not_executed',
                         'note': 'Passing these checks does not establish protection or an active guarded conversation.'}}


def render(report):
    lines = ['Local guard checks']
    for check in report['checks']:
        label = {'pass': 'PASS', 'fail': 'FAIL', 'not_checked': 'NOT CHECKED'}[check['status']]
        lines.append(f"{label}  {check['check']}: {check['detail']}")
    if report['configuredServers']:
        lines.append('\nConfigured scope:')
        for server in report['configuredServers']:
            names = ', '.join(server['tools']) or '(no tools)'
            lines.append(f"  {server['server']}: {names}; exact calls: {server['exactCalls']}")
    lines.extend(['', 'Host connection and Claude authentication are not verified.',
                  'Native host tools are not covered. Container isolation is not verified by doctor; direct remote HTTP transport is unsupported.',
                  'No model or server was started. No session was created or revoked.',
                  'Local checks passed; an active guarded conversation is not established.' if report['checksPassed'] else 'Resolve the failed checks before continuing.'])
    return '\n'.join(lines)
