"""JSON CLI. Use existing Key configuration; never log in or mint credentials."""
import argparse
import json
import os
from pathlib import Path

from . import __version__
from .client import Client, ClientError, call, doctor
from .workflow import run_plan, scoped, wait_run


def parser():
    p = argparse.ArgumentParser(prog='authcheck', description='Use the API testing platform through its existing tools.')
    p.add_argument('--version', action='version', version=__version__)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('doctor', 'capabilities', 'guide', 'calls'):
        sub.add_parser(name)
    sub.add_parser('describe').add_argument('tool')
    generic = sub.add_parser('call', help='Invoke any discovered tool without writing a script')
    generic.add_argument('tool')
    generic.add_argument('--json-file', type=Path)
    generic.add_argument('--arg', action='append', default=[], metavar='NAME=VALUE', help='Repeatable argument; JSON values or plain strings')
    generic.add_argument('--project')
    generic.add_argument('--idempotency-key')
    for name in ('projects', 'plans', 'assets', 'readiness', 'run', 'wait', 'results', 'status'):
        command = sub.add_parser(name)
        if name != 'projects':
            command.add_argument('--project', help='Required for account-wide keys; omit for project-restricted keys')
        if name in {'readiness', 'run'}:
            command.add_argument('plan_id')
        if name in {'wait', 'results', 'status'}:
            command.add_argument('run_id')
        if name in {'run', 'wait'}:
            command.add_argument('--timeout', type=float, default=120, help='Bounded result wait in seconds')
            command.add_argument('--interval', type=float, default=2)
        if name == 'run':
            command.add_argument('--idempotency-key', required=True, help='Keep the same value when retrying the same operation')
            command.add_argument('--no-wait', action='store_true')
        if name in {'projects', 'assets'}:
            command.add_argument('--page', type=int, default=1)
    sub.add_parser('receipt').add_argument('--idempotency-key', required=True)
    return p


def arguments_from(args):
    data = json.loads(args.json_file.read_text(encoding='utf-8-sig')) if args.json_file else {}
    if not isinstance(data, dict):
        raise ClientError('arguments_must_be_object')
    for item in args.arg:
        name, sep, value = item.partition('=')
        if not sep or not name or name in data:
            raise ClientError('invalid_or_duplicate_argument')
        try:
            data[name] = json.loads(value)
        except ValueError:
            data[name] = value
    if args.project:
        if 'project_id' in data and data['project_id'] != args.project:
            raise ClientError('conflicting_project_arguments')
        data['project_id'] = args.project
    return data


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        client = Client(os.getenv('API_MANAGER_URL', 'http://127.0.0.1:5000'), os.getenv('API_MANAGER_ACCESS_KEY', '').strip())
        project = getattr(args, 'project', None)
        command = args.command
        if command in {'run', 'wait'} and (not 0 < args.timeout <= 3600 or not 0 < args.interval <= 30):
            raise ClientError('invalid_wait_bounds')
        if command == 'doctor':
            result = doctor(client)
        elif command in {'capabilities', 'guide', 'calls', 'receipt'}:
            result = client.request('/api/ai/' + command, idem=getattr(args, 'idempotency_key', None))
        elif command == 'describe':
            import re
            if not re.fullmatch(r'[a-zA-Z0-9_.]+', args.tool):
                raise ClientError('invalid_tool_name')
            result = client.request('/api/ai/tools/' + args.tool)
        elif command == 'call':
            data = arguments_from(args)
            # Discover write semantics; never invent an idempotency key for callers.
            import re
            if not re.fullmatch(r'[a-zA-Z0-9_.]+', args.tool):
                raise ClientError('invalid_tool_name')
            detail = client.request('/api/ai/tools/' + args.tool)
            if detail.get('invocation', {}).get('idempotency_required') and not args.idempotency_key:
                raise ClientError('idempotency_key_required_16_to_128_chars')
            result = call(client, args.tool, data, args.idempotency_key)
        elif command == 'run':
            result = run_plan(client, args.plan_id, project, args.idempotency_key, args.timeout, args.interval, args.no_wait)
        elif command == 'wait':
            result = wait_run(client, args.run_id, project, args.timeout, args.interval)
        else:
            tool = {'projects': 'list', 'plans': 'list_plans', 'assets': 'assets',
                'readiness': 'readiness', 'results': 'results', 'status': 'run'}[command]
            data = scoped(project)
            for name in ('page', 'plan_id', 'run_id'):
                if hasattr(args, name):
                    data[name] = getattr(args, name)
            result = call(client, 'project.' + tool, data)
    except ClientError as exc:
        result = {'ok': False, 'error': exc.code, 'status': exc.status, **exc.details}
        if args.command == 'run':
            result['idempotency_key'] = args.idempotency_key
            result['next_action'] = 'Inspect authcheck receipt using this key, or retry the identical command; never replace the key after an uncertain request.'
    except (OSError, ValueError):
        result = {'ok': False, 'error': 'invalid_input_file_or_url'}
    except KeyboardInterrupt:
        result = {'ok': False, 'error': 'interrupted', 'exit_code': 130,
            'next_action': 'Read the existing receipt or run status before retrying.'}
    print(json.dumps(result, ensure_ascii=False))
    return result.get('exit_code', 0 if result['ok'] else 1)
