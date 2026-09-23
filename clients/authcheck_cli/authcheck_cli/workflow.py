"""Bounded execution and readback, with no business traffic from the client."""
import re
import time

from .client import ClientError, call


def scoped(project_id, **arguments):
    if project_id:
        arguments['project_id'] = project_id
    return arguments


def wait_run(client, run_id, project_id=None, timeout=120, interval=2):
    if timeout <= 0 or not 0 < interval <= 30:
        raise ClientError('invalid_wait_bounds')
    deadline = time.monotonic() + timeout
    latest = None
    while time.monotonic() < deadline:
        try:
            latest = call(client, 'project.results', scoped(project_id, run_id=run_id),
                timeout=max(0.01, min(30, deadline-time.monotonic())))
        except ClientError as exc:
            return {'ok': False, 'error': exc.code, 'status': exc.status, 'run_id': run_id,
                'exit_code': 1, 'next_action': 'Resolve the error, then continue authcheck wait for this run_id.'}
        output = latest.get('output')
        if not isinstance(output, dict) or not isinstance(output.get('run'), dict) or not isinstance(output.get('execution_complete'), bool) or not isinstance(output.get('results_complete'), bool):
            raise ClientError('server_completion_contract_required')
        run = output['run']
        if run.get('run_id') != run_id:
            raise ClientError('run_readback_mismatch')
        state = run.get('status')
        if state not in {'queued', 'running', 'cancel_requested', 'done', 'failed', 'cancelled', 'paused'}:
            raise ClientError('unknown_run_state', details={'run_id': run_id})
        if state in {'failed', 'cancelled', 'paused'}:
            return dict(latest, ok=False, error='run_' + state, run_id=run_id, exit_code=4)
        if output['execution_complete']:
            if state == 'done' and output['results_complete']:
                return dict(latest, ok=True, run_id=run_id, workflow='completed',
                    security_verdict='not_automatically_determined', exit_code=0)
            return dict(latest, ok=False, run_id=run_id, error='run_results_incomplete', exit_code=3)
        remaining = deadline-time.monotonic()
        if remaining > 0:
            time.sleep(min(interval, remaining))
    return {'ok': False, 'error': 'wait_timeout', 'run_id': run_id, 'exit_code': 3,
        'output': latest.get('output') if latest else None,
        'next_action': 'Use authcheck wait with this run_id; do not resubmit execution.'}


def run_plan(client, plan_id, project_id, idem, timeout=120, interval=2, no_wait=False):
    if not re.fullmatch(r'[A-Za-z0-9_-]{16,128}', idem or ''):
        raise ClientError('idempotency_key_required_16_to_128_chars')
    arguments = scoped(project_id, plan_id=plan_id)
    # Recover before preflight: the plan may since be archived. Do not requeue
    # after uncertain delivery or invent a new idempotency key.
    try:
        lookup = client.request('/api/ai/receipt', idem=idem)
    except ClientError as exc:
        if exc.status != 404 or exc.code != 'receipt_not_found':
            raise
        lookup = None
    if lookup is not None:
        receipt = lookup.get('call', {})
        expected = receipt.get('subject') or {}
        if receipt.get('tool') != 'project.execute_plan' or expected.get('plan_id') != plan_id or (project_id and expected.get('project_id') != project_id):
            raise ClientError('idempotency_conflict')
        if receipt.get('state') != 'done':
            return {'ok': False, 'error': 'execution_receipt_' + str(receipt.get('state')),
                'request_id': receipt.get('request_id'), 'exit_code': 3,
                'next_action': 'Inspect authcheck receipt and platform runs; do not retry with a new key.'}
        scheduled = {'ok': True, 'output': receipt.get('receipt'), 'replayed': True,
            'request_id': receipt.get('request_id')}
    else:
        plan = call(client, 'project.plan', arguments).get('output') or {}
        if plan.get('status') != 'active':
            return {'ok': False, 'error': 'plan_not_active', 'exit_code': 2, 'plan_id': plan_id}
        preflight = call(client, 'project.readiness', arguments).get('output') or {}
        if preflight.get('status') != 'preflight_only' or preflight.get('blockers') != []:
            return {'ok': False, 'error': 'readiness_blocked', 'output': preflight, 'exit_code': 2}
        scheduled = call(client, 'project.execute_plan', arguments, idem)
    output = scheduled.get('output') or {}
    run_id = output.get('run_id')
    if not isinstance(run_id, str) or not run_id:
        raise ClientError('execution_receipt_missing_run_id')
    if no_wait:
        return dict(scheduled, workflow='submitted', execution_complete=False, exit_code=0)
    result = wait_run(client, run_id, project_id, timeout, interval)
    result['execution_request_id'] = scheduled.get('request_id')
    result['idempotency_key'] = idem
    return result
