import contextlib
import io
import json
import os
import unittest
from unittest.mock import Mock, patch
import urllib.error

# Also proves the repository's legacy entry point exports the same implementation.
from tools.ai_access_client import Client, ClientError
from authcheck_cli.cli import main
from authcheck_cli.workflow import run_plan, wait_run


def response(state='queued', complete=False, count=0):
    return {'ok': True, 'output': {'run': {'run_id': 'run-test', 'status': state},
        'execution_complete': state in {'done', 'failed', 'cancelled'},
        'results_complete': complete, 'total': count}}


class WorkflowTests(unittest.TestCase):
    def test_http_200_empty_results_are_not_completion(self):
        client = Mock()
        client.request.side_effect = [response(), response('done', True, 1)]
        result = wait_run(client, 'run-test', 'project-test', interval=.001)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(client.request.call_count, 2)
        self.assertEqual(result['security_verdict'], 'not_automatically_determined')

    def test_terminal_empty_results_are_incomplete(self):
        client = Mock()
        client.request.return_value = response('done')
        result = wait_run(client, 'run-test')
        self.assertEqual(result['error'], 'run_results_incomplete')
        self.assertEqual(result['exit_code'], 3)

    def test_failure_pause_cancel_do_not_claim_success(self):
        for status in ('failed', 'cancelled', 'paused'):
            client = Mock()
            client.request.return_value = response(status)
            result = wait_run(client, 'run-test')
            self.assertFalse(result['ok'])
            self.assertEqual(result['exit_code'], 4)

    def test_old_server_contract_is_not_guessed(self):
        client = Mock()
        client.request.return_value = {'ok': True, 'output': {'total': 1}}
        with self.assertRaisesRegex(ClientError, 'server_completion_contract_required'):
            wait_run(client, 'run-test')

    def test_timeout_only_reads_existing_run(self):
        client = Mock()
        client.request.return_value = response()
        result = wait_run(client, 'run-test', timeout=.003, interval=.001)
        self.assertEqual(result['error'], 'wait_timeout')
        self.assertTrue(all(c.args[0] == '/api/ai/tools/project.results' for c in client.request.call_args_list))

    def test_network_error_preserves_run_for_resume(self):
        client = Mock()
        client.request.side_effect = ClientError('connection_failed')
        result = wait_run(client, 'run-test')
        self.assertEqual(result['run_id'], 'run-test')
        self.assertEqual(result['exit_code'], 1)

    def test_recover_receipt_without_rechecking_archived_plan(self):
        client = Mock()
        client.request.return_value = {'ok': True, 'call': {'tool': 'project.execute_plan',
            'subject': {'project_id': 'p', 'plan_id': 'plan'}, 'state': 'done',
            'request_id': 'receipt', 'receipt': {'run_id': 'run-test', 'status': 'queued'}}}
        result = run_plan(client, 'plan', 'p', 'synthetic-operation-1', no_wait=True)
        self.assertTrue(result['replayed'])
        self.assertEqual(client.request.call_count, 1)

    def test_pending_and_unknown_never_resubmit(self):
        for state in ('pending', 'unknown', 'failed'):
            client = Mock()
            client.request.return_value = {'ok': True, 'call': {'tool': 'project.execute_plan',
                'subject': {'project_id': 'p', 'plan_id': 'plan'}, 'state': state}}
            result = run_plan(client, 'plan', 'p', 'synthetic-operation-1')
            self.assertEqual(result['exit_code'], 3)
            self.assertEqual(client.request.call_count, 1)

    def test_receipt_conflict_never_resubmits(self):
        client = Mock()
        client.request.return_value = {'ok': True, 'call': {'tool': 'project.execute_plan',
            'subject': {'project_id': 'other', 'plan_id': 'plan'}, 'state': 'done'}}
        with self.assertRaisesRegex(ClientError, 'idempotency_conflict'):
            run_plan(client, 'plan', 'p', 'synthetic-operation-1')
        self.assertEqual(client.request.call_count, 1)

    def test_preflight_block_preserves_reasons_and_does_not_execute(self):
        client = Mock()
        client.request.side_effect = [ClientError('receipt_not_found', 404),
            {'ok': True, 'output': {'status': 'active'}},
            {'ok': True, 'output': {'status': 'blocked', 'blockers': [{'code': 'environment_unavailable'}]}}]
        result = run_plan(client, 'plan', 'p', 'synthetic-operation-1')
        self.assertEqual(result['exit_code'], 2)
        self.assertTrue(result['output']['blockers'])
        self.assertEqual(client.request.call_count, 3)

    def test_missing_receipt_endpoint_does_not_enqueue(self):
        client = Mock()
        client.request.side_effect = ClientError('http_error', 404)
        with self.assertRaises(ClientError):
            run_plan(client, 'plan', 'p', 'synthetic-operation-1')
        self.assertEqual(client.request.call_count, 1)

    def test_generic_call_needs_no_argument_file_or_new_script(self):
        with patch('authcheck_cli.cli.Client') as cls, contextlib.redirect_stdout(io.StringIO()) as out:
            cls.return_value.request.side_effect = [{'ok': True, 'invocation': {'idempotency_required': False}}, {'ok': True}]
            code = main(['call', 'project.plan', '--project', 'p', '--arg', 'plan_id=plan'])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out.getvalue())['ok'])
        self.assertEqual(cls.return_value.request.call_args.args[1], {'arguments': {'project_id': 'p', 'plan_id': 'plan'}})

    def test_error_body_cannot_echo_key(self):
        payload = json.dumps({'error': 'amak_synthetic_secret', 'request_id': 'amak_synthetic_secret',
            'state': 'amak_synthetic_secret'}).encode()
        error = urllib.error.HTTPError('http://localhost', 500, '', {}, io.BytesIO(payload))
        with patch('urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(ClientError) as caught:
                Client('http://localhost', 'synthetic').request('/api/ai/capabilities')
        self.assertEqual(caught.exception.code, 'http_error')
        self.assertEqual(caught.exception.details, {})

    def test_missing_key_does_not_login_or_create_credentials(self):
        with patch.dict(os.environ, {'API_MANAGER_ACCESS_KEY': ''}), patch('urllib.request.build_opener') as opener:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main(['doctor']), 1)
            self.assertEqual(json.loads(out.getvalue())['error'], 'configure_API_MANAGER_ACCESS_KEY')
            opener.assert_not_called()
