import datetime as dt
import os
import json
import subprocess
import sys
from pathlib import Path
import threading
import unittest
import uuid
from unittest.mock import patch
from urllib.parse import urlunsplit

from flask import Flask
from werkzeug.serving import make_server
from mongoengine import connect, disconnect

from apiAnalysis.web import bp_api, bp_web
from apiAnalysis.web import views_ai_access as access
from apiAnalysis.db.ai_access import AiAccessKey, AiAccessCall
from apiAnalysis.db.collection import ApiProject, security_test_plan, security_test_run, security_test_result
from tools.ai_access_client import Client, ClientError, doctor


class AiAccessClientTests(unittest.TestCase):
    def test_origin_and_path_boundaries(self):
        synthetic_user = 'test-user'
        synthetic_password = 'test-password'
        credential_url = urlunsplit(('https', '{}:{}@example.test'.format(
            synthetic_user, synthetic_password), '', '', ''))
        for url in (credential_url, 'http://example.test', 'https://example.test/path'):
            with self.assertRaises(ClientError):
                Client(url, 'synthetic')
        client = Client('http://127.0.0.1:5000', 'synthetic')
        for path in ('https://example.test', '//example.test', '/api/ai/../login', '/api/ai/%2e%2e/login'):
            with self.assertRaises(ClientError):
                client.request(path)

    def test_http_surface_excludes_unmanaged_tools(self):
        for spec in access.registry().list():
            self.assertFalse(spec.shell)
            self.assertFalse(spec.name.startswith(('shell.', 'auth.', 'filesystem.')))


@unittest.skipUnless(os.getenv('RUN_AI_ACCESS_INTEGRATION') == '1', 'isolated Mongo HTTP integration opt-in')
class AiAccessIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from apiAnalysis.conf.secret import mongo_host, mongo_port, mongo_user, mongo_password
        cls.db_name = 'ai_access_test_' + uuid.uuid4().hex
        disconnect()
        cls.mongo = connect(cls.db_name, host=mongo_host, port=mongo_port,
            username=mongo_user, password=mongo_password, serverSelectionTimeoutMS=3000)
        cls.mongo.admin.command('ping')
        cls.app = Flask(__name__, template_folder=str(Path(__file__).resolve().parents[1] / 'apiAnalysis/templates'))
        cls.app.secret_key = 'synthetic-test-secret'
        cls.app.register_blueprint(bp_api)
        cls.app.register_blueprint(bp_web)

    @classmethod
    def tearDownClass(cls):
        assert cls.db_name.startswith('ai_access_test_') and len(cls.db_name) == 47
        cls.mongo.drop_database(cls.db_name)
        disconnect()

    def setUp(self):
        self.owner = 'synthetic-' + uuid.uuid4().hex
        self.users = {self.owner: {'role': ['manage_granted', 'access_granted']}}
        self.patch = patch('apiAnalysis.users', self.users)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.project = 'p-' + uuid.uuid4().hex
        ApiProject(project_id=self.project, name='Synthetic project').save()
        self.key, self.raw = access.issue_key(self.owner, 'Synthetic key', '', 'account', 1)
        self.headers = {'Authorization': 'Bearer ' + self.raw}
        self.client = self.app.test_client()

    def invoke(self, tool, arguments, **headers):
        return self.client.post('/api/ai/tools/' + tool, json={'arguments': arguments}, headers={**self.headers, **headers})

    def test_account_inheritance_and_immediate_downgrade(self):
        catalog = self.client.get('/api/ai/capabilities', headers=self.headers).json
        self.assertEqual(catalog['scope'], 'account')
        self.assertIn('project.execute_plan', [t['name'] for t in catalog['tools']])
        self.users[self.owner]['role'] = ['access_granted']
        catalog = self.client.get('/api/ai/capabilities', headers=self.headers).json
        self.assertNotIn('project.execute_plan', [t['name'] for t in catalog['tools']])
        self.assertEqual(self.invoke('project.execute_plan', {}).status_code, 403)
        self.assertEqual(self.invoke('project.list', {}).status_code, 200)
        self.users.clear()
        self.assertEqual(self.client.get('/api/ai/capabilities', headers=self.headers).status_code, 401)

    def test_hash_only_expiry_revoke_and_browser_separation(self):
        self.assertNotIn(self.raw, str(self.key.to_mongo()))
        self.assertEqual(self.client.get('/api-keys', headers=self.headers).status_code, 302)
        response = self.client.get('/ai?format=markdown', headers=self.headers)
        self.assertNotIn(self.raw, response.text)
        self.key.reload()
        self.assertIsNone(self.key.last_used_at)
        for update in ({'set__expires_at': dt.datetime.utcnow()-dt.timedelta(seconds=1)}, {'set__active': False}):
            self.key.update(set__active=True, set__expires_at=dt.datetime.utcnow()+dt.timedelta(days=1))
            self.key.update(**update)
            response = self.client.get('/api/ai/capabilities', headers=self.headers)
            self.assertEqual(response.status_code, 401)
            self.assertIn('no-store', response.headers['Cache-Control'])

    def test_optional_project_restriction_and_argument_validation(self):
        self.key.update(set__project_id=self.project, set__mode='read_only')
        response = self.invoke('project.list', {})
        self.assertEqual([x['project_id'] for x in response.json['output']['items']], [self.project])
        self.assertEqual(self.invoke('project.runs', {'project_id': 'other'}).status_code, 403)
        self.assertEqual(self.invoke('project.assets', {'page': 'bad'}).status_code, 422)
        self.assertEqual(self.invoke('project.runs', {'raw_command': 'bad'}).status_code, 422)
        self.assertEqual(self.invoke('project.execute_plan', {}).status_code, 403)

    def test_cross_project_plan_rejected_and_no_schedule(self):
        other = 'other-' + uuid.uuid4().hex
        plan = security_test_plan(name='Synthetic', project_id=other, check_type='replay').save()
        with patch('apiAnalysis.tool.test_plan.schedule_plan_execution') as scheduler:
            response = self.invoke('project.execute_plan', {'project_id': self.project, 'plan_id': str(plan.id)},
                **{'Idempotency-Key': uuid.uuid4().hex})
            self.assertEqual(response.status_code, 422)
            scheduler.assert_not_called()

    def test_idempotent_execution_receipt_and_conflict(self):
        idem = uuid.uuid4().hex
        with patch.object(access, 'execute', return_value={'run_id': 'synthetic', 'status': 'queued'}) as execute:
            args = {'project_id': self.project, 'plan_id': 'synthetic'}
            response = self.invoke('project.execute_plan', args, **{'Idempotency-Key': idem})
            self.assertEqual(response.status_code, 200)
            repeat = self.invoke('project.execute_plan', args, **{'Idempotency-Key': idem})
            self.assertTrue(repeat.json['replayed'])
            self.assertEqual(repeat.json['output'], response.json['output'])
            conflict = self.invoke('project.execute_plan', {**args, 'plan_id': 'different'}, **{'Idempotency-Key': idem})
            self.assertEqual(conflict.status_code, 409)
            self.assertEqual(execute.call_count, 1)

    def test_csrf_key_page_and_owner_isolation(self):
        with self.client.session_transaction() as session:
            session['username'] = self.owner
        self.assertEqual(self.client.get('/api-keys').status_code, 200)
        self.assertEqual(self.client.post('/api-keys', data={'action': 'revoke', 'key_id': str(self.key.id)}).status_code, 403)
        # Session login must never authenticate the external AI API.
        self.assertEqual(self.client.get('/api/ai/capabilities').status_code, 401)

    def test_failed_call_does_not_echo_exception_or_retry_write(self):
        idem = uuid.uuid4().hex
        with patch.object(access, 'execute', side_effect=RuntimeError('synthetic-sensitive-value')) as execute:
            args = {'project_id': self.project, 'plan_id': 'synthetic'}
            response = self.invoke('project.execute_plan', args, **{'Idempotency-Key': idem})
            self.assertEqual(response.status_code, 500)
            self.assertNotIn('synthetic-sensitive-value', response.text)
            repeat = self.invoke('project.execute_plan', args, **{'Idempotency-Key': idem})
            self.assertEqual(repeat.status_code, 409)
            self.assertEqual(execute.call_count, 1)

    def test_storage_failure_is_not_success(self):
        from pymongo.errors import ConnectionFailure
        with patch.object(access, 'AiAccessKey') as keys:
            keys.objects.side_effect = ConnectionFailure('synthetic-private-detail')
            response = self.client.get('/api/ai/capabilities', headers=self.headers)
            self.assertEqual(response.status_code, 503)
            self.assertNotIn('synthetic-private-detail', response.text)

    def test_results_distinguish_queued_terminal_empty_and_complete(self):
        run = security_test_run(name='Synthetic completion', project_id=self.project,
            check_type='replay', status='queued', total_cases=1, pending_cases=1).save()
        args = {'project_id': self.project, 'run_id': str(run.id)}
        output = self.invoke('project.results', args).json['output']
        self.assertFalse(output['execution_complete'])
        self.assertFalse(output['results_complete'])
        self.assertEqual(output['total'], 0)
        run.update(set__status='done', set__pending_cases=0, set__completed_cases=1)
        output = self.invoke('project.results', args).json['output']
        self.assertTrue(output['execution_complete'])
        self.assertFalse(output['results_complete'])
        security_test_result(run_id=run.id, project_id=self.project, case_name='Synthetic',
            check_type='replay', verdict='not_evaluable').save()
        output = self.invoke('project.results', args).json['output']
        self.assertTrue(output['results_complete'])
        self.assertEqual(output['not_evaluable'], 1)
        self.assertEqual(self.invoke('project.run', {**args, 'project_id': 'other'}).status_code, 422)

    def test_exact_receipt_is_key_scoped_and_not_limited_to_twenty(self):
        idem = uuid.uuid4().hex
        with patch.object(access, 'execute', return_value={'run_id': 'synthetic', 'status': 'queued'}):
            self.invoke('project.execute_plan', {'project_id': self.project, 'plan_id': 'synthetic'},
                **{'Idempotency-Key': idem})
        for _ in range(21):
            self.invoke('project.list', {})
        receipt = self.client.get('/api/ai/receipt', headers={**self.headers, 'Idempotency-Key': idem})
        self.assertEqual(receipt.status_code, 200)
        self.assertEqual(receipt.json['call']['subject']['plan_id'], 'synthetic')
        _, other_raw = access.issue_key(self.owner, 'Other synthetic', '', 'account', 1)
        response = self.client.get('/api/ai/receipt', headers={'Authorization': 'Bearer '+other_raw, 'Idempotency-Key': idem})
        self.assertEqual(response.status_code, 404)

    def test_installed_cli_run_wait_and_resume_over_real_http(self):
        plan = security_test_plan(name='CLI synthetic lifecycle', project_id=self.project,
            status='active', check_type='replay').save()
        run = security_test_run(name='CLI synthetic run', project_id=self.project,
            check_type='replay', status='queued', total_cases=1, pending_cases=1).save()
        reads = []
        original_results = access.results
        def advance(arguments):
            output = original_results(arguments)
            reads.append(output['run']['status'])
            if len(reads) == 1:
                security_test_result(run_id=run.id, project_id=self.project, case_name='Synthetic CLI',
                    check_type='replay', verdict='not_evaluable').save()
                run.update(set__status='done', set__pending_cases=0, set__completed_cases=1)
            return output
        server = make_server('127.0.0.1', 0, self.app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        env = dict(os.environ, API_MANAGER_URL='http://127.0.0.1:'+str(server.server_port),
            API_MANAGER_ACCESS_KEY=self.raw, PYTHONIOENCODING='utf-8')
        command = [sys.executable, '-m', 'authcheck_cli', 'run', str(plan.id), '--project', self.project,
            '--idempotency-key', uuid.uuid4().hex, '--timeout', '5', '--interval', '.01']
        try:
            with patch.object(access, 'readiness', return_value={'status': 'preflight_only', 'blockers': []}), \
                    patch('apiAnalysis.tool.test_plan.schedule_plan_execution', return_value=(run, True)) as scheduler, \
                    patch.object(access, 'results', side_effect=advance):
                completed = subprocess.run(command, env=env, cwd=str(Path(os.environ.get('TEMP', '.'))),
                    capture_output=True, text=True, encoding='utf-8', timeout=20)
                self.assertEqual(completed.returncode, 0, completed.stdout+completed.stderr)
                self.assertEqual(json.loads(completed.stdout)['workflow'], 'completed')
                self.assertEqual(reads[:2], ['queued', 'done'])
                plan.update(set__status='archived')
                repeated = subprocess.run(command, env=env, capture_output=True, text=True, encoding='utf-8', timeout=20)
                self.assertEqual(repeated.returncode, 0, repeated.stdout+repeated.stderr)
                self.assertEqual(scheduler.call_count, 1)
        finally:
            server.shutdown()
            thread.join(5)
            server.server_close()

    def test_real_http_doctor_reads_back_audited_call(self):
        server = make_server('127.0.0.1', 0, self.app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = doctor(Client('http://127.0.0.1:' + str(server.server_port), self.raw))
            self.assertTrue(result['ok'], result)
            self.assertEqual(len(result['checks']), 6)
            http = Client('http://127.0.0.1:' + str(server.server_port), self.raw)
            created = http.request('/api/ai/tools/project.create_plan', {'arguments': {
                'project_id': self.project, 'name': 'Synthetic HTTP lifecycle', 'check_type': 'replay',
            }}, uuid.uuid4().hex)
            ident = created['output']['plan_id']
            for action, status in [('activate', 'active'), ('archive', 'archived')]:
                args = {'arguments': {'project_id': self.project, 'plan_id': ident}}
                response = http.request('/api/ai/tools/project.' + action + '_plan', args, uuid.uuid4().hex)
                self.assertEqual(response['output']['status'], status)
                readback = http.request('/api/ai/tools/project.plan', args)
                self.assertEqual(readback['output']['status'], status)
            stored = str(list(AiAccessCall.objects(key_id=str(self.key.id)).as_pymongo()))
            self.assertNotIn(self.raw, stored)
            self.assertNotIn('arguments', stored)
        finally:
            server.shutdown()
            thread.join(5)
            server.server_close()
