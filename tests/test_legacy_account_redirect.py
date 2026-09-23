import unittest
from pathlib import Path
from flask import Flask
from apiAnalysis.web import bp_web
from apiAnalysis.model.model import PolicyEnum


class LegacyAccountRedirectTests(unittest.TestCase):
    def test_existing_account_entry_points_use_current_management(self):
        app = Flask(__name__, template_folder=str(Path(__file__).resolve().parents[1] / 'apiAnalysis' / 'templates'))
        app.secret_key = 'synthetic-test'
        app.register_blueprint(bp_web)
        with app.test_client() as client:
            with client.session_transaction() as session:
                session['username'] = 'synthetic-manager'
                session['role'] = [PolicyEnum.MANAGE.value]
            for path in ['/account', '/account-add', '/account/edit/synthetic']:
                with self.subTest(path=path):
                    response = client.get(path)
                    self.assertEqual(response.status_code, 302)
                    self.assertEqual(response.location, '/project-auth')

    def test_anonymous_account_entry_still_requires_login(self):
        app = Flask(__name__)
        app.secret_key = 'synthetic-test'
        app.register_blueprint(bp_web)
        with app.test_client() as client:
            response = client.get('/account')
            self.assertEqual(response.location, '/login')
