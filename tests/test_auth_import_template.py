import unittest
from pathlib import Path
from types import SimpleNamespace

from flask import Flask, render_template

from apiAnalysis.web import bp_web


class AuthImportTemplateTests(unittest.TestCase):
    def test_selected_project_renders_all_import_paths_and_literal_secret_hint(self):
        root = Path(__file__).resolve().parents[1] / "apiAnalysis"
        app = Flask(
            __name__,
            template_folder=str(root / "templates"),
            static_folder=str(root / "static"),
        )
        app.secret_key = "auth-import-template-test"
        app.register_blueprint(bp_web)
        with app.test_request_context(
                "/auth-import?project_id=project-1&env_id=test"):
            html = render_template(
                "auth-import.html",
                projects=[SimpleNamespace(
                    project_id="project-1", name="Project 1",
                )],
                project_id="project-1",
                env_id="test",
                environments=[SimpleNamespace(env_id="test", name="Test")],
                notice=None,
                can_manage=True,
                csrf_token="csrf-test-token",
                trusted_code_enabled=True,
                recipe_schema_doc="schema",
                ai_prompt_template="prompt",
            )

        self.assertIn("{{secret.xxx}}", html)
        self.assertEqual(html.count('name="csrf_token"'), 4)
        self.assertIn('name="login_scene"', html)
        self.assertIn('name="role_key"', html)
        self.assertIn('name="login_mode"', html)
        self.assertEqual(html.count('name="tls_verify_present"'), 4)
        self.assertEqual(html.count('name="tls_verify"'), 4)
        self.assertIn('value="import_sso_product"', html)
        self.assertIn('name="product_verification_url"', html)
        self.assertIn('name="realm_client_token"', html)
        self.assertIn("严格校验 TLS 证书", html)
        self.assertIn("showPath(event, 'recipe')", html)


if __name__ == "__main__":
    unittest.main()
