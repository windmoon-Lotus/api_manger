from flask import blueprints

bp_web = blueprints.Blueprint('web', __name__)
bp_api = blueprints.Blueprint('api', __name__, url_prefix="/api")

from . import api
from . import error
from . import views_auth_session
from . import views_misc
from . import views_api_assets
from . import views_data_source
from . import views_execution
from . import views_parameter_workbench
from . import views_auth_profile
from . import views_interface_chains
from . import views_version
from . import views_test_plan
from . import views_review_finding
from . import views_project_v2
from . import views_auth_import
from . import views_mfa_receiver
from . import views_ai_access
