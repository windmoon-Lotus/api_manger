from flask import blueprints

bp_web = blueprints.Blueprint('web', __name__)
bp_api = blueprints.Blueprint('api', __name__, url_prefix="/api")
bp_ws = blueprints.Blueprint('ws', __name__, url_prefix='/ws')

from . import api
from . import error
from . import web
from . import ws
