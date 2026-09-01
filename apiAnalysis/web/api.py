"""Small Web API surface for session login and asset metadata.

Import, authentication, execution, result writing and finding transitions are
owned by their versioned services.  The retired Workspace/capture/replay API is
deliberately absent instead of remaining as unreachable code.
"""
from flask import jsonify, request, session

from .. import users
from ..common.decorators import login_check, policy_check
from ..common.util import to_json
from ..db.collection import raw_data
from ..model.exception import ApiException
from ..model.model import PolicyEnum, Resp
from . import bp_api


@bp_api.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or not data.get("username") or not data.get("password"):
        raise ApiException("请求格式错误")
    user = users.get(data["username"])
    if not user or user.get("password") != data.get("password"):
        raise ApiException("账号或密码错误")
    session["username"] = data["username"]
    session["role"] = user.get("role")
    return jsonify(Resp(Resp.SUCCESS))


@bp_api.route("/logout")
def logout():
    session.clear()
    return jsonify(Resp(Resp.SUCCESS))


@bp_api.route("/rawdata", methods=["GET"])
@login_check
def rawdata_list():
    query = {}
    if request.args.get("action"):
        query["action"] = request.args["action"]
    if request.args.get("path"):
        query["path__regex"] = request.args["path"]
    hits = raw_data.objects(**query).order_by("-ptah_id").limit(100)
    return jsonify(Resp(Resp.SUCCESS, to_json(hits)))


@bp_api.route("/rawdata/<asset_id>", methods=["PUT"])
@policy_check(PolicyEnum.MANAGE, method="PUT")
def rawdata_update(asset_id):
    data = request.get_json()
    if not data:
        raise ApiException("Incorrect format")
    update_fields = {
        key: data[key]
        for key in ("action", "rule", "des", "tags", "modificator")
        if key in data
    }
    if not update_fields:
        raise ApiException("No valid fields to update")
    asset = raw_data.objects(pk=asset_id).first()
    if not asset:
        raise ApiException("raw_data not found")
    for key, value in update_fields.items():
        setattr(asset, key, value)
    asset.save()
    return jsonify(Resp(Resp.SUCCESS))
