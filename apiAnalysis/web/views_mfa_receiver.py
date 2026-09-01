"""Authenticated API used by trusted tools to deliver MFA codes."""
import hmac
import os

from flask import jsonify, request

from . import bp_api
from ..tool.mfa_receiver import MfaReceiverError, default_mfa_push_broker


def _configured_token() -> str:
    token = str(os.getenv("API_MANAGER_MFA_RECEIVER_TOKEN", "")).strip()
    return token if len(token) >= 16 else ""


def _authorized() -> bool:
    configured = _configured_token()
    supplied = str(request.headers.get("Authorization") or "")
    if not configured or not supplied.startswith("Bearer "):
        return False
    return hmac.compare_digest(configured, supplied[7:].strip())


def _auth_failure():
    if not _configured_token():
        return jsonify({"error": "mfa_receiver_not_configured"}), 503
    return jsonify({"error": "unauthorized"}), 401


@bp_api.route("/auth/mfa-receiver/pending", methods=["GET"])
def mfa_receiver_pending():
    if not _authorized():
        return _auth_failure()
    receiver_id = str(request.args.get("receiver_id") or "").strip()
    if not receiver_id:
        return jsonify({"error": "receiver_id_required"}), 400
    try:
        pending = default_mfa_push_broker().pending(receiver_id)
    except ValueError:
        return jsonify({"error": "invalid_receiver_id"}), 400
    except MfaReceiverError:
        return jsonify({"error": "mfa_receiver_unavailable"}), 503
    return jsonify({"pending": pending})


@bp_api.route("/auth/mfa-receiver/push", methods=["POST"])
def mfa_receiver_push():
    if not _authorized():
        return _auth_failure()
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "invalid_request"}), 400
    try:
        accepted = default_mfa_push_broker().deliver(
            body.get("transaction_id"), body.get("code"),
        )
    except ValueError:
        return jsonify({"error": "invalid_request"}), 400
    except MfaReceiverError:
        return jsonify({"error": "mfa_receiver_unavailable"}), 503
    if not accepted:
        return jsonify({"error": "transaction_unavailable"}), 404
    return jsonify({"accepted": True}), 202
