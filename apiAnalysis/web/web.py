import redis
import time
import json
from urllib.parse import urlencode
from .. import redis_pool
from ..model.exception import *
from ..common.decorators import *
from flask import request, make_response, redirect, url_for, session
from werkzeug.utils import secure_filename
from . import bp_web
from ..core.lib import refresh_session
from ..common.func import is_manager
from ..common.util import get_page, resp_length
from ..conf.conf import *
from ..db.collection import *
from ..rule.privilege import PrivilegeEngine
from ..model.model import PolicyEnum, requests_request
from ..rule.analysis import analysis
from ..db.save import (
    parameter_disassemble_mongodb,
    parameter_date_mongodb,
    data_generate_mongodb,
    data_generate_openapi,
    data_generate_postman,
    format_mongodb_table,
    get_format_table_options,
    get_format_quick_modes,
    resolve_format_targets,
)
from ..tool.compose_request import create_request_snapshot
from ..tool.snapshot_runner import replay_snapshot


def _security_result_triage(row):
    evidence = row.evidence_summary or {}
    manual = evidence.get("manual_review") or {}
    if manual.get("triage"):
        return manual.get("triage")
    judgement = evidence.get("judgement") or {}
    reason = judgement.get("reason") or ""
    text = json.dumps(evidence, ensure_ascii=False, default=str)
    path = ""
    target = row.target or {}
    if isinstance(target, dict):
        path = target.get("path") or target.get("endpoint_name") or ""
    bodies = []
    if isinstance(evidence.get("accounts"), list):
        for account in evidence.get("accounts") or []:
            bodies.append((account.get("result") or {}).get("bodySample"))
    else:
        if isinstance(evidence.get("owner"), dict):
            bodies.append((evidence.get("owner") or {}).get("bodySample"))
        if isinstance(evidence.get("attacker"), dict):
            bodies.append((evidence.get("attacker") or {}).get("bodySample"))

    def _body_text(value):
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        except Exception:
            return str(value)

    def _xml_error(value):
        body_text = _body_text(value)
        if "<category>error</category>" in body_text or "<action>error</action>" in body_text:
            return True
        return any(token in body_text for token in ["AUTH_FAILED", "MISSING_PARAMETERS", "USER_NOT_EXISTS", "API_NOT_IMPLEMENT"])

    def _identity_values(value):
        values = set()

        def _walk(node):
            if isinstance(node, dict):
                for key, child in node.items():
                    if str(key).lower() in {"userid", "user_id", "owner_id"} and child not in [None, "", [], {}]:
                        values.add(str(child))
                    _walk(child)
            elif isinstance(node, list):
                for child in node[:20]:
                    _walk(child)

        _walk(value)
        return values

    if row.verdict == "error":
        return "error_like"
    if "same_business_error" in reason or "xml_error" in reason or "AUTH_FAILED" in text or "API_NOT_IMPLEMENT" in text:
        return "error_like"
    if bodies and all(_xml_error(body) for body in bodies):
        return "error_like"
    if "response_contains_each_account_own_userid" in reason or "identity_values_differ_by_account" in reason:
        return "account_isolated"
    if len(bodies) >= 2:
        body_values = [_identity_values(body) for body in bodies[:2]]
        if body_values[0] and body_values[1] and body_values[0].isdisjoint(body_values[1]):
            return "account_isolated"
    public_hints = [
        "/advertisement/", "/passport/check", "/passport/agree", "/passport/get-regist",
        "/passport/verify", "/passport/alter", "/passport/register", "/passport/login",
        "/passport/reset",
        "/customize/", "/package/", "/mobile/active-module", "/notify/coupon",
        "/upgrade/", "/image/", "/tryout/", "/rongyun/info",
    ]
    if any(hint in path for hint in public_hints):
        return "likely_public_data"
    if len(bodies) >= 2:
        left = _body_text(bodies[0])
        right = _body_text(bodies[1])
        if left == right and len(left) < 800:
            return "likely_public_data"
    if row.verdict == "need_review":
        return "ownership_unclear"
    return ""


def _security_result_summary(row):
    evidence = row.evidence_summary or {}
    target = row.target or {}
    manual = evidence.get("manual_review") or {}
    status_text = []
    if "accounts" in evidence:
        for account in evidence.get("accounts") or []:
            result = account.get("result") or {}
            status_text.append("{}:{} len={}".format(
                account.get("accountIndex"),
                result.get("statusCode"),
                result.get("responseLength"),
            ))
    else:
        owner = evidence.get("owner") or {}
        attacker = evidence.get("attacker") or {}
        if owner or attacker:
            status_text.append("owner:{} len={}".format(owner.get("statusCode"), owner.get("responseLength")))
            status_text.append("attacker:{} len={}".format(attacker.get("statusCode"), attacker.get("responseLength")))
    return {
        "pathid": row.related_pathid or target.get("pathid"),
        "path": target.get("path") or target.get("endpoint_name") or "",
        "statuses": " | ".join(status_text),
        "reason": ",".join(row.reason_codes or []),
        "triage": _security_result_triage(row),
        "manual": manual,
        "fix_status": _code_review_status(row),
        "owner": manual.get("owner") or "",
        "fix_version": manual.get("fix_version") or "",
        "verify_note": manual.get("verify_note") or "",
        "retest_status": manual.get("retest_status") or "",
        "retest_note": manual.get("retest_note") or "",
        "evidence_ref": row.evidence_ref or "",
        "replay_steps": _security_replay_steps(row),
    }


def _security_results_filter_args(form):
    args = {}
    for key in [
        "check_type", "verdict", "triage", "pathid", "priority", "fix_status",
        "code_queue", "include_processed", "include_duplicates", "page", "size"
    ]:
        value = form.get("filter_" + key) or form.get(key)
        if value not in [None, ""]:
            args[key] = value
    return args


def _apply_manual_review(row, form):
    evidence = row.evidence_summary or {}
    manual = evidence.get("manual_review") or {}
    if not isinstance(manual, dict):
        manual = {}
    field_map = {
        "manual_triage": "triage",
        "manual_status": "status",
        "manual_note": "note",
        "fix_status": "fix_status",
        "owner": "owner",
        "fix_version": "fix_version",
        "verify_note": "verify_note",
        "retest_status": "retest_status",
        "retest_note": "retest_note",
    }
    for form_key, manual_key in field_map.items():
        if form_key in form:
            manual[manual_key] = form.get(form_key) or ""
    manual["reviewer"] = session.get("username") or ""
    manual["reviewed_at"] = int(time.time())
    evidence["manual_review"] = manual
    row.evidence_summary = evidence
    row.save()


def _promote_security_result_to_vuln(row, form):
    summary = _security_result_summary(row)
    pathid = summary.get("pathid")
    scenario = form.get("vuln_scenario") or row.check_type or row.case_name or "security_result"
    severity = form.get("vuln_severity") or row.severity or row.priority or "medium"
    status = form.get("vuln_status") or "open"
    result_text = form.get("vuln_result") or ",".join(row.reason_codes or []) or row.verdict
    existing = None
    if pathid is not None:
        existing = vuln_record.objects(pathid=int(pathid), scenario=scenario, status=status).first()
    evidence = {
        "security_result_id": str(row.id),
        "run_id": str(row.run_id),
        "check_type": row.check_type,
        "case_name": row.case_name,
        "verdict": row.verdict,
        "priority": row.priority,
        "reason_codes": row.reason_codes or [],
        "evidence_ref": row.evidence_ref,
        "target": row.target or {},
        "promoted_by": session.get("username") or "",
        "promoted_at": int(time.time()),
    }
    if existing:
        existing.severity = severity
        existing.result = result_text
        existing.evidence = evidence
        existing.save()
        vuln = existing
    else:
        vuln = vuln_record(
            pathid=int(pathid) if pathid is not None else None,
            scenario=scenario,
            severity=severity,
            status=status,
            result=result_text,
            evidence=evidence,
        )
        vuln.save()
    row.related_vuln_id = vuln.id
    evidence_summary = row.evidence_summary or {}
    manual = evidence_summary.get("manual_review") or {}
    if not isinstance(manual, dict):
        manual = {}
    manual["fix_status"] = manual.get("fix_status") or "pending_confirm"
    manual["promoted_vuln_id"] = str(vuln.id)
    manual["reviewer"] = session.get("username") or ""
    manual["reviewed_at"] = int(time.time())
    evidence_summary["manual_review"] = manual
    row.evidence_summary = evidence_summary
    row.save()
    return vuln


def _manual_review(row):
    evidence = row.evidence_summary or {}
    if not isinstance(evidence, dict):
        return {}
    manual = evidence.get("manual_review") or {}
    return manual if isinstance(manual, dict) else {}


def _code_review_status(row):
    manual = _manual_review(row)
    status = manual.get("fix_status") or manual.get("status") or ""
    if status:
        return status
    if row.verdict == "potential_vuln":
        return "pending_confirm"
    if row.verdict == "need_review":
        return "pending_review"
    return ""


ACTIVE_REVIEW_STATUSES = {"pending_confirm", "pending_review", "fixing", "fixed_pending_verify"}
FINAL_REVIEW_STATUSES = {"verified_fixed", "false_positive", "accepted_risk", "done", "ignore"}


def _is_final_review_status(status):
    return status in FINAL_REVIEW_STATUSES


def _is_code_review_candidate(row):
    manual = _manual_review(row)
    status = manual.get("fix_status") or manual.get("status") or ""
    if status in ACTIVE_REVIEW_STATUSES:
        return True
    if status in FINAL_REVIEW_STATUSES:
        return False
    if manual.get("triage") in ["potential_issue", "retest_needed"]:
        return True
    return row.verdict in ["potential_vuln", "need_review"]


def _security_target_path(row):
    target = row.target or {}
    if not isinstance(target, dict):
        return ""
    for key in ["path", "cleanup_path", "endpoint_name"]:
        if target.get(key):
            return str(target.get(key))
    return ""


def _normalize_security_path(path):
    path = (path or "").strip()
    if not path:
        return ""
    parts = [part for part in path.strip("/").split("/") if part]
    while parts and (parts[-1].startswith("{") or parts[-1].isdigit()):
        parts.pop()
    if not parts:
        return path
    return "/" + "/".join(parts)


def _security_result_group_key(row):
    target = row.target or {}
    if not isinstance(target, dict):
        target = {}
    path = _security_target_path(row)
    cleanup_path = target.get("cleanup_path") or ""
    base_path = _normalize_security_path(path) or _normalize_security_path(cleanup_path)
    if not base_path and row.related_pathid is not None:
        base_path = "pathid:{}".format(row.related_pathid)
    check_type = row.check_type or row.case_name or ""
    # Treat create/delete and manual replay rows on the same resource family as
    # one finding so manual retest status can supersede older automated rows.
    if check_type in ["create_delete_authz", "manual_replay_delete_authz"]:
        check_type = "delete_authz"
    return "{}|{}".format(check_type, base_path)


def _is_processed_security_result(row):
    status = _code_review_status(row)
    if _is_final_review_status(status):
        return True
    manual = _manual_review(row)
    if manual.get("triage") == "false_positive":
        return True
    return False


def _dedupe_security_results(rows):
    merged = {}
    for row in rows:
        key = _security_result_group_key(row)
        if key not in merged:
            merged[key] = row
            continue
        current = merged[key]
        current_status = _code_review_status(current)
        row_status = _code_review_status(row)
        if row_status and not current_status:
            merged[key] = row
            continue
        if bool(row.related_vuln_id) and not bool(current.related_vuln_id):
            merged[key] = row
            continue
    return list(merged.values())


def _compact_body_sample(value, limit=1200):
    try:
        text = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    except Exception:
        text = str(value)
    if len(text) > limit:
        return text[:limit] + "\n...<truncated>"
    return text


def _curl_quote(value):
    return str(value).replace("'", "'\"'\"'")


def _guess_replay_method(key, step):
    method = step.get("method") if isinstance(step, dict) else None
    if method:
        return str(method).upper()
    key_lower = key.lower()
    if "delete" in key_lower or "cleanup" in key_lower:
        return "DELETE"
    if "create" in key_lower:
        return "POST"
    if "update" in key_lower or "patch" in key_lower:
        return "PATCH"
    return "GET"


def _build_replay_curl(method, url, body=None):
    lines = [
        "curl -k -i -X {} '{}'".format(method, _curl_quote(url or "<REQUEST_URL>")),
        "  -H 'Authorization: Bearer <CURRENT_TOKEN>'",
        "  -H 'Cookie: <CURRENT_COOKIE>'",
        "  -H 'Accept: application/json, text/plain, */*'",
    ]
    if body not in [None, "", [], {}] and method in ["POST", "PUT", "PATCH"]:
        body_text = json.dumps(body, ensure_ascii=False, separators=(",", ":"), default=str)
        lines.append("  -H 'Content-Type: application/json'")
        lines.append("  --data-raw '{}'".format(_curl_quote(body_text)))
    return " \\\n".join(lines)


def _security_replay_steps(row):
    evidence = row.evidence_summary or {}
    if not isinstance(evidence, dict):
        return []
    labels = [
        ("ownerCreate", "1. owner create", "owner"),
        ("ownerVerifyBeforeDelete", "2. owner GET before", "owner"),
        ("attackerDelete", "3. attacker DELETE", "attacker"),
        ("attackerDeleteWebapiNoEntid", "3a. attacker DELETE webapi no entid", "attacker"),
        ("attackerDeleteApiStdWithEntid", "3b. attacker DELETE api-std with entid", "attacker"),
        ("ownerVerifyAfterDelete", "4. owner GET after", "owner"),
        ("ownerVerifyAfterWebapiNoEntid", "4a. owner GET after webapi test", "owner"),
        ("ownerGetBefore", "owner GET before", "owner"),
        ("ownerGetAfter", "owner GET after", "owner"),
        ("ownerCleanup", "owner cleanup", "owner"),
    ]
    seen = set()
    steps = []
    create_body = evidence.get("body") if isinstance(evidence.get("body"), dict) else None
    direction = evidence.get("direction") or {}
    for key, label, actor in labels:
        step = evidence.get(key)
        if not isinstance(step, dict):
            continue
        seen.add(key)
        url = step.get("url") or step.get("rendered_url") or ""
        method = _guess_replay_method(key, step)
        body = create_body if key == "ownerCreate" else None
        actor_name = actor
        if isinstance(direction, dict):
            if actor == "owner":
                actor_name = direction.get("ownerUsername") or direction.get("owner") or actor
            elif actor == "attacker":
                actor_name = direction.get("attackerUsername") or direction.get("attacker") or actor
        steps.append({
            "key": key,
            "label": label,
            "actor": actor_name,
            "method": method,
            "url": url,
            "status": step.get("statusCode"),
            "contains": step.get("containsResource"),
            "skipped": step.get("skipped") or "",
            "curl": _build_replay_curl(method, url, body),
            "body": _compact_body_sample(body) if body else "",
            "response": _compact_body_sample(step.get("bodySample")),
        })
    # Include any future request-like evidence fields without changing the UI again.
    for key, step in evidence.items():
        if key in seen or not isinstance(step, dict):
            continue
        if not (step.get("url") or step.get("rendered_url") or step.get("statusCode") is not None):
            continue
        method = _guess_replay_method(key, step)
        steps.append({
            "key": key,
            "label": key,
            "actor": "",
            "method": method,
            "url": step.get("url") or step.get("rendered_url") or "",
            "status": step.get("statusCode"),
            "contains": step.get("containsResource"),
            "skipped": step.get("skipped") or "",
            "curl": _build_replay_curl(method, step.get("url") or step.get("rendered_url") or ""),
            "body": "",
            "response": _compact_body_sample(step.get("bodySample")),
        })
    return steps


def _apply_code_review(row, form):
    evidence = row.evidence_summary or {}
    manual = evidence.get("manual_review") or {}
    if not isinstance(manual, dict):
        manual = {}
    for key, form_key in [
        ("fix_status", "fix_status"),
        ("owner", "owner"),
        ("fix_version", "fix_version"),
        ("verify_note", "verify_note"),
    ]:
        value = form.get(form_key)
        if value is not None:
            manual[key] = value
    manual["reviewer"] = session.get("username") or ""
    manual["reviewed_at"] = int(time.time())
    evidence["manual_review"] = manual
    row.evidence_summary = evidence
    row.save()


def _code_review_summary(row):
    summary = _security_result_summary(row)
    manual = _manual_review(row)
    summary.update({
        "fix_status": _code_review_status(row),
        "owner": manual.get("owner") or "",
        "fix_version": manual.get("fix_version") or "",
        "verify_note": manual.get("verify_note") or manual.get("note") or "",
        "evidence_ref": row.evidence_ref or "",
    })
    return summary


@bp_web.route("/favicon.ico")
def favicon():
    """
    favicon
    :return:
    """
    from .. import app_path
    resp = make_response()
    resp.headers['Content-Type'] = 'image/x-icon'
    with open(os.path.join(app_path, "..", "favicon.ico"), "rb") as f:
        resp.set_data(f.read())
    return resp


@bp_web.route("/welcome")
@login_check
@templated("welcome.html")
def welcome():
    rs = redis.Redis(connection_pool=redis_pool)
    statistics = rs.hgetall("statistics")
    if not statistics:
        ws_num = Workspace.objects.count()
        request_num = PacketRecord.objects.count()

        people_set = set()
        depart_set = set()
        system_set = set()
        hosts_set = set()
        for ws in Workspace.objects():
            depart_set.add(ws.depart_name)
            system_set.add(ws.system_name)
            hosts_set.update(ws.hosts)
        for pr in PacketRecord.objects():
            people_set.add(pr.username)

        statistics = {
            "ws_num": ws_num,
            "request_num": request_num,
            "people_num": len(people_set),
            "depart_num": len(depart_set),
            "system_num": len(system_set),
            "hosts_num": len(hosts_set)
        }
        rs.hmset("statistics", statistics)
        rs.expire("statistics", statistics_timeout * 60)
    else:
        statistics = {k.decode('utf-8'): v.decode('utf-8') for k, v in statistics.items()}
    return statistics


@bp_web.route("/login")
@templated("/login.html")
def login():
    pass


@bp_web.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("web.login"))


@bp_web.route("/")
@login_check
@templated("/home.html")
def home():
    pass

@bp_web.route("/report/<_filename>", methods=['GET'])
@login_check
def report(_filename):
    path = os.listdir("app/templates/report")
    if _filename in path:
        file = open("app/templates/report/"+_filename, encoding="utf-8")
        content = file.read()
        return content
    else:
        ret = {"filename"+str(i): path[i] for i in range(0, len(path))}
        return ret


@bp_web.route("/lang/<lang>")
def set_lang(lang):
    if lang in ["zh", "en"]:
        session["lang"] = lang
    nxt = request.args.get("next") or request.referrer or url_for("web.home")
    return redirect(nxt)

@bp_web.route("/workspace/<_id>", methods=['GET', 'POST'])
@login_check
@templated("/workspace-traffic.html")
def workspace_traffic(_id):
    """
    宸ヤ綔绌洪棿鍐呯殑娴侀噺鏄庣粏
    :return:
    """
    banner = ""
    nor_banner = ""
    al = None
    suspect = None
    if request.method == 'POST':
        banner = request.form.get('banner')
        nor_banner = request.form.get('nor_banner')
        al = request.form.get('al')
        suspect = request.form.get('suspect')

    # 姝ゅ涓嶅仛鏉冮檺鏍￠獙锛屽彲鐩存帴閫氳繃杩欎釜宸ヤ綔绌洪棿id鏉ヨ鍙栨暟鎹紝渚夸簬鍒嗕韩
    # if not is_manager():
    #     ws = Workspace.objects(id=_id, cname=session['username'])
    #     if len(ws) == 0:
    #         raise NormalException("娌℃湁鎵惧埌瀵瑰簲宸ヤ綔绌洪棿")

    # 鍒锋柊session
    refresh_session(session.get('username'), _id)

    obj = PacketRecord.objects(ws_id=_id)
    if not al:
        obj = obj.filter(is_delete=False)
    packet_records = obj.order_by('-ctime')

    hits = []
    for pr in packet_records:
        assert isinstance(pr, PacketRecord)

        # raw_packet
        pd = PacketData.objects(id=pr.raw_packet.id,
                                __raw__=PacketData.raw_query(banner, nor_banner))
        if len(pd) == 0:
            pr.raw_packet = None
        else:
            pr.raw_packet = pd[0]

        # per_packets
        pr.per_packets = PacketData.objects(id__in=[i.id for i in pr.per_packets],
                                            __raw__=PacketData.raw_query(banner, nor_banner))
        if not pr.raw_packet or not pr.per_packets:
            continue
        if suspect:  # 鍙睍绀哄彲鐤戠殑璇锋眰
            for pd in pr.per_packets:
                assert isinstance(pd, PacketData)
                if resp_length(pr.raw_packet.banner) == resp_length(pd.banner):
                    hits.append(pr)
                    break
        else:
            hits.append(pr)

    return {
        'banner': banner,
        'nor_banner': nor_banner,
        'workspace_id': _id,
        'packet_records': hits,
        'al': al,
        'suspect': suspect
    }


# =================================== 鈫?宸ヤ綔绌洪棿 鈫?=============================================
@bp_web.route("/workspace", methods=['GET', 'POST'])
@login_check
@templated("/workspace.html")
def workspace():
    page = int(request.args.get('page')) if request.args.get('page') else 0
    size = int(request.args.get('size')) if request.args.get('size') else 50
    form = request.form

    raw = {}
    if form.get('cname'):
        raw['cname'] = form.get('cname')
    if form.get('status'):
        raw['status'] = form.get('status')
    if form.get('depart_name'):
        raw['depart_name'] = {
            '$regex': form.get('depart_name')
        }
    if form.get('system_name'):
        raw['system_name'] = {
            '$regex': form.get('system_name')
        }
    if not is_manager():
        raw['cname'] = session['username']

    objects = Workspace.objects(__raw__=raw).order_by('-ctime')
    count = objects.count()
    hits = objects[page * size: page * size + size]

    return {
        'form': form,
        'page': page,
        'size': size,
        'count': count,
        'hits': hits,
        'hit': get_page(page, size, count)
    }


@bp_web.route("/workspace-create")
@login_check
@templated("/workspace-create.html")
def workspace_create():
    return {
        'source': {}
    }


@bp_web.route("/workspace/<_id>/config")
@login_check
@templated("/workspace-config.html")
def workspace_config(_id):
    return {
        'ws_id': _id
    }


def _normalize_replay_headers(headers):
    result = {}
    if not isinstance(headers, dict):
        return result
    for key, value in headers.items():
        if isinstance(value, list):
            result[key] = value[0] if value else ""
        else:
            result[key] = value
    result.pop("Content-Length", None)
    return result


def _build_replay_body(raw_item, headers):
    if raw_item is None:
        return None, None
    content_type = str(headers.get("Content-Type", headers.get("content-type", ""))).lower()
    if isinstance(raw_item, (dict, list)):
        return raw_item, None
    if isinstance(raw_item, bytes):
        if "application/json" in content_type:
            try:
                return json.loads(raw_item.decode("utf-8", errors="ignore")), None
            except Exception:
                return None, raw_item
        return None, raw_item
    if isinstance(raw_item, str):
        if "application/json" in content_type:
            try:
                return json.loads(raw_item), None
            except Exception:
                return None, raw_item
        return None, raw_item
    return None, raw_item


def _replay_raw_data_once(row):
    assert isinstance(row, raw_data)
    snapshot = create_request_snapshot(row.ptah_id, source="web_replay")
    if not snapshot:
        return {
            "ok": False,
            "status_code": None,
            "expected_codes": row.response_status_code or [],
            "text": "",
            "error": "snapshot not created",
        }
    result = replay_snapshot(snapshot)
    return {
        "ok": result.get("ok"),
        "status_code": result.get("status_code"),
        "expected_codes": result.get("expected_status_codes") or [],
        "text": result.get("text_sample") or "",
        "error": result.get("error") or None,
        "snapshot_id": result.get("snapshot_id"),
    }


@bp_web.route("/rawdata", methods=['GET', 'POST'])
@login_check
@templated("/rawdata.html")
def rawdata():
    page = int(request.args.get('page')) if request.args.get('page') else 0
    size = int(request.args.get('size')) if request.args.get('size') else 50
    form = request.form
    result = ""
    result_level = ""

    if request.method == 'POST':
        op_action = (form.get('op_action') or '').strip()

        if op_action == 'single_update' and form.get('raw_id'):
            raw_id = form.get('raw_id')
            update_fields = {}
            for key in ['action', 'rule', 'des', 'tags', 'modificator']:
                if key in form:
                    update_fields[key] = form.get(key)
            if update_fields:
                obj = raw_data.objects(id=raw_id).first()
                if obj:
                    for key, value in update_fields.items():
                        setattr(obj, key, value)
                    obj.save()
                    result = "单条接口已更新 / Single API updated."
                    result_level = "success"

        elif op_action in ['batch_update', 'batch_replay_verify', 'batch_link_vuln']:
            selected_ids = [i for i in form.getlist('raw_ids') if i]
            if not selected_ids:
                result = "请先勾选接口 / Please select API rows first."
                result_level = "warning"
            else:
                selected_rows = list(raw_data.objects(id__in=selected_ids))
                if op_action == 'batch_update':
                    update_fields = {}
                    batch_map = {
                        'batch_action': 'action',
                        'batch_rule': 'rule',
                        'batch_des': 'des',
                        'batch_tags': 'tags',
                        'batch_modificator': 'modificator',
                    }
                    for form_key, field_key in batch_map.items():
                        value = form.get(form_key)
                        if value is not None and str(value).strip() != "":
                            update_fields[field_key] = value
                    if not update_fields:
                        result = "批量更新未生效：请至少填写一个字段 / Batch update skipped: provide at least one field."
                        result_level = "warning"
                    else:
                        updated_count = 0
                        for row in selected_rows:
                            for key, value in update_fields.items():
                                setattr(row, key, value)
                            row.save()
                            updated_count += 1
                        result = "批量更新完成：{} 条 / Batch update finished: {} APIs.".format(updated_count, updated_count)
                        result_level = "success"

                elif op_action == 'batch_replay_verify':
                    success_count = 0
                    fail_count = 0
                    error_count = 0
                    auto_vuln_on_fail = form.get('auto_vuln_on_fail') == 'on'
                    vuln_created = 0
                    replay_note = (form.get('replay_note') or '').strip()
                    for row in selected_rows:
                        case = test_case.objects(pathid=row.ptah_id, name="auto_replay_{}".format(row.ptah_id)).first()
                        if not case:
                            case = test_case(name="auto_replay_{}".format(row.ptah_id), pathid=row.ptah_id)
                        case.save()

                        replay = _replay_raw_data_once(row)
                        snapshot = request_snapshot.objects(id=replay.get("snapshot_id")).first() if replay.get("snapshot_id") else None
                        if snapshot:
                            case.method = snapshot.method
                            case.url = snapshot.url
                            case.headers = snapshot.headers or {}
                            case.body = snapshot.body
                            case.expected = {
                                "status_codes": snapshot.expected_status_codes or [],
                                "note": replay_note or "from interface manager",
                                "snapshot_id": str(snapshot.id),
                            }
                            case.save()
                        if replay.get("error"):
                            error_count += 1
                        elif replay.get("ok"):
                            success_count += 1
                        else:
                            fail_count += 1
                            if auto_vuln_on_fail:
                                scenario = form.get('replay_fail_scenario') or "replay_verify"
                                exists = vuln_record.objects(pathid=row.ptah_id, scenario=scenario, status="open").first()
                                if not exists:
                                    vuln_record(
                                        pathid=row.ptah_id,
                                        scenario=scenario,
                                        severity=form.get('replay_fail_severity') or "medium",
                                        status="open",
                                        result="replay status mismatch: got {}, expect {}".format(
                                            replay.get("status_code"),
                                            replay.get("expected_codes"),
                                        ),
                                        evidence={
                                            "method": row.method,
                                            "path": row.path,
                                            "url": row.url,
                                            "replay": replay,
                                        }
                                    ).save()
                                    vuln_created += 1
                    result = "重放验证完成：成功 {} 失败 {} 异常 {} 新增漏洞 {} / Replay done: success {}, fail {}, error {}, vuln {}.".format(
                        success_count, fail_count, error_count, vuln_created,
                        success_count, fail_count, error_count, vuln_created
                    )
                    result_level = "success" if fail_count == 0 and error_count == 0 else "warning"

                elif op_action == 'batch_link_vuln':
                    scenario = (form.get('vuln_scenario') or 'manual_link').strip()
                    severity = (form.get('vuln_severity') or 'medium').strip()
                    status = (form.get('vuln_status') or 'open').strip()
                    vuln_result = (form.get('vuln_result') or 'linked from interface manager').strip()
                    created = 0
                    skipped = 0
                    for row in selected_rows:
                        exists = vuln_record.objects(pathid=row.ptah_id, scenario=scenario, status=status).first()
                        if exists:
                            skipped += 1
                            continue
                        vuln_record(
                            pathid=row.ptah_id,
                            scenario=scenario,
                            severity=severity,
                            status=status,
                            result=vuln_result,
                            evidence={
                                "raw_id": str(row.id),
                                "method": row.method,
                                "path": row.path,
                                "url": row.url,
                                "action": row.action,
                            }
                        ).save()
                        created += 1
                    result = "漏洞挂钩完成：新增 {} 跳过 {} / Vulnerability linking finished: created {}, skipped {}.".format(
                        created, skipped, created, skipped
                    )
                    result_level = "success"

    raw = {}
    if form.get('filter_action'):
        raw['action'] = form.get('filter_action')
    if form.get('filter_path'):
        raw['path__regex'] = form.get('filter_path')
    objects = raw_data.objects(__raw__=raw).order_by('-ptah_id')
    count = objects.count()
    hits = objects[page * size: page * size + size]

    return {
        'form': form,
        'page': page,
        'size': size,
        'count': count,
        'hits': hits,
        'hit': get_page(page, size, count),
        'result': result,
        'result_level': result_level,
    }


@bp_web.route("/import-data", methods=['GET', 'POST'])
@login_check
@templated("/import_data.html")
def import_data():
    form = request.form
    result = ""
    result_level = ""
    accounts = SsoAccount.objects()
    stats = {
        "raw_count": raw_data.objects.count(),
        "relation_count": parameter_relation.objects.count(),
        "task_init_count": privilege_task.objects(status=privilege_task.STATUS_INIT).count(),
    }
    if request.method == 'POST':
        fmt = (form.get('format') or '').strip()
        source_file = request.files.get('source_file')
        if not source_file or not source_file.filename:
            result = "请选择上传文件 / Please choose a file to upload."
            result_level = "warning"
        elif fmt not in ['har', 'openapi', 'postman']:
            result = "请选择正确导入格式（HAR/OpenAPI/Postman） / Please choose a valid import format."
            result_level = "warning"
        else:
            t0 = time.perf_counter()
            upload_dir = os.path.join(os.path.dirname(__file__), "uploads")
            os.makedirs(upload_dir, exist_ok=True)
            safe_name = secure_filename(source_file.filename)
            if not safe_name:
                safe_name = "import_{}.dat".format(int(time.time()))
            saved_path = os.path.join(upload_dir, "{}_{}".format(int(time.time()), safe_name))
            source_file.save(saved_path)

            try:
                if fmt == 'har':
                    data_generate_mongodb(saved_path, "har")
                elif fmt == 'openapi':
                    data_generate_openapi(saved_path)
                elif fmt == 'postman':
                    data_generate_postman(saved_path)

                call = analysis()
                call.classify_raw_data()

                selected_account = form.get('account_select') or form.get('account_id') or None
                if form.get('run_param') == 'on':
                    parameter_disassemble_mongodb()
                    parameter_date_mongodb()
                    call.parameter_archive(account_id=selected_account)
                    call.infer_weak_relations()
                    call.verify_weak_relations()
                    call.build_request_compose()

                if form.get('prepare_tasks') == 'on':
                    call.prepare_privilege_tasks()

                cost = round(time.perf_counter() - t0, 2)
                result = "导入成功：{}，格式 {}，耗时 {}s / Import success: {}, format {}, cost {}s".format(
                    safe_name, fmt, cost, safe_name, fmt, cost
                )
                result_level = "success"
            except Exception as e:
                result = "瀵煎叆澶辫触锛歿}".format(str(e))
                result_level = "error"

            stats = {
                "raw_count": raw_data.objects.count(),
                "relation_count": parameter_relation.objects.count(),
                "task_init_count": privilege_task.objects(status=privilege_task.STATUS_INIT).count(),
            }

    return {
        "form": form,
        "result": result,
        "result_level": result_level,
        "stats": stats,
        "accounts": accounts,
    }


@bp_web.route("/ops", methods=['GET', 'POST'])
@login_check
@templated("/op_flow.html")
def ops_panel():
    result = ""
    result_level = ""
    last_action = ""
    form = request.form
    accounts = SsoAccount.objects()
    stats = {
        "raw_count": raw_data.objects.count(),
        "relation_count": parameter_relation.objects.count(),
        "task_init_count": privilege_task.objects(status=privilege_task.STATUS_INIT).count(),
        "task_done_count": privilege_task.objects(status=privilege_task.STATUS_DONE).count(),
        "task_skip_count": privilege_task.objects(status=privilege_task.STATUS_SKIP).count(),
        "vuln_count": vuln_record.objects.count(),
    }
    if request.method == 'POST':
        action = form.get('action')
        last_action = action or ""
        call = analysis()
        t0 = time.perf_counter()
        try:
            def _as_bool(name, default=False, present_name=None):
                value = form.get(name)
                if present_name and form.get(present_name) and value is None:
                    return False
                if value is None:
                    return default
                return str(value).lower() in ['1', 'true', 'on', 'yes']

            if action == 'run_recommended':
                selected_account = form.get('account_select') or form.get('account_id') or None
                call.classify_raw_data()
                parameter_disassemble_mongodb()
                parameter_date_mongodb()
                call.parameter_archive(account_id=selected_account)
                call.infer_weak_relations()
                call.verify_weak_relations()
                call.build_request_compose()
                call.prepare_privilege_tasks()
                result = "推荐流程完成：分类 -> 关联 -> 组合请求 -> 越权任务 / Recommended flow finished."
            elif action == 'classify_raw':
                call.classify_raw_data()
                result = "接口分类完成 / API classification finished."
            elif action == 'rebuild_params':
                selected_account = form.get('account_select') or form.get('account_id') or None
                parameter_disassemble_mongodb()
                parameter_date_mongodb()
                call.parameter_archive(account_id=selected_account)
                call.infer_weak_relations()
                call.verify_weak_relations()
                call.build_request_compose()
                result = "参数重建与关联推断完成 / Parameter rebuild and relation inference finished."
            elif action == 'infer_relations':
                infer_min_overlap = form.get('infer_min_overlap') or 1
                summary = call.infer_weak_relations(
                    enable_value_intersection=_as_bool(
                        'infer_enable_value_intersection',
                        True,
                        present_name='infer_enable_value_intersection_present'
                    ),
                    min_overlap_count=infer_min_overlap,
                    enable_name_fallback=_as_bool('infer_enable_name_fallback', False),
                    fallback_parameter_names=form.get('infer_fallback_parameter_names') or "",
                    enable_same_path_not_equal=_as_bool(
                        'infer_enable_same_path_not_equal',
                        True,
                        present_name='infer_enable_same_path_not_equal_present'
                    ),
                )
                result = (
                    "弱关联推断完成 / Weak relation inference done: value_intersection={}, min_overlap={}, "
                    "name_fallback={}, same_path_not_equal={}, candidates(total/accepted/skipped)={}/{}/{}"
                ).format(
                    _as_bool(
                        'infer_enable_value_intersection',
                        True,
                        present_name='infer_enable_value_intersection_present'
                    ),
                    infer_min_overlap,
                    _as_bool('infer_enable_name_fallback', False),
                    _as_bool(
                        'infer_enable_same_path_not_equal',
                        True,
                        present_name='infer_enable_same_path_not_equal_present'
                    ),
                    (summary or {}).get("total_candidates", 0),
                    (summary or {}).get("accepted_candidates", 0),
                    (summary or {}).get("skipped_low_score", 0),
                )
            elif action == 'verify_relations':
                call.verify_weak_relations()
                result = "启发式弱关联验证完成 / Heuristic weak-relation verification finished."
            elif action == 'verify_relations_real':
                verify_limit = int(form.get('verify_limit') or 200)
                verify_min_score = float(form.get('verify_min_score') or 60.0)
                summary = call.verify_weak_relations_real(limit=verify_limit, min_score=verify_min_score)
                result = (
                    "真实重放验证完成 / Real replay verification finished: "
                    "processed={processed}, verified={verified}, skipped={skipped}, "
                    "limit={limit}, min_score={min_score}"
                ).format(**(summary or {
                    "processed": 0, "verified": 0, "skipped": 0,
                    "limit": verify_limit, "min_score": verify_min_score
                }))
            elif action == 'prepare_privilege_tasks':
                call.prepare_privilege_tasks()
                result = "越权任务已生成 / Privilege tasks prepared."
            elif action == 'format_rawdata':
                table_name = (form.get('format_table') or 'raw_data').strip()
                quick_mode = (form.get('format_quick_mode') or 'custom').strip()
                targets = resolve_format_targets(
                    table_name=table_name,
                    quick_mode=quick_mode,
                    manual_targets=form.getlist('format_targets'),
                )
                path_regex = (form.get('format_path_regex') or '').strip() or None
                action_filter = (form.get('format_action_filter') or '').strip() or None
                format_limit = int(form.get('format_limit') or 0)
                dry_run = form.get('format_dry_run') == 'on'
                summary = format_mongodb_table(
                    table_name=table_name,
                    targets=targets,
                    path_regex=path_regex,
                    action=action_filter,
                    limit=format_limit,
                    dry_run=dry_run,
                )
                summary["quick_mode"] = quick_mode
                result = (
                    "format complete: table={table}, scanned={scanned}, updated={updated}, "
                    "dry_run={dry_run}, quick_mode={quick_mode}, "
                    "targets={targets}, changed_fields={changed_fields}"
                ).format(**summary)
            elif action == 'exec_privilege':
                limit = int(form.get('limit') or 20)
                call.execute_privilege_tasks(limit=limit)
                result = "越权任务执行完成（limit={}） / Privilege task execution finished (limit={}).".format(limit, limit)
            elif action == 'exec_ai_stub':
                limit = int(form.get('limit') or 20)
                call.execute_ai_stub(limit=limit)
                result = "AI 本地判定完成（limit={}） / AI stub execution finished (limit={}).".format(limit, limit)
            elif action == 'exec_ai_http':
                limit = int(form.get('limit') or 20)
                ai_url = form.get('ai_url') or None
                ai_key = form.get('ai_key') or None
                call.execute_ai_http(limit=limit, url=ai_url, api_key=ai_key)
                result = "AI HTTP 判定完成（limit={}） / AI HTTP execution finished (limit={}).".format(limit, limit)
            else:
                result = "未知操作，请刷新重试 / Unknown action, please refresh and try again."
                result_level = "warning"
            if not result_level:
                result_level = "success"
        except Exception as e:
            result = "鎵ц澶辫触锛歿}".format(str(e))
            result_level = "error"
        cost = round(time.perf_counter() - t0, 2)
        result = "{}（耗时 {}s）".format(result, cost)
        stats = {
            "raw_count": raw_data.objects.count(),
            "relation_count": parameter_relation.objects.count(),
            "task_init_count": privilege_task.objects(status=privilege_task.STATUS_INIT).count(),
            "task_done_count": privilege_task.objects(status=privilege_task.STATUS_DONE).count(),
            "task_skip_count": privilege_task.objects(status=privilege_task.STATUS_SKIP).count(),
            "vuln_count": vuln_record.objects.count(),
        }

    return {
        'form': form,
        'result': result,
        'result_level': result_level,
        'last_action': last_action,
        'stats': stats,
        'accounts': accounts,
        'format_table_options': get_format_table_options(),
        'format_quick_modes': get_format_quick_modes(),
    }


@bp_web.route("/parameter-relations", methods=['GET'])
@login_check
@templated("/parameter-relations.html")
def parameter_relations():
    page = int(request.args.get('page')) if request.args.get('page') else 0
    size = int(request.args.get('size')) if request.args.get('size') else 50
    form = request.args
    raw = {}
    if form.get('parameter'):
        raw['parameter__regex'] = form.get('parameter')
    if form.get('relation'):
        raw['relation'] = form.get('relation')
    if form.get('verified'):
        raw['verified'] = form.get('verified') == 'true'
    objects = parameter_relation.objects(__raw__=raw).order_by('-id')
    count = objects.count()
    hits = objects[page * size: page * size + size]
    return {
        'form': form,
        'page': page,
        'size': size,
        'count': count,
        'hits': hits,
        'hit': get_page(page, size, count)
    }


@bp_web.route("/privilege-tasks", methods=['GET', 'POST'])
@login_check
@templated("/privilege-tasks.html")
def privilege_tasks():
    page = int(request.args.get('page')) if request.args.get('page') else 0
    size = int(request.args.get('size')) if request.args.get('size') else 50
    form = request.form if request.method == 'POST' else request.args

    if request.method == 'POST':
        if form.get('action') == 'run_pending':
            limit = int(form.get('limit') or 20)
            PrivilegeEngine().execute_pending(limit=limit)
        if form.get('action') == 'run_ai_pending':
            limit = int(form.get('limit') or 20)
            PrivilegeEngine().execute_ai_stub(limit=limit)
        if form.get('task_id'):
            task = privilege_task.objects(id=form.get('task_id')).first()
            if task:
                PrivilegeEngine().execute_task(task)
        if form.get('action') == 'run_ai' and form.get('task_id'):
            task = privilege_task.objects(id=form.get('task_id')).first()
            if task:
                PrivilegeEngine()._apply_ai_stub(task)
        if form.get('config_ws_id'):
            ws_id = form.get('config_ws_id')
            scenario = form.get('config_scenario')
            account_id = form.get('config_account_id')
            baseline_account_id = form.get('config_baseline_account_id')
            auth_describe = form.get('config_auth_describe')
            if ws_id and scenario:
                cfg = privilege_config.objects(ws_id=ws_id, scenario=scenario).first()
                if not cfg:
                    cfg = privilege_config(ws_id=ws_id, scenario=scenario)
                cfg.account_id = account_id
                cfg.baseline_account_id = baseline_account_id
                cfg.auth_describe = auth_describe
                cfg.enabled = True
                cfg.save()

    raw = {}
    if form.get('scenario'):
        raw['scenario'] = form.get('scenario')
    if form.get('status'):
        raw['status'] = form.get('status')
    if form.get('result'):
        raw['result'] = form.get('result')
    if form.get('final_result'):
        raw['final_result'] = form.get('final_result')
    if form.get('ai_result'):
        raw['ai_result'] = form.get('ai_result')
    if form.get('pathid'):
        try:
            raw['pathid'] = int(form.get('pathid'))
        except Exception:
            pass

    sort = (form.get('sort') or 'id_desc').strip()
    objects = privilege_task.objects(__raw__=raw)
    if sort == 'final_score_desc':
        objects = objects.order_by('-final_score', '-id')
    elif sort == 'rule_score_desc':
        objects = objects.order_by('-rule_score', '-id')
    elif sort == 'ai_score_desc':
        objects = objects.order_by('-ai_score', '-id')
    else:
        objects = objects.order_by('-id')
    count = objects.count()
    hits = objects[page * size: page * size + size]

    stats = {
        "status_init": privilege_task.objects(status=privilege_task.STATUS_INIT).count(),
        "status_done": privilege_task.objects(status=privilege_task.STATUS_DONE).count(),
        "status_skip": privilege_task.objects(status=privilege_task.STATUS_SKIP).count(),
        "final_potential_vuln": privilege_task.objects(final_result="potential_vuln").count(),
        "final_need_review": privilege_task.objects(final_result="need_review").count(),
        "final_no_vuln": privilege_task.objects(final_result="no_vuln").count(),
    }
    return {
        'form': form,
        'page': page,
        'size': size,
        'count': count,
        'hits': hits,
        'hit': get_page(page, size, count),
        'configs': privilege_config.objects(),
        'accounts': SsoAccount.objects(),
        'stats': stats,
    }


@bp_web.route("/vuln", methods=['GET', 'POST'])
@login_check
@templated("/vuln.html")
def vuln_list_web():
    page = int(request.args.get('page')) if request.args.get('page') else 0
    size = int(request.args.get('size')) if request.args.get('size') else 50
    form = request.form if request.method == 'POST' else request.args
    if request.method == 'POST' and form.get('vuln_id'):
        v = vuln_record.objects(id=form.get('vuln_id')).first()
        if v:
            if form.get('scenario') is not None:
                v.scenario = form.get('scenario')
            if form.get('severity') is not None:
                v.severity = form.get('severity')
            if form.get('status') is not None:
                v.status = form.get('status') or v.status
            if form.get('result') is not None:
                v.result = form.get('result')
            v.save()
    elif request.method == 'POST' and form.get('pathid'):
        v = vuln_record(pathid=int(form.get('pathid')),
                        scenario=form.get('scenario'),
                        severity=form.get('severity'),
                        status=form.get('status') or "open",
                        result=form.get('result'),
                        evidence={})
        v.save()
    raw = {}
    if form.get('scenario'):
        raw['scenario'] = form.get('scenario')
    if form.get('status'):
        raw['status'] = form.get('status')
    if form.get('pathid'):
        try:
            raw['pathid'] = int(form.get('pathid'))
        except Exception:
            pass
    objects = vuln_record.objects(__raw__=raw).order_by('-ctime')
    count = objects.count()
    hits = objects[page * size: page * size + size]
    return {
        'form': form,
        'page': page,
        'size': size,
        'count': count,
        'hits': hits,
        'hit': get_page(page, size, count)
    }


@bp_web.route("/security-results", methods=['GET', 'POST'])
@login_check
@templated("/security-results.html")
def security_results_web():
    page = int(request.args.get('page')) if request.args.get('page') else 0
    size = int(request.args.get('size')) if request.args.get('size') else 30
    form = request.form if request.method == 'POST' else request.args
    result = ""
    result_level = ""

    if request.args.get("saved"):
        result = "人工处置已保存 {} 条 / Manual review saved.".format(request.args.get("saved"))
        result_level = "success"

    if request.method == 'POST':
        updated = 0
        action = form.get("action") or "single_review"
        if action == "batch_review":
            for result_id in form.getlist("result_ids"):
                row = security_test_result.objects(id=result_id).first()
                if row:
                    _apply_manual_review(row, form)
                    updated += 1
        elif action == "batch_promote_vuln":
            for result_id in form.getlist("result_ids"):
                row = security_test_result.objects(id=result_id).first()
                if row:
                    _apply_manual_review(row, form)
                    _promote_security_result_to_vuln(row, form)
                    updated += 1
        elif action == "promote_vuln" and form.get("result_id"):
            row = security_test_result.objects(id=form.get("result_id")).first()
            if row:
                _apply_manual_review(row, form)
                _promote_security_result_to_vuln(row, form)
                updated += 1
        elif form.get("result_id"):
            row = security_test_result.objects(id=form.get("result_id")).first()
            if row:
                _apply_manual_review(row, form)
                updated += 1
        if updated:
            args = _security_results_filter_args(form)
            args["saved"] = str(updated)
            return redirect(url_for("web.security_results_web", **args))
        args = _security_results_filter_args(form)
        args["saved"] = "0"
        return redirect(url_for("web.security_results_web", **args))

    raw = {}
    if form.get("check_type"):
        raw["check_type"] = form.get("check_type")
    if form.get("verdict"):
        raw["verdict"] = form.get("verdict")
    if form.get("priority"):
        raw["priority"] = form.get("priority")
    if form.get("pathid"):
        try:
            raw["related_pathid"] = int(form.get("pathid"))
        except Exception:
            pass
    objects = security_test_result.objects(__raw__=raw).order_by("-ctime")
    filtered_rows = None
    triage_filter = form.get("triage") or ""
    if triage_filter:
        filtered_rows = [row for row in objects if _security_result_triage(row) == triage_filter]
    if form.get("code_queue"):
        source_rows = filtered_rows if filtered_rows is not None else list(objects)
        filtered_rows = [row for row in source_rows if _is_code_review_candidate(row)]
    if form.get("fix_status"):
        source_rows = filtered_rows if filtered_rows is not None else list(objects)
        filtered_rows = [row for row in source_rows if _code_review_status(row) == form.get("fix_status")]
    if not form.get("include_processed") and not form.get("fix_status"):
        source_rows = filtered_rows if filtered_rows is not None else list(objects)
        filtered_rows = [row for row in source_rows if not _is_processed_security_result(row)]
    if not form.get("include_duplicates"):
        source_rows = filtered_rows if filtered_rows is not None else list(objects)
        filtered_rows = _dedupe_security_results(source_rows)
    if filtered_rows is not None:
        all_count = len(filtered_rows)
        hits = filtered_rows[page * size: page * size + size]
    else:
        all_count = objects.count()
        rows = list(objects[: max((page + 1) * size, size)])
        hits = rows[page * size: page * size + size]

    stats = {
        "total": security_test_result.objects.count(),
        "need_review": security_test_result.objects(verdict="need_review").count(),
        "potential_vuln": security_test_result.objects(verdict="potential_vuln").count(),
        "no_vuln": security_test_result.objects(verdict="no_vuln").count(),
        "not_evaluable": security_test_result.objects(verdict="not_evaluable").count(),
        "error": security_test_result.objects(verdict="error").count(),
    }
    code_candidates = [
        row for row in _dedupe_security_results(security_test_result.objects().order_by("-ctime"))
        if _is_code_review_candidate(row) and not _is_processed_security_result(row)
    ]
    stats["code_queue"] = len(code_candidates)
    for key in ["pending_confirm", "pending_review", "fixing", "fixed_pending_verify", "verified_fixed", "false_positive", "accepted_risk"]:
        stats["fix_" + key] = len([row for row in code_candidates if _code_review_status(row) == key])
    summaries = {str(row.id): _security_result_summary(row) for row in hits}
    return {
        "form": form,
        "page": page,
        "size": size,
        "count": all_count,
        "hits": hits,
        "hit": get_page(page, size, all_count),
        "stats": stats,
        "summaries": summaries,
        "result": result,
        "result_level": result_level,
    }


@bp_web.route("/code-review", methods=['GET', 'POST'])
@login_check
def code_review_web():
    args = dict(request.args)
    args["code_queue"] = args.get("code_queue") or "1"
    return redirect(url_for("web.security_results_web", **args))


@bp_web.route("/version", methods=['GET', 'POST'])
@login_check
@templated("/version.html")
def version_list_web():
    page = int(request.args.get('page')) if request.args.get('page') else 0
    size = int(request.args.get('size')) if request.args.get('size') else 50
    form = request.form if request.method == 'POST' else request.args
    if request.method == 'POST' and form.get('name') and form.get('version'):
        v = api_version(name=form.get('name'), version=form.get('version'), base_url=form.get('base_url'))
        v.save()
    objects = api_version.objects().order_by('-ctime')
    count = objects.count()
    hits = objects[page * size: page * size + size]
    return {
        'form': form,
        'page': page,
        'size': size,
        'count': count,
        'hits': hits,
        'hit': get_page(page, size, count)
    }


@bp_web.route("/testcase", methods=['GET', 'POST'])
@login_check
@templated("/testcase.html")
def testcase_list_web():
    page = int(request.args.get('page')) if request.args.get('page') else 0
    size = int(request.args.get('size')) if request.args.get('size') else 50
    form = request.form if request.method == 'POST' else request.args
    if request.method == 'POST' and form.get('name'):
        t = test_case(name=form.get('name'),
                      pathid=int(form.get('pathid')) if form.get('pathid') else None,
                      method=form.get('method'),
                      url=form.get('url'),
                      headers={},
                      body=form.get('body'),
                      expected={})
        t.save()
    objects = test_case.objects().order_by('-ctime')
    count = objects.count()
    hits = objects[page * size: page * size + size]
    return {
        'form': form,
        'page': page,
        'size': size,
        'count': count,
        'hits': hits,
        'hit': get_page(page, size, count)
    }


# =================================== 鈫?宸ヤ綔绌洪棿 鈫?=============================================


# =================================== 鈫?role 鈫?================================================
@bp_web.route("/account")
@login_check
@templated("/sso-account.html")
def sso_account():
    return {'hits': SsoAccount.objects()}


@bp_web.route("/account-add")
@policy_check(PolicyEnum.MANAGE)
@templated("/sso-account-edit.html")
def sso_account_add():
    return {'account': {}}


@bp_web.route("/account/edit/<_id>")
@policy_check(PolicyEnum.MANAGE)
@templated("/sso-account-edit.html")
def sso_account_edit(_id):
    account = SsoAccount.objects(id=_id)
    if len(account) == 0:
        raise ApiException("account {} not found!".format(_id))
    account = account[0]
    return {
        'account': account
    }


@bp_web.route("/account/show/<_id>")
@policy_check(PolicyEnum.MANAGE)
@templated("/sso-account-show.html")
def sso_account_show(_id):
    account = SsoAccount.objects(id=_id)
    if len(account) == 0:
        raise ApiException("account {} not found!".format(_id))
    account = account[0]
    return {
        'account': account
    }
# =================================== 鈫?account 鈫?=============================================


