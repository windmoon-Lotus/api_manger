import json
import re
from typing import Dict, List
from urllib.parse import urlencode
from apiAnalysis.db.collection import (
    raw_data,
    req_data,
    res_data,
    target_whitelist,
    privilege_task,
    privilege_config,
    Workspace,
    WorkspaceAuth,
    WorkspaceSso,
    SsoAccount,
)
from apiAnalysis.model.model import HeaderModel, BodyModel, requests_request, AuthSession
from apiAnalysis.core.identify.sso import legalize_ws
from apiAnalysis.tool.compose_request import build_request_payload
from apiAnalysis.rule.object_id import build_idor_payload
from apiAnalysis.ai.judge_service import PrivilegeAiJudgeService
from apiAnalysis.ai.prompts import PROMPT_VERSION
from apiAnalysis.ai.schema import AiJudgeResult
from apiAnalysis.rule.evidence import build_rule_evidence
from apiAnalysis.rule.scoring import score_rule_from_evidence
from apiAnalysis.rule.fusion import ai_score, fuse_rule_ai


SCENARIO_UNAUTH = "unauth"
SCENARIO_HORIZONTAL = "horizontal"
SCENARIO_VERTICAL = "vertical"


class TargetFilter:
    def __init__(self, scenario: str):
        self.scenario = scenario

    def _in_whitelist(self, pathid: int) -> bool:
        return target_whitelist.objects(pathid=pathid, scenario=self.scenario).first() is not None

    def _add_whitelist(self, pathid: int, reason: str):
        entry = target_whitelist.objects(pathid=pathid, scenario=self.scenario).first()
        if entry:
            return
        target_whitelist(pathid=pathid, scenario=self.scenario, reason=reason).save()

    def should_skip(self, data) -> bool:
        if self._in_whitelist(data.ptah_id):
            return True
        if self.scenario in [SCENARIO_HORIZONTAL, SCENARIO_VERTICAL]:
            if req_data.objects(raw_data=data).count() == 0:
                self._add_whitelist(data.ptah_id, "no_request_params")
                return True
        if self.scenario == SCENARIO_UNAUTH:
            if data.action == "Auth_Path":
                self._add_whitelist(data.ptah_id, "auth_endpoint")
                return True
        return False


class PrivilegeEngine:
    def __init__(self, scenarios: List[str] = None):
        self.scenarios = scenarios or [SCENARIO_UNAUTH, SCENARIO_HORIZONTAL, SCENARIO_VERTICAL]

    def prepare_tasks(self):
        for data in raw_data.objects:
            for scenario in self.scenarios:
                target_filter = TargetFilter(scenario)
                if target_filter.should_skip(data):
                    privilege_task.objects(pathid=data.ptah_id, scenario=scenario).update(
                        status=privilege_task.STATUS_SKIP
                    )
                    continue
                if privilege_task.objects(pathid=data.ptah_id, scenario=scenario).first():
                    continue
                privilege_task(pathid=data.ptah_id, scenario=scenario).save()

    def build_judgement_payload(self, data):
        reqs = req_data.objects(raw_data=data)
        ress = res_data.objects(raw_data=data)
        return {
            "endpoint": data.path,
            "method": data.method,
            "action": data.action,
            "original_request": {
                "query": {r.parameter: r.value for r in reqs if r.position == "query"},
                "headers": {r.parameter: r.value for r in reqs if r.position == "header"},
                "path": {r.parameter: r.value for r in reqs if r.position == "path"},
                "body": {r.parameter: r.value for r in reqs if r.position == "body"},
            },
            "original_response": {
                "sample": data.raw_res[0] if data.raw_res else None,
                "parameters": {r.parameter: r.value for r in ress},
            },
            "doc": {
                "endpoint_description": data.des,
                "param_description": {},
            }
        }

    def execute_pending(self, limit: int = 20):
        tasks = privilege_task.objects(status=privilege_task.STATUS_INIT)[:limit]
        for task in tasks:
            self.execute_task(task)
        self.execute_ai_stub(limit=limit)

    def execute_ai_stub(self, limit: int = 20):
        tasks = privilege_task.objects(status=privilege_task.STATUS_DONE, ai_result=None)[:limit]
        for task in tasks:
            self._apply_ai_stub(task)

    def _apply_ai_stub(self, task):
        if task.ai_result:
            return
        result = task.result or "need_review"
        ai_result = AiJudgeResult(
            verdict=result if result in {"potential_vuln", "no_vuln", "need_review"} else "need_review",
            risk_level="medium",
            confidence=0.4,
            reason="rule-based placeholder: {}".format(result),
            reason_codes=["AI_STUB_FROM_RULE"],
            prompt_ver=task.prompt_ver or PROMPT_VERSION,
        )
        self._apply_ai_and_fusion(task, ai_result)

    def execute_ai_http(self, limit: int = 20, url: str = None, api_key: str = None):
        tasks = privilege_task.objects(status=privilege_task.STATUS_DONE, ai_result=None)[:limit]
        for task in tasks:
            self._apply_ai_http(task, url=url, api_key=api_key)

    def _apply_ai_http(self, task, url: str = None, api_key: str = None):
        if task.ai_result:
            return
        data = raw_data.objects(ptah_id=task.pathid).first()
        service = PrivilegeAiJudgeService(url=url, api_key=api_key, prompt_ver=task.prompt_ver or PROMPT_VERSION)
        ai_result, prompt = service.judge(
            scenario=task.scenario,
            endpoint=data.path if data else "",
            method=data.method if data else "",
            action=data.action if data else "",
            rule_result=task.result or "need_review",
            rule_score=task.rule_score or 0.0,
            evidence=task.evidence or {},
            endpoint_description=data.des if data else "",
        )
        task.ai_prompt = prompt
        self._apply_ai_and_fusion(task, ai_result)

    def _apply_ai_and_fusion(self, task, ai_result: AiJudgeResult):
        task.ai_result = ai_result.verdict
        task.ai_reason = ai_result.reason
        task.ai_confidence = ai_result.confidence
        task.ai_reason_codes = ai_result.reason_codes
        task.prompt_ver = ai_result.prompt_ver or task.prompt_ver or PROMPT_VERSION
        task.model_ver = ai_result.model_ver
        task.ai_raw_ref = ai_result.raw_text[:1000] if ai_result.raw_text else ""
        ai_score_value = ai_score(ai_result.verdict, ai_result.risk_level, ai_result.confidence)
        task.ai_score = ai_score_value
        fused = fuse_rule_ai(task.rule_score or 0.0, ai_score_value)
        task.final_score = fused["final_score"]
        task.final_result = fused["final_result"]
        task.save()

    def execute_task(self, task):
        data = raw_data.objects(ptah_id=task.pathid).first()
        if not data:
            task.status = privilege_task.STATUS_SKIP
            task.result = "missing_raw_data"
            task.save()
            return
        ws = self._find_workspace(data)
        cfg = self._get_config(ws, task.scenario) if ws else None
        account_id = cfg.account_id if cfg else None
        payload = build_request_payload(task.pathid, account_id=account_id)
        if not payload:
            task.status = privilege_task.STATUS_SKIP
            task.result = "missing_payload"
            task.save()
            return
        ws = ws or self._find_workspace(data)
        if not ws:
            task.status = privilege_task.STATUS_SKIP
            task.result = "missing_workspace"
            task.save()
            return

        result = self._execute_with_workspace(task.scenario, payload, ws, cfg)
        task.status = privilege_task.STATUS_DONE if result.get("ok") else privilege_task.STATUS_SKIP
        task.result = result.get("result")
        task.evidence = result.get("evidence")
        task.rule_score = result.get("rule_score")
        task.rule_reason_codes = result.get("rule_reason_codes") or []
        task.prompt_ver = result.get("prompt_ver") or PROMPT_VERSION
        task.final_result = task.result
        task.final_score = task.rule_score
        task.ai_prompt = self._build_ai_prompt(task.scenario, data, result.get("evidence"))
        task.save()

    def _find_workspace(self, data):
        if not data.domain:
            return None
        ws = Workspace.objects(hosts=data.domain, status=Workspace.STATUS_START).first()
        return ws

    def _get_config(self, ws, scenario):
        return privilege_config.objects(ws_id=ws.id, scenario=scenario, enabled=True).first()

    def _execute_with_workspace(self, scenario, payload, ws, cfg=None):
        if scenario == SCENARIO_UNAUTH:
            return self._execute_unauth_with_baseline(payload, ws, cfg)
        if not cfg:
            return {"ok": False, "result": "missing_config", "evidence": {}}
        if ws.system_type == Workspace.TYPE_SSO:
            return self._execute_sso_compare(payload, ws, cfg, scenario=scenario)
        if ws.system_type == Workspace.TYPE_DIRECT:
            return self._execute_direct_compare(payload, ws, cfg, scenario=scenario)
        return {"ok": False, "result": "unknown_system_type", "evidence": {}}

    def _build_url(self, payload):
        url = payload.get("url")
        path_params = payload.get("path_params") or {}
        for key, value in path_params.items():
            url = url.replace("{" + key + "}", str(value))
            url = url.replace(":" + key, str(value))
        query = payload.get("query") or {}
        if query:
            url = "{}?{}".format(url, urlencode(query, doseq=True))
        return url

    def _build_body(self, payload):
        body = payload.get("body")
        content_type = payload.get("content_type") or "application/json"
        if not body:
            return BodyModel("")
        if "json" in content_type:
            return BodyModel(json.dumps(body))
        if "x-www-form-urlencoded" in content_type:
            return BodyModel(urlencode(body))
        return BodyModel(json.dumps(body))

    def execute_payload(self, payload, ws, cfg):
        if ws.system_type == Workspace.TYPE_SSO:
            return self._execute_sso_payload(payload, ws, cfg.account_id)
        if ws.system_type == Workspace.TYPE_DIRECT:
            return self._execute_direct_payload(payload, ws, cfg.auth_describe)
        return {"status_code": None, "text": ""}

    def _execute_sso_payload(self, payload, ws, account_id):
        if not account_id:
            return {"status_code": None, "text": ""}
        account = SsoAccount.objects(id=account_id).first()
        if not account:
            return {"status_code": None, "text": ""}
        sso = WorkspaceSso.objects(ws_id=ws.id).first()
        if not sso:
            return {"status_code": None, "text": ""}
        _token, session = legalize_ws(account, sso)
        auth_session = AuthSession(session, account)
        headers = dict(payload.get("headers") or {})
        url = self._build_url(payload)
        body = self._build_body(payload)
        header = HeaderModel(header=headers, url=url, method=payload.get("method"))
        if body.type == BodyModel.TYPE_JSON:
            resp = auth_session.request(header.method, header.url, json=body.body(), headers=header.header)
        elif body.type in [BodyModel.TYPE_FORM, BodyModel.TYPE_BYTE]:
            resp = auth_session.request(header.method, header.url, data=body.body(), headers=header.header)
        else:
            resp = auth_session.request(header.method, header.url, data=body.body(), headers=header.header)
        return {"status_code": resp.status_code, "text": resp.text}

    def _execute_direct_payload(self, payload, ws, auth_describe=None):
        auth = WorkspaceAuth.objects(ws_id=ws.id).first()
        if not auth or not auth.auth_info:
            return {"status_code": None, "text": ""}
        auth_info = None
        if auth_describe:
            for item in auth.auth_info:
                if item.describe == auth_describe:
                    auth_info = item
                    break
        if not auth_info:
            auth_info = auth.auth_info[0]
        headers = dict(payload.get("headers") or {})
        if auth_info.auth_header:
            headers.update(auth_info.auth_header)
        url = self._build_url(payload)
        header = HeaderModel(header=headers, url=url, method=payload.get("method"))
        body = self._build_body(payload)
        if auth_info.auth_args:
            header.update_args(auth_info.auth_args)
        if auth_info.auth_param:
            body.update_param(auth_info.auth_param)
        if body.type == BodyModel.TYPE_JSON:
            resp = requests_request(header.method, header.url, json=body.body(), headers=header.header)
        elif body.type in [BodyModel.TYPE_FORM, BodyModel.TYPE_BYTE]:
            resp = requests_request(header.method, header.url, data=body.body(), headers=header.header)
        else:
            resp = requests_request(header.method, header.url, data=body.body(), headers=header.header)
        return {"status_code": resp.status_code, "text": resp.text}

    def _execute_unauth(self, payload):
        headers = dict(payload.get("headers") or {})
        headers.pop("Authorization", None)
        headers.pop("Cookie", None)
        url = self._build_url(payload)
        body = self._build_body(payload)
        header = HeaderModel(header=headers, url=url, method=payload.get("method"))
        if body.type == BodyModel.TYPE_JSON:
            resp = requests_request(header.method, header.url, json=body.body(), headers=header.header)
        elif body.type in [BodyModel.TYPE_FORM, BodyModel.TYPE_BYTE]:
            resp = requests_request(header.method, header.url, data=body.body(), headers=header.header)
        else:
            resp = requests_request(header.method, header.url, data=body.body(), headers=header.header)
        return {
            "ok": True,
            "result": "executed",
            "evidence": {"status_code": resp.status_code, "text": resp.text[:500]}
        }

    def _execute_sso(self, payload, ws, account_id):
        if not account_id:
            return {"ok": False, "result": "missing_account", "evidence": {}}
        account = SsoAccount.objects(id=account_id).first()
        if not account:
            return {"ok": False, "result": "invalid_account", "evidence": {}}
        sso = WorkspaceSso.objects(ws_id=ws.id).first()
        if not sso:
            return {"ok": False, "result": "missing_sso", "evidence": {}}
        _token, session = legalize_ws(account, sso)
        auth_session = AuthSession(session, account)
        headers = dict(payload.get("headers") or {})
        url = self._build_url(payload)
        body = self._build_body(payload)
        header = HeaderModel(header=headers, url=url, method=payload.get("method"))
        if body.type == BodyModel.TYPE_JSON:
            resp = auth_session.request(header.method, header.url, json=body.body(), headers=header.header)
        elif body.type in [BodyModel.TYPE_FORM, BodyModel.TYPE_BYTE]:
            resp = auth_session.request(header.method, header.url, data=body.body(), headers=header.header)
        else:
            resp = auth_session.request(header.method, header.url, data=body.body(), headers=header.header)
        return {
            "ok": True,
            "result": "executed",
            "evidence": {"status_code": resp.status_code, "text": resp.text[:500]}
        }

    def _execute_direct(self, payload, ws, auth_describe=None):
        auth = WorkspaceAuth.objects(ws_id=ws.id).first()
        if not auth or not auth.auth_info:
            return {"ok": False, "result": "missing_auth_info", "evidence": {}}
        auth_info = None
        if auth_describe:
            for item in auth.auth_info:
                if item.describe == auth_describe:
                    auth_info = item
                    break
        if not auth_info:
            auth_info = auth.auth_info[0]
        headers = dict(payload.get("headers") or {})
        if auth_info.auth_header:
            headers.update(auth_info.auth_header)
        url = self._build_url(payload)
        header = HeaderModel(header=headers, url=url, method=payload.get("method"))
        body = self._build_body(payload)
        if auth_info.auth_args:
            header.update_args(auth_info.auth_args)
        if auth_info.auth_param:
            body.update_param(auth_info.auth_param)
        if body.type == BodyModel.TYPE_JSON:
            resp = requests_request(header.method, header.url, json=body.body(), headers=header.header)
        elif body.type in [BodyModel.TYPE_FORM, BodyModel.TYPE_BYTE]:
            resp = requests_request(header.method, header.url, data=body.body(), headers=header.header)
        else:
            resp = requests_request(header.method, header.url, data=body.body(), headers=header.header)
        return {
            "ok": True,
            "result": "executed",
            "evidence": {"status_code": resp.status_code, "text": resp.text[:500]}
        }

    def _execute_unauth_with_baseline(self, payload, ws, cfg):
        baseline = None
        if cfg and cfg.account_id:
            if ws.system_type == Workspace.TYPE_SSO:
                baseline = self._execute_sso(payload, ws, cfg.account_id)
            elif ws.system_type == Workspace.TYPE_DIRECT:
                baseline = self._execute_direct(payload, ws, cfg.auth_describe)
        unauth = self._execute_unauth(payload)
        judged = self._judge(unauth, baseline, scenario=SCENARIO_UNAUTH)
        return {"ok": True, **judged}

    def _execute_sso_compare(self, payload, ws, cfg, scenario):
        if scenario == SCENARIO_HORIZONTAL and cfg.baseline_account_id:
            attempt = self._idor_payloads(payload, cfg.baseline_account_id)
            if attempt:
                test = self._execute_sso(attempt["idor"], ws, cfg.account_id)
                reference = self._execute_sso(attempt["victim"], ws, cfg.baseline_account_id)
                return {"ok": True, **self._judge_idor(test, reference, attempt["swaps"])}
        baseline = None
        if cfg.baseline_account_id:
            baseline = self._execute_sso(payload, ws, cfg.baseline_account_id)
        test = self._execute_sso(payload, ws, cfg.account_id)
        judged = self._judge(test, baseline, scenario=scenario)
        return {"ok": True, **judged}

    def _execute_direct_compare(self, payload, ws, cfg, scenario):
        if scenario == SCENARIO_HORIZONTAL and cfg.baseline_account_id and cfg.baseline_auth_describe:
            attempt = self._idor_payloads(payload, cfg.baseline_account_id)
            if attempt:
                test = self._execute_direct(attempt["idor"], ws, cfg.auth_describe)
                reference = self._execute_direct(attempt["victim"], ws, cfg.baseline_auth_describe)
                return {"ok": True, **self._judge_idor(test, reference, attempt["swaps"])}
        baseline = None
        if cfg.baseline_auth_describe:
            baseline = self._execute_direct(payload, ws, cfg.baseline_auth_describe)
        test = self._execute_direct(payload, ws, cfg.auth_describe)
        judged = self._judge(test, baseline, scenario=scenario)
        return {"ok": True, **judged}

    def _idor_payloads(self, attacker_payload, victim_account_id):
        """
        Build a horizontal IDOR attempt: the attacker request carrying the
        victim's real object identifiers. Returns None when there is no
        object id to cross, so the caller falls back to plain comparison.
        """
        pathid = attacker_payload.get("pathid")
        if pathid is None or not victim_account_id:
            return None
        victim_payload = build_request_payload(pathid, account_id=victim_account_id)
        if not victim_payload:
            return None
        idor_payload, swaps = build_idor_payload(attacker_payload, victim_payload)
        if not swaps:
            return None
        return {"idor": idor_payload, "victim": victim_payload, "swaps": swaps}

    def _judge_idor(self, test, reference, swaps):
        """
        Judge a cross-account IDOR attempt. `test` is the attacker accessing the
        victim's object id; `reference` is the victim legitimately accessing the
        same object. If the attacker request succeeds and returns the victim's
        data shape, escalate to potential_vuln.
        """
        judged = self._judge(test, reference, scenario=SCENARIO_HORIZONTAL)
        reasons = list(set((judged.get("rule_reason_codes") or []) + ["IDOR_OBJECT_SWAP"]))
        evidence = judged.get("evidence") or {}
        if isinstance(evidence, dict):
            evidence["idor_swaps"] = swaps
        if evidence.get("test_success") and float(evidence.get("json_overlap") or 0.0) >= 0.7:
            judged["rule_score"] = max(float(judged.get("rule_score") or 0.0), 80.0)
            judged["result"] = "potential_vuln"
            reasons = list(set(reasons + ["IDOR_CROSS_ACCOUNT_DATA"]))
        judged["rule_reason_codes"] = reasons
        judged["evidence"] = evidence
        return judged

    def _judge(self, test, baseline, scenario):
        if not test or not test.get("evidence"):
            evidence = build_rule_evidence(scenario, test or {}, baseline or None)
            scored = score_rule_from_evidence(evidence)
            scored["rule_result"] = "need_review"
            scored["rule_reason_codes"] = list(set((scored.get("rule_reason_codes") or []) + ["MISSING_TEST_EVIDENCE"]))
            return {
                "result": scored["rule_result"],
                "evidence": evidence,
                "rule_score": scored["rule_score"],
                "rule_reason_codes": scored["rule_reason_codes"],
                "prompt_ver": PROMPT_VERSION,
            }
        evidence = build_rule_evidence(scenario, test, baseline)
        scored = score_rule_from_evidence(evidence)
        return {
            "result": scored["rule_result"],
            "evidence": evidence,
            "rule_score": scored["rule_score"],
            "rule_reason_codes": scored["rule_reason_codes"],
            "prompt_ver": PROMPT_VERSION,
        }

    def _try_json(self, text):
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            return None

    def _compare_json(self, a, b):
        if not a or not b:
            return False
        if isinstance(a, dict) and isinstance(b, dict):
            a_keys = set(a.keys())
            b_keys = set(b.keys())
            if not a_keys or not b_keys:
                return False
            overlap = len(a_keys.intersection(b_keys)) / max(len(a_keys), len(b_keys))
            return overlap >= 0.7
        if isinstance(a, list) and isinstance(b, list) and a and b:
            return self._compare_json(a[0], b[0])
        return False

    def _build_ai_prompt(self, scenario, data, evidence):
        return json.dumps({
            "scenario": scenario,
            "endpoint": data.path,
            "method": data.method,
            "action": data.action,
            "evidence": evidence,
            "doc": {
                "endpoint_description": data.des,
                "param_description": {}
            }
        }, ensure_ascii=False)
