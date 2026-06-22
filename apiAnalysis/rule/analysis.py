from apiAnalysis.conf.conf import error, account, cname, logger
import json
import copy
from apiAnalysis.db.collection import *
from apiAnalysis.db.collection import Workspace
from apiAnalysis.core.lib import get_roles
from apiAnalysis.tool.tool import deal_request, deal_raw, sheer_parameters
from apiAnalysis.tool.compose_request import build_compose_record, build_request_payload
from apiAnalysis.rule.privilege import PrivilegeEngine

query_api_keywords = [
    "get", "list", "query", "search", "detail", "info", "fetch", "count", "page", "find",
]
download_api_keywords = [
    "download", "export", "file", "attachment", "report", "csv", "excel", "pdf",
]
upload_api_keywords = [
    "upload", "import", "multipart", "avatar", "attach", "upfile",
]
add_api_keywords = [
    "add", "create", "new", "insert", "register", "invite", "apply", "submit",
]
delete_api_keywords = [
    "delete", "remove", "del", "destroy", "revoke", "unbind", "deactivate",
]
modify_api_keywords = [
    "modify", "update", "edit", "patch", "set", "change", "bind", "enable", "disable", "reset",
    "approve", "reject",
]
auth_api_keywords = [
    "login", "logout", "auth", "token", "oauth", "sso", "captcha", "verify", "password",
    "passwd", "otp", "mfa", "refresh",
]


def analsis(resp):
    if resp.status_code != 200:
        return False
    elif any(v.encode() in resp.content for v in error):
        return False
    else:
        return True


class analysis():
    _SUCCESS_STATUS = {200, 201, 202, 204}
    _READONLY_METHODS = {"GET", "HEAD", "OPTIONS"}
    _READONLY_ACTIONS = {"Q_Path", "Download_Path"}
    _LOW_INFO_VALUES = {"", "0", "1", "true", "false", "null", "none", "unknown"}
    _PARAM_BLACKLIST = {
        "page", "size", "offset", "sort", "order", "lang", "locale",
        "timestamp", "nonce", "token", "traceid",
    }

    @staticmethod
    def _to_hashable_set(values):
        """
        Normalize mixed/nested value list to hashable strings for set operations.
        """
        normalized = set()
        for value in (values or []):
            items = value if isinstance(value, list) else [value]
            for item in items:
                if item is None:
                    continue
                try:
                    normalized.add(json.dumps(item, ensure_ascii=False, sort_keys=True))
                except TypeError:
                    normalized.add(str(item))
        return normalized

    def apiType_PathAnalysis(self, rawdata, verify):
        method_ptah = (rawdata.method or "") + (rawdata.path or "")
        method = (rawdata.method or "").upper()
        text = method_ptah.lower()
        if verify == "None":
            if any(k in text for k in auth_api_keywords):
                api_type = "auth_api"
                verify = "observed"
                return api_type, verify
            if any(k in text for k in download_api_keywords):
                api_type = "download_api"
                verify = "observed"
                return api_type, verify
            elif any(k in text for k in upload_api_keywords):
                api_type = "upload_api"
                verify = "observed"
                return api_type, verify
            elif any(k in text for k in delete_api_keywords):
                api_type = "delete_api"
                verify = "observed"
                return api_type, verify
            elif any(k in text for k in modify_api_keywords):
                api_type = "modify_api"
                verify = "observed"
                return api_type, verify
            elif any(k in text for k in add_api_keywords):
                api_type = "add_api"
                verify = "observed"
                return api_type, verify
            elif any(k in text for k in query_api_keywords):
                api_type = "query_api"
                verify = "observed"
                return api_type, verify
            else:
                if method in ["GET", "HEAD", "OPTIONS"]:
                    api_type = "query_api"
                elif method == "DELETE":
                    api_type = "delete_api"
                elif method == "POST":
                    api_type = "add_api"
                elif method in ["PUT", "PATCH"]:
                    api_type = "modify_api"
                else:
                    api_type = "query_api"
                verify = "observed"
                return api_type, verify
        elif verify == "observed":
            logger.debug("%s api type auto judge finished please check", method_ptah)
        elif verify == "verified":
            logger.debug("%s api type authed finished", method_ptah)
        else:
            api_type, verify = self.apiType_bodyAnalysis(rawdata, verify)
            return api_type, verify

    def apiType_bodyAnalysis(self, rawdata, verify):
        request_data = req_data.objects(rawdata=rawdata)
        response_data = res_data.objects(rawdata=rawdata)
        if verify == "None":
            if request_data.count() > 0:
                verify = "maybe"
                api_type, verify = self.apiType_ResponseCodeAnalysis(rawdata, verify)
                if api_type == "None":
                    api_type = "modify or add or delete"
                return api_type, verify
            elif request_data.count() == 0:
                api_type = "query_api"
                verify = "presumably"
                return api_type, verify
            else:
                logger.debug("%s not request body", rawdata.path)
        elif verify == "maybe":
            if response_data.count() > 0:
                for data in response_data.objects():
                    compare_value = req_data.objects(value=data.value)
                    if compare_value.count() > 0:
                        api_type = "modify or add or delete"
                        verify = "presumably"
                        return api_type, verify

            else:
                self.apiType_ResponseCodeAnalysis(self, rawdata, verify)

    def apiType_ResponseCodeAnalysis(self, rawdata, verify):
        if verify == "None" or verify == "maybe":
            if rawdata.response_status_code == 204:
                api_type = "add_api"
                verify = "presumably"
                return api_type, verify
            else:
                api_type = "None"
                return api_type, verify

    def parameter_data(self, rawdata):
        parameter_archive()

    def parameter_archive(self, account_id=None):
        sheer_parameter, paths = sheer_parameters()
        yield_obj = deal_raw(sheer_parameter)
        param_archive = {}
        try:
            ws = Workspace.objects(status=Workspace.STATUS_START, cname=cname)
            for k, v, d in yield_obj:
                if k in sheer_parameter:
                    parameter_archive_data = parameter_archive(parameter=k, parameterid=v,
                                                               req_pathid=paths[k]["req_pathid"],
                                                               res_pathid=paths[k]["res_pathid"],
                                                               req_value=list(set(paths[k]["req_value"])),
                                                               res_value=list(set(paths[k]["res_value"])),
                                                               account_id=account_id)
                    parameter_archive_data.save()
                else:
                    if any(d["parameterid"] in value_list for key, value_list in param_archive.items()
                           if d["parameter"] in key):
                        break
                    parameterid_archive = []
                    for i in paths[d["parameter"]]["req_pathid"]:
                        req_data = parameter_data.objects(raw_data__ptah_id=i).first()
                        value = req_data.req_value[:3] if 3 < len(req_data.req_value) else req_data.req_value
                        responds = []
                        parameter_value = []
                        for j in value:
                            update_kv = {d["parameter"]: j}
                            v.update_param(update_kv)
                            resp = deal_request(k, v, account, ws, get_roles(ws))
                            if analsis(resp):
                                parameter_value.append(j)
                            else:
                                paths[d["parameter"]]["req_pathid"].remove(i)
                            #responds.append(resp)
                        parameterid_archive.append(req_data.parameterid)
                    if d["parameter"] not in param_archive:
                        param_archive[d["parameter"]] = list(set(parameterid_archive))
                    else:
                        param_archive[d["parameter"]+f"_{d['parameterid']}"] = list(set(parameterid_archive))
                        paths[d["parameter"] + f"_{d['parameterid']}"]["req_pathid"] = paths[d["parameter"]]["req_pathid"]
                        paths[d["parameter"] + f"_{d['parameterid']}"]["req_pathid"] = paths[d["parameter"]]["res_pathid"]
                    for key, value in param_archive.items():
                        parameter_archive_data = parameter_archive(parameter=key, parameterid=value,
                                                                   req_pathid=paths[key]["req_pathid"],
                                                                   res_pathid=paths[key]["res_pathid"],
                                                                   req_value=list(set(parameter_value)),
                                                                   res_value=list(set(paths[key]["res_value"])),
                                                                   account_id=account_id)
                        parameter_archive_data.save()
        except Exception as e:
            logger.exception("parameter_archive failed: %s", e)

    @staticmethod
    def _normalize_param_name(name):
        if not name:
            return ""
        return "".join(ch for ch in str(name).lower() if ch.isalnum())

    @staticmethod
    def _leaf_param_name(name):
        if not name:
            return ""
        parts = str(name).split(".")
        leaf = parts[-1]
        if leaf.isdigit() and len(parts) > 1:
            return ".".join(parts[-2:])
        return leaf

    @staticmethod
    def _parse_name_list(raw_names):
        if not raw_names:
            return set()
        names = set()
        for item in str(raw_names).replace(";", ",").split(","):
            val = item.strip()
            if val:
                names.add(val.lower())
        return names

    @staticmethod
    def _safe_ratio(a, b):
        if b <= 0:
            return 0.0
        return float(a) / float(b)

    def _normalize_relation_value(self, value):
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            low = text.lower()
            if low in {"true", "false"}:
                return low == "true"
            try:
                if "." in text:
                    return float(text)
                return int(text)
            except Exception:
                return text
        return value

    def _is_low_info_value(self, value):
        if value is None:
            return True
        text = str(value).strip().lower()
        return text in self._LOW_INFO_VALUES or len(text) < 2

    def _normalize_relation_values(self, values, leaf_name):
        leaf = (leaf_name or "").lower()
        is_black_param = leaf in self._PARAM_BLACKLIST
        normalized = set()
        for raw in values or []:
            items = raw if isinstance(raw, list) else [raw]
            for item in items:
                norm = self._normalize_relation_value(item)
                if norm is None:
                    continue
                if self._is_low_info_value(norm):
                    continue
                if is_black_param:
                    # 黑名单参数仅保留“较有信息量”的值，降低误关联
                    if len(str(norm)) < 6:
                        continue
                try:
                    normalized.add(json.dumps(norm, ensure_ascii=False, sort_keys=True))
                except Exception:
                    normalized.add(str(norm))
        return normalized

    def _score_weak_relation(self, leaf_name, overlap_count, req_count, res_count, used_name_fallback=False):
        score = 0.0
        reason_codes = []
        if overlap_count > 0:
            score += min(50.0, overlap_count * 10.0)
            reason_codes.append("OVERLAP_COUNT")
        max_count = max(req_count, res_count, 1)
        overlap_ratio = self._safe_ratio(overlap_count, max_count)
        if overlap_ratio >= 0.6:
            score += 25.0
            reason_codes.append("OVERLAP_RATIO_HIGH")
        elif overlap_ratio >= 0.3:
            score += 12.0
            reason_codes.append("OVERLAP_RATIO_MID")
        if leaf_name and leaf_name.lower() not in self._PARAM_BLACKLIST:
            score += 15.0
            reason_codes.append("LEAF_NOT_BLACKLIST")
        if used_name_fallback:
            score += 8.0
            reason_codes.append("NAME_FALLBACK")
        return round(min(100.0, score), 2), reason_codes

    def classify_with_score(self, rawdata):
        method = (rawdata.method or "").upper()
        path = (rawdata.path or "").lower()
        text = "{}{}".format(method, path)
        score = {
            "Auth_Path": 0,
            "Download_Path": 0,
            "Upload_Path": 0,
            "D_Path": 0,
            "M_Path": 0,
            "C_Path": 0,
            "Q_Path": 0,
        }
        reason = []

        if method in {"GET", "HEAD", "OPTIONS"}:
            score["Q_Path"] += 35
            reason.append("METHOD_READONLY")
        elif method == "DELETE":
            score["D_Path"] += 35
            reason.append("METHOD_DELETE")
        elif method in {"PUT", "PATCH"}:
            score["M_Path"] += 35
            reason.append("METHOD_MODIFY")
        elif method == "POST":
            score["C_Path"] += 25
            score["M_Path"] += 10
            reason.append("METHOD_POST")

        def hit(words):
            return any(k in text for k in words)

        if hit(auth_api_keywords):
            score["Auth_Path"] += 60
            reason.append("KW_AUTH")
        if hit(download_api_keywords):
            score["Download_Path"] += 55
            reason.append("KW_DOWNLOAD")
        if hit(upload_api_keywords):
            score["Upload_Path"] += 55
            reason.append("KW_UPLOAD")
        if hit(delete_api_keywords):
            score["D_Path"] += 45
            reason.append("KW_DELETE")
        if hit(modify_api_keywords):
            score["M_Path"] += 45
            reason.append("KW_MODIFY")
        if hit(add_api_keywords):
            score["C_Path"] += 45
            reason.append("KW_CREATE")
        if hit(query_api_keywords):
            score["Q_Path"] += 35
            reason.append("KW_QUERY")

        has_body = bool(rawdata.raw_req and any(i not in [None, b"", ""] for i in rawdata.raw_req))
        if has_body:
            score["C_Path"] += 10
            score["M_Path"] += 10
            reason.append("HAS_REQUEST_BODY")

        statuses = set(rawdata.response_status_code or [])
        if 204 in statuses or 201 in statuses:
            score["C_Path"] += 8
            score["M_Path"] += 8
            score["D_Path"] += 6
            reason.append("STATUS_201_204")

        best_action = max(score, key=score.get)
        confidence = int(score[best_action])
        if confidence < 40:
            best_action = "Q_Path"
            reason.append("LOW_CONF_FALLBACK_Q")
        return best_action, min(confidence, 100), reason[:8]

    def infer_weak_relations(self,
                             enable_value_intersection=True,
                             min_overlap_count=1,
                             enable_name_fallback=False,
                             fallback_parameter_names=None,
                             enable_same_path_not_equal=True,
                             min_relation_score=60.0,
                             top_candidate_limit=10):
        """
        Infer weak relations between request/response paths with configurable rules.
        """
        try:
            min_overlap_count = int(min_overlap_count)
        except Exception:
            min_overlap_count = 1
        if min_overlap_count < 1:
            min_overlap_count = 1
        fallback_names = {self._leaf_param_name(i).lower() for i in self._parse_name_list(fallback_parameter_names)}
        grouped = {}
        candidate_rows = []
        accepted = 0
        skipped_low_score = 0

        for param in parameter_data.objects():
            if not param.parameter:
                continue
            leaf_name = self._leaf_param_name(param.parameter)
            if not leaf_name:
                continue
            group = grouped.setdefault(
                leaf_name,
                {"req_pids": set(), "res_pids": set(), "req_values": set(), "res_values": set()}
            )
            group["req_pids"].update(param.req_pathid or [])
            group["res_pids"].update(param.res_pathid or [])
            group["req_values"].update(self._normalize_relation_values(param.req_value, leaf_name))
            group["res_values"].update(self._normalize_relation_values(param.res_value, leaf_name))

        for leaf_name, group in grouped.items():
            overlap = list(group["req_values"].intersection(group["res_values"]))
            allow_name_fallback = (
                enable_name_fallback and (
                    not fallback_names or leaf_name.lower() in fallback_names
                )
            )
            for req_pid in group["req_pids"]:
                for res_pid in group["res_pids"]:
                    if req_pid == res_pid:
                        continue
                    used_name_fallback = False
                    if enable_value_intersection and len(overlap) >= min_overlap_count:
                        rule_name = "value_intersection_leaf"
                        relation_type = "weak"
                        evidence = overlap[:5]
                    elif allow_name_fallback:
                        rule_name = "name_fallback_leaf"
                        relation_type = "weak"
                        evidence = [self._normalize_param_name(leaf_name)]
                        used_name_fallback = True
                    else:
                        continue
                    rel_score, reason_codes = self._score_weak_relation(
                        leaf_name=leaf_name,
                        overlap_count=len(overlap),
                        req_count=len(group["req_values"]),
                        res_count=len(group["res_values"]),
                        used_name_fallback=used_name_fallback,
                    )
                    candidate_rows.append({
                        "parameter": leaf_name,
                        "req_pathid": req_pid,
                        "res_pathid": res_pid,
                        "rule": rule_name,
                        "score": rel_score,
                        "reason_codes": reason_codes,
                        "accepted": rel_score >= min_relation_score,
                    })
                    if rel_score < min_relation_score:
                        skipped_low_score += 1
                        continue
                    relation_obj = parameter_relation.objects(parameter=leaf_name,
                                                              req_pathid=req_pid,
                                                              res_pathid=res_pid).first()
                    if not relation_obj:
                        relation_obj = parameter_relation(parameter=leaf_name,
                                                          req_pathid=req_pid,
                                                          res_pathid=res_pid,
                                                          rule=rule_name,
                                                          relation=relation_type,
                                                          score=rel_score,
                                                          reason_codes=reason_codes,
                                                          evidence=evidence)
                        relation_obj.save()
                    else:
                        # Keep highest score and reasons for explainability.
                        changed = False
                        if (relation_obj.score or 0) < rel_score:
                            relation_obj.score = rel_score
                            changed = True
                        if reason_codes:
                            relation_obj.reason_codes = reason_codes
                            changed = True
                        if changed:
                            relation_obj.save()
                    accepted += 1
        if not enable_same_path_not_equal:
            summary = self._build_relation_summary(
                candidate_rows=candidate_rows,
                accepted=accepted,
                skipped_low_score=skipped_low_score,
                min_relation_score=min_relation_score,
                top_candidate_limit=top_candidate_limit,
            )
            logger.info(
                "infer_weak_relations summary: total=%s accepted=%s skipped_low_score=%s min_score=%s",
                summary["total_candidates"],
                summary["accepted_candidates"],
                summary["skipped_low_score"],
                summary["min_relation_score"],
            )
            return summary

        for leaf_name, group in grouped.items():
            req_values = group["req_values"]
            res_values = group["res_values"]
            if not req_values or not res_values:
                continue
            if req_values.intersection(res_values):
                continue
            for req_pid in group["req_pids"]:
                for res_pid in group["res_pids"]:
                    if req_pid != res_pid:
                        continue
                    relation = parameter_relation.objects(parameter=leaf_name,
                                                          req_pathid=req_pid,
                                                          res_pathid=res_pid).first()
                    if relation:
                        continue
                    relation = parameter_relation(parameter=leaf_name,
                                                  req_pathid=req_pid,
                                                  res_pathid=res_pid,
                                                  rule="no_intersection_same_path",
                                                  relation="not_equal",
                                                  score=30.0,
                                                  reason_codes=["NO_INTERSECTION_SAME_PATH"],
                                                  evidence=[])
                    relation.save()

        summary = self._build_relation_summary(
            candidate_rows=candidate_rows,
            accepted=accepted,
            skipped_low_score=skipped_low_score,
            min_relation_score=min_relation_score,
            top_candidate_limit=top_candidate_limit,
        )
        logger.info(
            "infer_weak_relations summary: total=%s accepted=%s skipped_low_score=%s min_score=%s",
            summary["total_candidates"],
            summary["accepted_candidates"],
            summary["skipped_low_score"],
            summary["min_relation_score"],
        )
        return summary

    @staticmethod
    def _build_relation_summary(candidate_rows, accepted, skipped_low_score, min_relation_score, top_candidate_limit):
        candidates = sorted(candidate_rows, key=lambda x: (x.get("score") or 0), reverse=True)
        limit = int(top_candidate_limit or 10)
        if limit < 1:
            limit = 10
        top_candidates = candidates[:limit]
        return {
            "total_candidates": len(candidate_rows),
            "accepted_candidates": int(accepted),
            "skipped_low_score": int(skipped_low_score),
            "min_relation_score": float(min_relation_score),
            "top_candidates": top_candidates,
        }

    def build_request_compose(self):
        for data in raw_data.objects:
            build_compose_record(data.ptah_id)

    def verify_weak_relations(self):
        """
        Heuristic verification using existing path metadata.
        """
        for relation in parameter_relation.objects(verified=False):
            req = raw_data.objects(ptah_id=relation.req_pathid).first()
            res = raw_data.objects(ptah_id=relation.res_pathid).first()
            if not req or not res:
                continue
            if 200 in (req.response_status_code or []) and 200 in (res.response_status_code or []):
                relation.verified = True
                relation.save()

    def verify_weak_relations_real(self, limit=None, min_score=None):
        """
        Real replay verification using positive/negative/baseline samples.
        """
        return self.verify_weak_relations_real_with_switch(limit=limit, min_score=min_score)

    def verify_weak_relations_real_with_switch(self,
                                               allowed_actions=None,
                                               allow_write_actions=False,
                                               limit=None,
                                               min_score=None):
        """
        Real replay verification with classification-based switch.
        Default: only readonly actions/methods.
        """
        engine = PrivilegeEngine()
        allowed = set(self._parse_name_list(allowed_actions))
        if not allowed:
            allowed = {a.lower() for a in self._READONLY_ACTIONS}
        try:
            min_score_val = float(min_score) if min_score is not None else 60.0
        except Exception:
            min_score_val = 60.0
        try:
            limit_val = int(limit) if limit is not None else 200
        except Exception:
            limit_val = 200
        if limit_val <= 0:
            limit_val = 200
        if limit_val > 5000:
            limit_val = 5000

        qs = parameter_relation.objects(relation="weak", verified=False, score__gte=min_score_val).order_by("-score")
        processed = 0
        verified_count = 0
        skipped = 0

        for relation in qs:
            if processed >= limit_val:
                break
            processed += 1
            req_data_obj = raw_data.objects(ptah_id=relation.req_pathid).first()
            res_data_obj = raw_data.objects(ptah_id=relation.res_pathid).first()
            if not req_data_obj or not res_data_obj:
                skipped += 1
                continue
            if not self._allow_replay_pair(req_data_obj, res_data_obj, allowed, allow_write_actions):
                skipped += 1
                continue
            ws = engine._find_workspace(req_data_obj) or engine._find_workspace(res_data_obj)
            if not ws:
                skipped += 1
                continue
            cfg = engine._get_config(ws, "horizontal")
            if not cfg:
                skipped += 1
                continue
            sample_values = self._prepare_replay_values(relation.evidence)
            if not sample_values:
                skipped += 1
                continue

            total = 0
            passed = 0
            for idx, value in enumerate(sample_values):
                total += 1
                req_base = build_request_payload(relation.req_pathid, account_id=cfg.account_id)
                res_base = build_request_payload(relation.res_pathid, account_id=cfg.account_id)
                if not req_base or not res_base:
                    continue

                req_pos = copy.deepcopy(req_base)
                res_pos = copy.deepcopy(res_base)
                self._apply_param_value(relation.parameter, value, req_pos, relation.req_pathid)
                self._apply_param_value(relation.parameter, value, res_pos, relation.res_pathid)
                req_pos_resp = engine.execute_payload(req_pos, ws, cfg)
                res_pos_resp = engine.execute_payload(res_pos, ws, cfg)

                bad_value = self._make_negative_value(value, idx)
                req_neg = copy.deepcopy(req_base)
                res_neg = copy.deepcopy(res_base)
                self._apply_param_value(relation.parameter, bad_value, req_neg, relation.req_pathid)
                self._apply_param_value(relation.parameter, bad_value, res_neg, relation.res_pathid)
                req_neg_resp = engine.execute_payload(req_neg, ws, cfg)
                res_neg_resp = engine.execute_payload(res_neg, ws, cfg)

                req_base_resp = engine.execute_payload(req_base, ws, cfg)
                res_base_resp = engine.execute_payload(res_base, ws, cfg)

                if self._judge_replay_sample(
                    value=value,
                    bad_value=bad_value,
                    req_pos_resp=req_pos_resp,
                    res_pos_resp=res_pos_resp,
                    req_neg_resp=req_neg_resp,
                    res_neg_resp=res_neg_resp,
                    req_base_resp=req_base_resp,
                    res_base_resp=res_base_resp,
                ):
                    passed += 1

            if total <= 0:
                skipped += 1
                continue
            if passed / float(total) >= 0.6:
                relation.verified = True
                relation.modificator = "real_replay_vote_{}/{}".format(passed, total)
                relation.save()
                verified_count += 1

        summary = {
            "processed": processed,
            "verified": verified_count,
            "skipped": skipped,
            "limit": limit_val,
            "min_score": min_score_val,
        }
        logger.info(
            "verify_weak_relations_real summary: processed=%s verified=%s skipped=%s limit=%s min_score=%s",
            processed, verified_count, skipped, limit_val, min_score_val
        )
        return summary

    def _allow_replay_pair(self, req_data_obj, res_data_obj, allowed_actions, allow_write_actions):
        return (
            self._allow_replay_endpoint(req_data_obj, allowed_actions, allow_write_actions)
            and self._allow_replay_endpoint(res_data_obj, allowed_actions, allow_write_actions)
        )

    def _allow_replay_endpoint(self, data_obj, allowed_actions, allow_write_actions):
        method = (data_obj.method or "").upper()
        action = (data_obj.action or "").lower()
        if allow_write_actions:
            return True
        if method not in self._READONLY_METHODS:
            return False
        if allowed_actions and action not in allowed_actions:
            return False
        return True

    def _prepare_replay_values(self, evidence, max_samples=5):
        values = []
        seen = set()
        for raw in evidence or []:
            value = self._decode_evidence_value(raw)
            if value is None:
                continue
            key = self._normalize_value_key(value)
            if key in seen:
                continue
            seen.add(key)
            values.append(value)
            if len(values) >= max_samples:
                break
        return values

    def _decode_evidence_value(self, value):
        if value is None:
            return None
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            try:
                return json.loads(text)
            except Exception:
                return text
        return value

    def _normalize_value_key(self, value):
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        except Exception:
            return str(value)

    def _make_negative_value(self, value, idx):
        if isinstance(value, bool):
            return not value
        if isinstance(value, int):
            return value + 100000 + idx
        if isinstance(value, float):
            return value + 100000.0 + idx
        if isinstance(value, str):
            return "__invalid__{}__{}".format(value, idx)
        return "__invalid__{}".format(idx)

    def _status_ok(self, resp):
        code = None
        if isinstance(resp, dict):
            code = resp.get("status_code")
        return code in self._SUCCESS_STATUS

    def _text_contains_value(self, text, value):
        if not text:
            return False
        value_text = str(value)
        if value_text and value_text in str(text):
            return True
        try:
            return json.dumps(value, ensure_ascii=False) in str(text)
        except Exception:
            return False

    def _judge_replay_sample(self,
                             value,
                             bad_value,
                             req_pos_resp,
                             res_pos_resp,
                             req_neg_resp,
                             res_neg_resp,
                             req_base_resp,
                             res_base_resp):
        pos_ok = self._status_ok(req_pos_resp) and self._status_ok(res_pos_resp)
        if not pos_ok:
            return False

        neg_ok = self._status_ok(req_neg_resp) and self._status_ok(res_neg_resp)
        base_ok = self._status_ok(req_base_resp) and self._status_ok(res_base_resp)

        pos_text_req = (req_pos_resp or {}).get("text", "")
        pos_text_res = (res_pos_resp or {}).get("text", "")
        neg_text_req = (req_neg_resp or {}).get("text", "")
        neg_text_res = (res_neg_resp or {}).get("text", "")

        pos_has = self._text_contains_value(pos_text_req, value) or self._text_contains_value(pos_text_res, value)
        neg_has = self._text_contains_value(neg_text_req, bad_value) or self._text_contains_value(neg_text_res,
                                                                                                    bad_value)

        score = 0
        if pos_ok:
            score += 1
        if pos_has:
            score += 1
        if not neg_ok:
            score += 1
        if not neg_has:
            score += 1
        if base_ok:
            score += 1

        return score >= 3

    def _apply_param_value(self, parameter, value, payload, pathid):
        req_items = req_data.objects(raw_data__ptah_id=pathid, parameter=parameter)
        if not req_items:
            leaf_name = self._leaf_param_name(parameter)
            req_items = [
                item for item in req_data.objects(raw_data__ptah_id=pathid)
                if self._leaf_param_name(item.parameter) == leaf_name
            ]
        for item in req_items:
            pos = item.position or "body"
            target_name = item.parameter or parameter
            if pos == "query":
                payload.setdefault("query", {})[target_name] = value
            elif pos == "header":
                payload.setdefault("headers", {})[target_name] = value
            elif pos == "path":
                payload.setdefault("path_params", {})[target_name] = value
            else:
                payload.setdefault("body", {})[target_name] = value

    def prepare_privilege_tasks(self):
        PrivilegeEngine().prepare_tasks()

    def execute_privilege_tasks(self, limit: int = 20):
        PrivilegeEngine().execute_pending(limit=limit)

    def execute_ai_stub(self, limit: int = 20):
        PrivilegeEngine().execute_ai_stub(limit=limit)

    def execute_ai_http(self, limit: int = 20, url: str = None, api_key: str = None):
        PrivilegeEngine().execute_ai_http(limit=limit, url=url, api_key=api_key)

    def classify_raw_data(self):
        for data in raw_data.objects:
            if data.action:
                continue
            action, confidence, reason_codes = self.classify_with_score(data)
            data.action = action
            data.class_confidence = confidence
            data.class_reason_codes = reason_codes
            data.rule = "path_score_v1"
            data.save()



