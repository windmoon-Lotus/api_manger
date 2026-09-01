from apiAnalysis.conf.conf import logger
import json
from bson import ObjectId
from apiAnalysis.db.collection import *
from apiAnalysis.tool.compose_request import build_compose_record
from apiAnalysis.tool.parameter_locator import LOCATOR_VERSION
from apiAnalysis.rule.legacy_scoring import (
    classify_endpoint_with_score,
    score_weak_relation,
)

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

class analysis():
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

    def parameter_archive(self, *, pathids, account_id=None, project_id="", env_id=""):
        """Archive imported parameter facts without sending network requests.

        The old implementation attempted synchronous replay while importing.
        Import is now a deterministic data transformation, strictly bounded to
        the path ids returned by the current import contract.
        """
        selected = {int(value) for value in (pathids or [])}
        if not selected:
            raise ValueError("parameter archive requires non-empty pathids")

        def normalized_pathids(values):
            result = set()
            pending = list(values or [])
            while pending:
                value = pending.pop()
                if isinstance(value, (list, tuple, set)):
                    pending.extend(value)
                    continue
                try:
                    result.add(int(value))
                except (TypeError, ValueError):
                    continue
            return result

        def unique_values(values):
            result = []
            seen = set()
            for value in values:
                try:
                    key = json.dumps(value, ensure_ascii=False, sort_keys=True)
                except TypeError:
                    key = str(value)
                if key not in seen:
                    seen.add(key)
                    result.append(value)
            return result

        grouped = {}
        for item in parameter_data.objects():
            req_pathids = normalized_pathids(item.req_pathid)
            res_pathids = normalized_pathids(item.res_pathid)
            if not selected.intersection(req_pathids | res_pathids):
                continue
            key = self._leaf_param_name(item.parameter)
            target = grouped.setdefault(key, {
                "parameterids": set(), "req_pathids": set(), "res_pathids": set(),
                "req_values": [], "res_values": [],
            })
            target["parameterids"].add(int(item.parameterid))
            target["req_pathids"].update(req_pathids.intersection(selected))
            target["res_pathids"].update(res_pathids.intersection(selected))
            target["req_values"].extend(list(item.req_value or []))
            target["res_values"].extend(list(item.res_value or []))

        archived = 0
        identity = {
            "account_id": str(account_id or ""),
            "project_id": str(project_id or ""),
            "env_id": str(env_id or ""),
        }
        for name, values in grouped.items():
            record = parameter_archive.objects(parameter=name, **identity).first()
            if record is None:
                record = parameter_archive(parameter=name, **identity)
            record.parameterid = sorted(values["parameterids"])
            record.req_pathid = sorted(values["req_pathids"])
            record.res_pathid = sorted(values["res_pathids"])
            record.req_value = unique_values(values["req_values"])
            record.res_value = unique_values(values["res_values"])
            record.modificator = "offline_import_batch_v1"
            record.save()
            archived += 1
        return archived

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

    def _parameter_occurrence(self, pathid, direction, leaf_name, project_id=""):
        model = req_data if direction == "request" else res_data
        normalized = str(leaf_name or "").lower().replace("-", "_")
        compact = "".join(char for char in normalized if char.isalnum())
        endpoint_query = {"ptah_id": pathid}
        if project_id:
            endpoint_query["project_id"] = str(project_id)
        endpoint = raw_data.objects(**endpoint_query).first()
        if not endpoint and project_id:
            endpoint = raw_data.objects(ptah_id=pathid).first()
        if not endpoint:
            return None
        occurrences = model.objects(raw_data=endpoint)
        item = occurrences.filter(canonical_name=normalized).first()
        if item:
            return item
        for candidate in occurrences:
            leaf = self._leaf_param_name(candidate.parameter).lower().replace("-", "_")
            if leaf == normalized or (
                    compact and "".join(char for char in leaf if char.isalnum()) == compact):
                return candidate
        return None

    def _bind_relation_occurrences(self, relation, leaf_name, req_pathid, res_pathid):
        source = self._parameter_occurrence(
            res_pathid, "response", leaf_name, relation.project_id,
        )
        target = self._parameter_occurrence(
            req_pathid, "request", leaf_name, relation.project_id,
        )
        if source:
            relation.source_parameter = source.parameter or leaf_name
            relation.source_position = source.position or "body"
            relation.source_locator = dict(source.locator or {})
        if target:
            relation.target_parameter = target.parameter or leaf_name
            relation.target_position = target.position or "body"
            relation.target_locator = dict(target.locator or {})
        endpoint = target.raw_data if target and target.raw_data else (source.raw_data if source else None)
        if endpoint:
            relation.project_id = endpoint.project_id or relation.project_id
            relation.env_id = endpoint.env_id or relation.env_id
        relation.locator_version = LOCATOR_VERSION
        relation.location_status = "resolved" if source and target else "unresolved"
        missing = []
        if not source:
            missing.append("source")
        if not target:
            missing.append("target")
        relation.location_note = "" if not missing else "{} parameter occurrence is unavailable".format("/".join(missing))
        return relation

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
        return score_weak_relation(
            leaf_name,
            overlap_count,
            req_count,
            res_count,
            used_name_fallback=used_name_fallback,
        )

    def classify_with_score(self, rawdata):
        return classify_endpoint_with_score(rawdata)

    def infer_weak_relations(self,
                             enable_value_intersection=True,
                             min_overlap_count=1,
                             enable_name_fallback=False,
                             fallback_parameter_names=None,
                             enable_same_path_not_equal=True,
                             min_relation_score=60.0,
                             top_candidate_limit=10,
                             pathids=None):
        """
        Infer weak relations between request/response paths with configurable rules.

        ``enable_same_path_not_equal`` is retained as a compatibility flag for
        counting legacy empty-intersection cases.  Empty intersections are now
        reported as insufficient evidence and never create/update a relation.
        """
        try:
            min_overlap_count = int(min_overlap_count)
        except Exception:
            min_overlap_count = 1
        if min_overlap_count < 1:
            min_overlap_count = 1
        fallback_names = {self._leaf_param_name(i).lower() for i in self._parse_name_list(fallback_parameter_names)}
        selected_pathids = None if pathids is None else {int(item) for item in pathids}
        grouped = {}
        candidate_rows = []
        accepted = 0
        skipped_low_score = 0
        insufficient_evidence_pairs = 0

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
                    if selected_pathids is not None and req_pid not in selected_pathids and res_pid not in selected_pathids:
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
                        self._bind_relation_occurrences(relation_obj, leaf_name, req_pid, res_pid)
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
                        self._bind_relation_occurrences(relation_obj, leaf_name, req_pid, res_pid)
                        changed = True
                        if changed:
                            relation_obj.save()
                    accepted += 1
        if enable_same_path_not_equal:
            for _, group in grouped.items():
                req_values = group["req_values"]
                res_values = group["res_values"]
                if not req_values or not res_values or req_values.intersection(res_values):
                    continue
                same_pathids = set(group["req_pids"]).intersection(group["res_pids"])
                if selected_pathids is not None:
                    same_pathids.intersection_update(selected_pathids)
                insufficient_evidence_pairs += len(same_pathids)

        summary = self._build_relation_summary(
            candidate_rows=candidate_rows,
            accepted=accepted,
            skipped_low_score=skipped_low_score,
            min_relation_score=min_relation_score,
            top_candidate_limit=top_candidate_limit,
            insufficient_evidence_pairs=insufficient_evidence_pairs,
        )
        logger.info(
            "infer_weak_relations summary: total=%s accepted=%s skipped_low_score=%s "
            "insufficient_evidence=%s min_score=%s",
            summary["total_candidates"],
            summary["accepted_candidates"],
            summary["skipped_low_score"],
            summary["insufficient_evidence_pairs"],
            summary["min_relation_score"],
        )
        return summary

    @staticmethod
    def _build_relation_summary(candidate_rows, accepted, skipped_low_score, min_relation_score,
                                top_candidate_limit, insufficient_evidence_pairs=0):
        candidates = sorted(candidate_rows, key=lambda x: (x.get("score") or 0), reverse=True)
        limit = int(top_candidate_limit or 10)
        if limit < 1:
            limit = 10
        top_candidates = candidates[:limit]
        return {
            "total_candidates": len(candidate_rows),
            "accepted_candidates": int(accepted),
            "skipped_low_score": int(skipped_low_score),
            "insufficient_evidence_pairs": int(insufficient_evidence_pairs),
            "min_relation_score": float(min_relation_score),
            "top_candidates": top_candidates,
        }

    def build_request_compose(self, pathids=None):
        query = {}
        if pathids is not None:
            query["ptah_id__in"] = list(pathids)
        for data in raw_data.objects(**query):
            build_compose_record(data.ptah_id)

    def classify_raw_data(self, raw_ids=None, pathids=None):
        query = {}
        if raw_ids is not None:
            query["pk__in"] = [ObjectId(str(item)) for item in raw_ids]
        if pathids is not None:
            query["ptah_id__in"] = list(pathids)
        for data in raw_data.objects(**query):
            if data.action:
                continue
            action, confidence, reason_codes = self.classify_with_score(data)
            data.action = action
            data.class_confidence = confidence
            data.class_reason_codes = reason_codes
            data.rule = "path_score_v1"
            data.save()



