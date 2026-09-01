"""Pure scoring helpers extracted from the legacy analysis worker.

The functions in this module are deliberately storage and network agnostic.
They preserve the current endpoint classification and weak-relation score so
the P0 rule framework can compare old and new behavior without importing the
Mongo-backed analysis worker.
"""
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Sequence, Tuple


QUERY_API_KEYWORDS = (
    "get", "list", "query", "search", "detail", "info", "fetch", "count", "page", "find",
)
DOWNLOAD_API_KEYWORDS = (
    "download", "export", "file", "attachment", "report", "csv", "excel", "pdf",
)
UPLOAD_API_KEYWORDS = (
    "upload", "import", "multipart", "avatar", "attach", "upfile",
)
ADD_API_KEYWORDS = (
    "add", "create", "new", "insert", "register", "invite", "apply", "submit",
)
DELETE_API_KEYWORDS = (
    "delete", "remove", "del", "destroy", "revoke", "unbind", "deactivate",
)
MODIFY_API_KEYWORDS = (
    "modify", "update", "edit", "patch", "set", "change", "bind", "enable", "disable", "reset",
    "approve", "reject",
)
AUTH_API_KEYWORDS = (
    "login", "logout", "auth", "token", "oauth", "sso", "captcha", "verify", "password",
    "passwd", "otp", "mfa", "refresh",
)


@dataclass(frozen=True)
class ClassificationDetail:
    action: str
    confidence: int
    reason_codes: Tuple[str, ...]
    action_scores: Tuple[Tuple[str, int], ...]
    contributions: Tuple[Tuple[str, str, int], ...]


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def classify_endpoint_detail(endpoint: Any) -> ClassificationDetail:
    """Return the exact legacy classification plus bounded score evidence."""
    method = str(_field(endpoint, "method", "") or "").upper()
    path = str(_field(endpoint, "path", _field(endpoint, "path_template", "")) or "").lower()
    text = "{}{}".format(method, path)
    score: Dict[str, int] = {
        "Auth_Path": 0,
        "Download_Path": 0,
        "Upload_Path": 0,
        "D_Path": 0,
        "M_Path": 0,
        "C_Path": 0,
        "Q_Path": 0,
    }
    reasons = []
    contributions = []

    def add(action: str, points: int, reason: str) -> None:
        score[action] += points
        contributions.append((action, reason, points))

    if method in {"GET", "HEAD", "OPTIONS"}:
        add("Q_Path", 35, "METHOD_READONLY")
        reasons.append("METHOD_READONLY")
    elif method == "DELETE":
        add("D_Path", 35, "METHOD_DELETE")
        reasons.append("METHOD_DELETE")
    elif method in {"PUT", "PATCH"}:
        add("M_Path", 35, "METHOD_MODIFY")
        reasons.append("METHOD_MODIFY")
    elif method == "POST":
        add("C_Path", 25, "METHOD_POST")
        add("M_Path", 10, "METHOD_POST")
        reasons.append("METHOD_POST")

    keyword_groups = (
        (AUTH_API_KEYWORDS, "Auth_Path", 60, "KW_AUTH"),
        (DOWNLOAD_API_KEYWORDS, "Download_Path", 55, "KW_DOWNLOAD"),
        (UPLOAD_API_KEYWORDS, "Upload_Path", 55, "KW_UPLOAD"),
        (DELETE_API_KEYWORDS, "D_Path", 45, "KW_DELETE"),
        (MODIFY_API_KEYWORDS, "M_Path", 45, "KW_MODIFY"),
        (ADD_API_KEYWORDS, "C_Path", 45, "KW_CREATE"),
        (QUERY_API_KEYWORDS, "Q_Path", 35, "KW_QUERY"),
    )
    for words, action, points, reason in keyword_groups:
        if any(keyword in text for keyword in words):
            add(action, points, reason)
            reasons.append(reason)

    raw_req = _field(endpoint, "raw_req", None)
    if raw_req is None:
        has_body = bool(_field(endpoint, "has_request_body", False))
    else:
        has_body = bool(raw_req and any(item not in (None, b"", "") for item in raw_req))
    if has_body:
        add("C_Path", 10, "HAS_REQUEST_BODY")
        add("M_Path", 10, "HAS_REQUEST_BODY")
        reasons.append("HAS_REQUEST_BODY")

    statuses = _field(endpoint, "response_status_code", None)
    if statuses is None:
        statuses = _field(endpoint, "response_status_codes", ())
    status_set = set(statuses or ())
    if 204 in status_set or 201 in status_set:
        add("C_Path", 8, "STATUS_201_204")
        add("M_Path", 8, "STATUS_201_204")
        add("D_Path", 6, "STATUS_201_204")
        reasons.append("STATUS_201_204")

    best_action = max(score, key=score.get)
    confidence = int(score[best_action])
    if confidence < 40:
        best_action = "Q_Path"
        reasons.append("LOW_CONF_FALLBACK_Q")
    return ClassificationDetail(
        action=best_action,
        confidence=min(confidence, 100),
        reason_codes=tuple(reasons[:8]),
        action_scores=tuple((name, value) for name, value in score.items()),
        contributions=tuple(contributions),
    )


def classify_endpoint_with_score(endpoint: Any) -> Tuple[str, int, Sequence[str]]:
    detail = classify_endpoint_detail(endpoint)
    return detail.action, detail.confidence, list(detail.reason_codes)


def score_weak_relation(leaf_name: str, overlap_count: int, req_count: int,
                        res_count: int, used_name_fallback: bool = False) -> Tuple[float, Sequence[str]]:
    """Preserve the existing weak-relation score without persistence."""
    blacklist = {
        "page", "size", "offset", "sort", "order", "lang", "locale",
        "timestamp", "nonce", "token", "traceid",
    }
    score = 0.0
    reason_codes = []
    if overlap_count > 0:
        score += min(50.0, overlap_count * 10.0)
        reason_codes.append("OVERLAP_COUNT")
    maximum = max(req_count, res_count, 1)
    overlap_ratio = float(overlap_count) / float(maximum)
    if overlap_ratio >= 0.6:
        score += 25.0
        reason_codes.append("OVERLAP_RATIO_HIGH")
    elif overlap_ratio >= 0.3:
        score += 12.0
        reason_codes.append("OVERLAP_RATIO_MID")
    if leaf_name and leaf_name.lower() not in blacklist:
        score += 15.0
        reason_codes.append("LEAF_NOT_BLACKLIST")
    if used_name_fallback:
        score += 8.0
        reason_codes.append("NAME_FALLBACK")
    return round(min(100.0, score), 2), reason_codes
