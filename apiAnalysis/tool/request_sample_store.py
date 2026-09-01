import datetime
import hashlib
import json
from urllib.parse import urlparse

from apiAnalysis.db.collection import request_sample
from apiAnalysis.tool.api_signature import body_shape_signature, query_key_signature, route_query_signature


MAX_SAMPLES_PER_API = 10
FULL_RESPONSE_SAMPLE_LIMIT = 2048


def _body_len(value):
    if value is None:
        return 0
    if isinstance(value, bytes):
        return len(value)
    return len(str(value).encode("utf-8", errors="ignore"))


def _body_hash(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        raw = value
    else:
        raw = str(value).encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()


def _sample_response(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value[:FULL_RESPONSE_SAMPLE_LIMIT]
    text = str(value)
    return text[:FULL_RESPONSE_SAMPLE_LIMIT]


def sample_signature(method, url, path, query, body, headers=None):
    parsed = urlparse(url or "")
    header_keys = []
    for key in (headers or {}).keys():
        lower_key = str(key).lower()
        if lower_key in {"authorization", "cookie", "x-token", "x-csrf-token"}:
            header_keys.append(lower_key)
    payload = {
        "method": (method or "GET").upper(),
        "path": path or parsed.path,
        "route_query": route_query_signature(path or parsed.path, query),
        "query_keys": query_key_signature(query),
        "body_shape": body_shape_signature(body),
        "auth_shape": sorted(set(header_keys)),
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def save_request_sample(data, method, url, path, domain, query, headers, body, response_status_code, response_body,
                        project_id="", env_id="", account_id="", import_run_id="", observation_id="",
                        source="traffic"):
    signature = sample_signature(method, url, path, query, body, headers=headers)
    now = datetime.datetime.utcnow()
    sample = request_sample.objects(raw_data=data, sample_signature=signature).first()
    if sample:
        sample.hit_count = (sample.hit_count or 0) + 1
        sample.last_seen = now
        sample.response_status_code = response_status_code
        sample.response_len = _body_len(response_body)
        sample.response_hash = _body_hash(response_body)
        sample.project_id = project_id or sample.project_id
        sample.env_id = env_id or sample.env_id
        sample.account_id = account_id or sample.account_id
        sample.import_run_id = import_run_id or sample.import_run_id
        sample.observation_id = observation_id or sample.observation_id
        sample.source = source or sample.source or "traffic"
        if sample.response_sample in [None, ""]:
            sample.response_sample = _sample_response(response_body)
        sample.save()
        return sample

    count = request_sample.objects(raw_data=data).count()
    if count >= MAX_SAMPLES_PER_API:
        return None

    sample = request_sample(
        pathid=data.ptah_id,
        raw_data=data,
        sample_signature=signature,
        source=source or "traffic",
        project_id=project_id or "",
        env_id=env_id or "",
        account_id=account_id or "",
        import_run_id=import_run_id or "",
        observation_id=observation_id or "",
        method=(method or "GET").upper(),
        url=url,
        path=path,
        domain=domain,
        query=query or {},
        headers=headers or {},
        body=body,
        body_shape=body_shape_signature(body),
        response_status_code=response_status_code,
        response_len=_body_len(response_body),
        response_hash=_body_hash(response_body),
        response_sample=_sample_response(response_body),
        ctime=now,
        last_seen=now,
    )
    sample.save()
    return sample


def best_request_sample(data, *, project_id="", env_id="", account_id=""):
    """Return the newest sample without crossing an explicit runtime context."""
    query = {"raw_data": data}
    if project_id:
        query["project_id"] = str(project_id)
    if env_id:
        query["env_id"] = str(env_id)
    if account_id:
        query["account_id"] = str(account_id)
    return request_sample.objects(**query).order_by("-last_seen").first()
