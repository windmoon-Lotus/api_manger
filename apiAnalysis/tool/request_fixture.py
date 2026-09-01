"""Reusable, non-auth request inputs for relation and chain validation."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
from types import SimpleNamespace
from typing import Any, Dict, Mapping, Optional, Sequence

from apiAnalysis.db.collection import (
    ProjectRequestFixture,
    ProjectRequestFixtureEvent,
    ProjectRequestFixtureRevision,
    raw_data,
    req_data,
)
from apiAnalysis.tool.compose_request import build_request_payload, render_request_url
from apiAnalysis.tool.parameter_locator import extract_values_at_locator


AUTH_HEADER_NAMES = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-access-token", "x-auth-token",
}
AUTH_PARAMETER_NAMES = {
    "authorization", "cookie", "token", "access_token", "refresh_token",
    "session", "sessionid", "sid", "csrf", "xsrf", "signature", "sign",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _fixture_id(project_id: str, env_id: str, pathid: int,
                profile_id: str, name: str) -> str:
    raw = "\x00".join([
        _text(project_id), _text(env_id), str(int(pathid)),
        _text(profile_id), _text(name) or "default",
    ])
    return "request-fixture-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _fixture_payload_sha256(query: Mapping[str, Any], headers: Mapping[str, Any],
                            path_params: Mapping[str, Any], body: Any, note: str) -> str:
    encoded = json.dumps({
        "query": dict(query or {}),
        "headers": dict(headers or {}),
        "path_params": dict(path_params or {}),
        "body": body,
        "note": _text(note)[:500],
    }, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _append_fixture_event(fixture: ProjectRequestFixture, event_type: str, *,
                          actor: str = "", reason: str = "",
                          from_lifecycle: str = "", revision_id: str = ""):
    event = ProjectRequestFixtureEvent(
        fixture_id=fixture.fixture_id,
        fixture_revision_id=revision_id or fixture.current_revision_id or "",
        event_type=event_type,
        from_lifecycle=from_lifecycle,
        to_lifecycle=fixture.lifecycle,
        actor=_text(actor)[:120],
        reason=_text(reason)[:500],
    )
    event.save()
    return event


def _mapping(value: Any, field: str) -> Dict[str, Any]:
    if value in (None, ""):
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("{} 必须是 JSON 对象".format(field))
    return {str(key): copy.deepcopy(item) for key, item in value.items()}


def _validate_non_auth_headers(headers: Mapping[str, Any]) -> None:
    forbidden = sorted(
        str(key) for key in headers
        if str(key).strip().lower() in AUTH_HEADER_NAMES
    )
    if forbidden:
        raise ValueError(
            "认证 Header 由账号认证方案自动刷新，测试数据模板不能保存：{}".format(
                ", ".join(forbidden)
            )
        )


def _validate_non_auth_payload(value: Any, field: str, path: str = "") -> None:
    """Fixture revisions contain business inputs only, never authentication material."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key).strip().lower().replace("-", "_")
            location = "{}.{}".format(path, key).strip(".")
            if name in AUTH_PARAMETER_NAMES:
                raise ValueError(
                    "{} 中的认证字段由认证方案管理，测试数据模板不能保存：{}".format(
                        field, location,
                    )
                )
            _validate_non_auth_payload(item, field, location)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_non_auth_payload(item, field, "{}[{}]".format(path, index))
    elif isinstance(value, str):
        lowered = value.strip().lower()
        if lowered.startswith("bearer ") or "-----begin private key-----" in lowered:
            raise ValueError("{} 包含疑似认证材料，测试数据模板不能保存".format(field))


def get_request_fixture(project_id: str, env_id: str, pathid: int,
                        profile_id: str = "", name: str = "default") -> Optional[ProjectRequestFixture]:
    return ProjectRequestFixture.objects(
        project_id=_text(project_id), env_id=_text(env_id), pathid=int(pathid),
        profile_id=_text(profile_id), name=_text(name) or "default", active=True,
    ).first()


def save_request_fixture(project_id: str, env_id: str, pathid: int, *,
                         profile_id: str = "", name: str = "default",
                         query: Optional[Mapping[str, Any]] = None,
                         headers: Optional[Mapping[str, Any]] = None,
                         path_params: Optional[Mapping[str, Any]] = None,
                         body: Any = None, note: str = "",
                         operator: str = "") -> ProjectRequestFixture:
    query = _mapping(query, "Query")
    headers = _mapping(headers, "Header")
    path_params = _mapping(path_params, "Path")
    _validate_non_auth_headers(headers)
    _validate_non_auth_payload(query, "Query")
    _validate_non_auth_payload(path_params, "Path")
    _validate_non_auth_payload(body, "Body")
    endpoint = raw_data.objects(ptah_id=int(pathid), project_id=_text(project_id)).first()
    if not endpoint:
        raise ValueError("测试数据模板对应的接口不存在或不属于当前项目")
    now = dt.datetime.utcnow()
    fixture = ProjectRequestFixture.objects(
        project_id=_text(project_id), env_id=_text(env_id), pathid=int(pathid),
        profile_id=_text(profile_id), name=_text(name) or "default",
    ).first()
    created = fixture is None
    previous_lifecycle = _text(getattr(fixture, "lifecycle", "")) if fixture else ""
    previous_revision_id = _text(getattr(fixture, "current_revision_id", "")) if fixture else ""
    if fixture and fixture.lifecycle == ProjectRequestFixture.ARCHIVED:
        raise ValueError("archived fixture is immutable; create a new named fixture")
    if not fixture:
        fixture = ProjectRequestFixture(
            fixture_id=_fixture_id(project_id, env_id, pathid, profile_id, name),
            project_id=_text(project_id), env_id=_text(env_id), pathid=int(pathid),
            profile_id=_text(profile_id), name=_text(name) or "default", ctime=now,
        )
    payload_sha256 = _fixture_payload_sha256(query, headers, path_params, body, note)
    revision = ProjectRequestFixtureRevision.objects(
        fixture_id=fixture.fixture_id,
        payload_sha256=payload_sha256,
    ).first()
    revision_created = revision is None
    if not revision:
        latest_revision = ProjectRequestFixtureRevision.objects(
            fixture_id=fixture.fixture_id,
        ).order_by("-revision_no").only("revision_no").first()
        revision_no = int(getattr(latest_revision, "revision_no", 0) or 0) + 1
        revision = ProjectRequestFixtureRevision(
            fixture_revision_id="{}-r{}-{}".format(
                fixture.fixture_id, revision_no, payload_sha256[:12],
            ),
            fixture_id=fixture.fixture_id,
            revision_no=revision_no,
            payload_sha256=payload_sha256,
            query=copy.deepcopy(query),
            headers=copy.deepcopy(headers),
            path_params=copy.deepcopy(path_params),
            body=copy.deepcopy(body),
            note=_text(note)[:500],
            created_by=_text(operator)[:120],
        )
        revision.save(force_insert=True)
    fixture.query = query
    fixture.headers = headers
    fixture.path_params = path_params
    fixture.body = copy.deepcopy(body)
    fixture.note = _text(note)[:500]
    fixture.modificator = _text(operator)[:120]
    fixture.active = True
    fixture.lifecycle = ProjectRequestFixture.ACTIVE
    fixture.current_revision_id = revision.fixture_revision_id
    fixture.current_revision_no = int(revision.revision_no)
    fixture.payload_sha256 = payload_sha256
    fixture.mtime = now
    fixture.save()
    if created:
        _append_fixture_event(
            fixture, ProjectRequestFixtureEvent.CREATED,
            actor=operator, revision_id=revision.fixture_revision_id,
        )
    elif previous_lifecycle != ProjectRequestFixture.ACTIVE:
        _append_fixture_event(
            fixture, ProjectRequestFixtureEvent.ACTIVATED,
            actor=operator, from_lifecycle=previous_lifecycle,
            revision_id=revision.fixture_revision_id,
        )
    elif previous_revision_id != revision.fixture_revision_id:
        _append_fixture_event(
            fixture,
            (
                ProjectRequestFixtureEvent.REVISED
                if revision_created else ProjectRequestFixtureEvent.ACTIVATED
            ),
            actor=operator,
            reason="new immutable fixture revision" if revision_created else "activated existing revision",
            from_lifecycle=previous_lifecycle,
            revision_id=revision.fixture_revision_id,
        )
    return fixture


def activate_fixture_revision(fixture_id: str, fixture_revision_id: str, *,
                              operator: str = "", reason: str = "") -> ProjectRequestFixture:
    fixture = ProjectRequestFixture.objects(fixture_id=_text(fixture_id)).first()
    revision = ProjectRequestFixtureRevision.objects(
        fixture_id=_text(fixture_id),
        fixture_revision_id=_text(fixture_revision_id),
    ).first()
    if not fixture or not revision:
        raise ValueError("fixture or revision not found")
    if fixture.lifecycle == ProjectRequestFixture.ARCHIVED:
        raise ValueError("archived fixture cannot be activated")
    if (
        fixture.lifecycle == ProjectRequestFixture.ACTIVE
        and fixture.current_revision_id == revision.fixture_revision_id
    ):
        return fixture
    previous = fixture.lifecycle
    fixture.query = copy.deepcopy(revision.query or {})
    fixture.headers = copy.deepcopy(revision.headers or {})
    fixture.path_params = copy.deepcopy(revision.path_params or {})
    fixture.body = copy.deepcopy(revision.body)
    fixture.note = revision.note or ""
    fixture.current_revision_id = revision.fixture_revision_id
    fixture.current_revision_no = revision.revision_no
    fixture.payload_sha256 = revision.payload_sha256
    fixture.lifecycle = ProjectRequestFixture.ACTIVE
    fixture.active = True
    fixture.modificator = _text(operator)[:120]
    fixture.mtime = dt.datetime.utcnow()
    fixture.save()
    _append_fixture_event(
        fixture, ProjectRequestFixtureEvent.ACTIVATED,
        actor=operator, reason=reason, from_lifecycle=previous,
        revision_id=revision.fixture_revision_id,
    )
    return fixture


def deactivate_request_fixture(fixture_id: str, *, operator: str = "",
                               reason: str = "") -> ProjectRequestFixture:
    fixture = ProjectRequestFixture.objects(fixture_id=_text(fixture_id)).first()
    if not fixture:
        raise ValueError("fixture not found")
    if fixture.lifecycle == ProjectRequestFixture.ARCHIVED:
        raise ValueError("archived fixture cannot be deactivated")
    if fixture.lifecycle == ProjectRequestFixture.INACTIVE:
        return fixture
    previous = fixture.lifecycle
    fixture.lifecycle = ProjectRequestFixture.INACTIVE
    fixture.active = False
    fixture.modificator = _text(operator)[:120]
    fixture.mtime = dt.datetime.utcnow()
    fixture.save()
    _append_fixture_event(
        fixture, ProjectRequestFixtureEvent.DEACTIVATED,
        actor=operator, reason=reason, from_lifecycle=previous,
    )
    return fixture


def archive_request_fixture(fixture_id: str, *, operator: str = "",
                            reason: str = "") -> ProjectRequestFixture:
    fixture = ProjectRequestFixture.objects(fixture_id=_text(fixture_id)).first()
    if not fixture:
        raise ValueError("fixture not found")
    if fixture.lifecycle == ProjectRequestFixture.ARCHIVED:
        return fixture
    previous = fixture.lifecycle
    fixture.lifecycle = ProjectRequestFixture.ARCHIVED
    fixture.active = False
    fixture.modificator = _text(operator)[:120]
    fixture.mtime = dt.datetime.utcnow()
    fixture.save()
    _append_fixture_event(
        fixture, ProjectRequestFixtureEvent.ARCHIVED,
        actor=operator, reason=reason, from_lifecycle=previous,
    )
    return fixture


def fixture_history(fixture_id: str) -> Dict[str, Any]:
    fixture = ProjectRequestFixture.objects(fixture_id=_text(fixture_id)).first()
    if not fixture:
        raise ValueError("fixture not found")
    return {
        "fixture": fixture,
        "revisions": list(ProjectRequestFixtureRevision.objects(
            fixture_id=fixture.fixture_id,
        ).order_by("-revision_no")),
        "events": list(ProjectRequestFixtureEvent.objects(
            fixture_id=fixture.fixture_id,
        ).order_by("-ctime")),
    }


def fixture_payload(fixture: Optional[Any]) -> Dict[str, Any]:
    if not fixture:
        return {"query": {}, "headers": {}, "path_params": {}, "body": None}
    if isinstance(fixture, Mapping):
        return {
            "query": copy.deepcopy(dict(fixture.get("query") or {})),
            "headers": copy.deepcopy(dict(fixture.get("headers") or {})),
            "path_params": copy.deepcopy(dict(fixture.get("path_params") or {})),
            "body": copy.deepcopy(fixture.get("body")),
        }
    return {
        "query": copy.deepcopy(dict(fixture.query or {})),
        "headers": copy.deepcopy(dict(fixture.headers or {})),
        "path_params": copy.deepcopy(dict(fixture.path_params or {})),
        "body": copy.deepcopy(fixture.body),
    }


def _deep_merge(base: Any, overlay: Any) -> Any:
    if isinstance(base, dict) and isinstance(overlay, Mapping):
        result = copy.deepcopy(base)
        for key, value in overlay.items():
            result[str(key)] = _deep_merge(result.get(str(key)), value)
        return result
    return copy.deepcopy(overlay)


def apply_request_fixture(snapshot: Any, fixture: Optional[Any], *,
                          url_template: str = "") -> Any:
    """Overlay business inputs without touching AccountContext auth values."""
    values = fixture_payload(fixture)
    snapshot.query = dict(getattr(snapshot, "query", None) or {})
    snapshot.query.update(values["query"])
    snapshot.headers = dict(getattr(snapshot, "headers", None) or {})
    snapshot.headers.update(values["headers"])
    snapshot.path_params = dict(getattr(snapshot, "path_params", None) or {})
    snapshot.path_params.update(values["path_params"])
    if values["body"] is not None:
        snapshot.body = _deep_merge(getattr(snapshot, "body", None), values["body"])
    if url_template:
        snapshot.url = str(url_template)
    snapshot.url = render_request_url({
        "url": getattr(snapshot, "url", ""),
        "query": snapshot.query,
        "path_params": snapshot.path_params,
    })
    sources = dict(getattr(snapshot, "parameter_sources", None) or {})
    for position, mapping in (
        ("query", values["query"]), ("header", values["headers"]),
        ("path", values["path_params"]),
    ):
        for name in mapping:
            sources[str(name)] = {"position": position, "source": "request_fixture"}
    if values["body"] is not None:
        sources["$body"] = {"position": "body", "source": "request_fixture"}
    snapshot.parameter_sources = sources
    return snapshot


def _present(snapshot: Any, entry: Any) -> bool:
    position = _text(entry.position or "body").lower()
    name = _text(entry.parameter)
    if position == "body":
        return bool(extract_values_at_locator(getattr(snapshot, "body", None), entry.locator or {}))
    mapping_name = {
        "query": "query", "header": "headers", "path": "path_params", "cookie": "cookies",
    }.get(position)
    values = dict(getattr(snapshot, mapping_name, None) or {}) if mapping_name else {}
    if position == "header":
        return any(str(key).lower() == name.lower() and value not in (None, "") for key, value in values.items())
    return name in values and values.get(name) not in (None, "")


def _relation_target_identity(target: Any) -> Dict[str, str]:
    if isinstance(target, Mapping):
        locator = dict(target.get("locator") or {})
        return {
            "position": _text(target.get("position") or "body").lower(),
            "parameter": _text(target.get("parameter")),
            "pointer": _text(locator.get("json_pointer") or locator.get("schema_path")),
        }
    values = list(target or []) if isinstance(target, (tuple, list)) else []
    return {
        "position": _text(values[0] if values else "body").lower(),
        "parameter": _text(values[1] if len(values) > 1 else ""),
        "pointer": "",
    }


def request_input_view(pathid: int, project_id: str, env_id: str,
                       profile_id: str = "", *,
                       account_id: str = "",
                       relation_targets: Sequence[Any] = ()) -> Dict[str, Any]:
    """Describe how every required input will be supplied, without values."""
    endpoint = raw_data.objects(ptah_id=int(pathid), project_id=_text(project_id)).first()
    if not endpoint:
        return {}
    fixture = get_request_fixture(project_id, env_id, pathid, profile_id)
    payload = build_request_payload(
        int(pathid), project_id=_text(project_id), env_id=_text(env_id),
        account_id=_text(account_id) or _text(profile_id),
        auth_mode="account", source="fixture_preview",
    )
    snapshot = SimpleNamespace(**{
        "url": payload.get("url") or endpoint.url,
        "query": copy.deepcopy(payload.get("query") or {}),
        "headers": copy.deepcopy(payload.get("headers") or {}),
        "cookies": copy.deepcopy(payload.get("cookies") or {}),
        "path_params": copy.deepcopy(payload.get("path_params") or {}),
        "body": copy.deepcopy(payload.get("body")),
        "parameter_sources": copy.deepcopy(payload.get("parameter_sources") or {}),
    })
    apply_request_fixture(snapshot, fixture, url_template=endpoint.url)
    relation_identities = [_relation_target_identity(item) for item in relation_targets]
    fields = []
    gaps = []
    coverage = {"relation": 0, "fixture": 0, "automatic": 0, "auth": 0, "missing": 0}
    fixture_values = fixture_payload(fixture)
    for entry in req_data.objects(raw_data=endpoint).order_by("position", "parameter"):
        position = _text(entry.position or "body").lower()
        name = _text(entry.parameter)
        locator = dict(entry.locator or {})
        pointer = _text(locator.get("json_pointer") or locator.get("schema_path"))
        source_meta = dict((payload.get("parameter_sources") or {}).get(name) or {})
        relation_supplied = any(
            target["position"] == position
            and target["parameter"] == name
            and (not target["pointer"] or not pointer or target["pointer"] == pointer)
            for target in relation_identities
        )
        if relation_supplied:
            source = "relation"
        elif position == "body" and fixture_values["body"] is not None and _present(snapshot, entry):
            source = "fixture"
        elif position in {"query", "header", "path"} and name in fixture_values.get(
                {"query": "query", "header": "headers", "path": "path_params"}[position], {}):
            source = "fixture"
        elif position == "cookie" or name.lower().replace("-", "_") in AUTH_PARAMETER_NAMES:
            source = "auth"
        elif source_meta.get("source") not in {"", "empty_default", "omitted_empty_optional"} and _present(snapshot, entry):
            source = "automatic"
        else:
            source = "missing"
        coverage[source] += 1
        item = {
            "parameter": name,
            "position": position,
            "required": bool(entry.required),
            "type": _text(entry.type),
            "source": source,
            "locator": pointer,
        }
        fields.append(item)
        if item["required"] and source == "missing":
            gaps.append(item)
    return {
        "fixture": fixture,
        "fixture_id": fixture.fixture_id if fixture else "",
        "pathid": int(pathid),
        "method": _text(endpoint.method).upper(),
        "path": _text(endpoint.path),
        "coverage": coverage,
        "fields": fields,
        "gaps": gaps,
        "ready": not gaps,
        "query_json": json.dumps(fixture_values["query"], ensure_ascii=False, indent=2),
        "headers_json": json.dumps(fixture_values["headers"], ensure_ascii=False, indent=2),
        "path_json": json.dumps(fixture_values["path_params"], ensure_ascii=False, indent=2),
        "body_json": "" if fixture_values["body"] is None else json.dumps(
            fixture_values["body"], ensure_ascii=False, indent=2,
        ),
        "note": _text(getattr(fixture, "note", "")),
    }
