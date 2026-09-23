"""Persisted, reusable read-chain definitions over the existing snapshot contract.

This module turns a proven multi-step read chain (for example
network list -> network members -> member line) into an explicit, reviewable
artifact instead of a one-off runner script.

Design boundaries:

* Definitions are declarative. They carry path templates (including Apifox
  ``{{name}}`` placeholders), request parameter position/type, upstream response
  references and account-profile *references*. They never carry credentials,
  tokens or raw business IDs.
* Resolution is in memory. Upstream references are resolved against the JSON
  values of earlier responses; a missing or empty required source blocks every
  dependent step and records the reason. Values are never guessed.
* Nothing here opens a socket on import. Live execution lives in
  :func:`replay_chain_live` and requires an explicit acknowledgement flag; the
  CLI additionally requires an operator confirmation switch.
* Results reuse the existing execution contract (``security_test_run`` /
  ``security_test_result``) and the bounded, body-free evidence sanitiser. An
  ordinary HTTP 2xx is recorded as ``not_evaluable``/``adapter_judge_required``,
  never as a security verdict.
"""
import copy
import hashlib
import json
import re
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from apiAnalysis.db.collection import interface_chain_definition, raw_data


CHAIN_SCHEMA_VERSION = "interface-chain.v1"
CHAIN_ADAPTER_ID = "interface_chain"
CHAIN_CHECK_TYPE = "read_chain_replay"

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
PARAMETER_POSITIONS = frozenset({"path", "query", "header", "body", "cookie"})
PARAMETER_SOURCES = frozenset({"constant", "upstream_ref"})
PLACEHOLDER_STYLES = frozenset({
    "none", "apifox_double_brace", "openapi_single_brace", "colon",
})
ACCOUNT_AUTH_MODES = frozenset({"account", "anonymous", "inherit"})

# Reasons a step (or the whole chain) cannot be executed.
SOURCE_NOT_BOUND = "SOURCE_NOT_BOUND"
UPSTREAM_STEP_BLOCKED = "UPSTREAM_STEP_BLOCKED"
UPSTREAM_STEP_FAILED = "UPSTREAM_STEP_FAILED"
MISSING_UPSTREAM_REF = "MISSING_UPSTREAM_REF"
EMPTY_REQUIRED_SOURCE = "EMPTY_REQUIRED_SOURCE"
UNRESOLVED_PATH_PARAMETER = "UNRESOLVED_PATH_PARAMETER"
MISSING_REQUIRED_PARAMETER = "MISSING_REQUIRED_PARAMETER"
NON_READ_METHOD = "NON_READ_METHOD"
OPTIONAL_UPSTREAM_REF_EMPTY = "OPTIONAL_UPSTREAM_REF_EMPTY"
STEP_REQUEST_FAILED = "STEP_REQUEST_FAILED"
STEP_STATUS_UNEXPECTED = "STEP_STATUS_UNEXPECTED"
LIVE_NOT_CONFIRMED = "LIVE_NOT_CONFIRMED"

# Keys that must never appear anywhere in a definition.
_FORBIDDEN_KEYS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie", "cookies",
    "token", "access_token", "refresh_token", "id_token", "session",
    "session_id", "sessionid", "password", "passwd", "pwd", "secret",
    "client_secret", "private_key", "apikey", "api_key", "credential",
    "credentials", "bearer", "sign", "signature", "auth_header",
})

_SECRET_VALUE_PATTERNS = (
    ("jwt", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("bearer", re.compile(r"(?i)\bbearer\s+\S{8,}")),
    ("known_token", re.compile(r"(?<![A-Za-z0-9])(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{24,}|sk-[A-Za-z0-9_-]{20,})")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("long_hex", re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{16,}(?![0-9A-Za-z])")),
    ("long_base64", re.compile(r"(?<![0-9A-Za-z+/])[A-Za-z0-9+/]{40,}={0,2}(?![0-9A-Za-z+/=])")),
    ("long_digit_run", re.compile(r"(?<![0-9])[0-9]{8,}(?![0-9])")),
)

_PATH_PLACEHOLDER_RE = re.compile(
    r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}"
    r"|\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}"
    r"|(?<![A-Za-z0-9_]):([A-Za-z_][A-Za-z0-9_]*)"
)
_REF_HEAD_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(.*)$")
_REF_FIELD_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)")
_REF_INDEX_RE = re.compile(r"^\[(\d+)\]")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,80}$")

_SENSITIVE_KEY_HINT_RE = re.compile(
    r"(?i)(authorization|cookie|token|secret|passw|credential|api[_-]?key|private[_-]?key|session)"
)


class ChainDefinitionError(ValueError):
    """Raised when a chain definition is malformed, unsafe, or unresolvable."""


class ChainLiveExecutionNotConfirmed(ChainDefinitionError):
    """Raised when live chain execution is attempted without acknowledgement."""


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _as_int(value: Any, field: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ChainDefinitionError("{} must be an integer".format(field))


def _is_empty_source(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


# ---------------------------------------------------------------------------
# Path templates: Apifox ``{{name}}`` and OpenAPI ``{name}`` / ``:name``
# ---------------------------------------------------------------------------

def placeholder_names(path_template: str) -> List[str]:
    """Return unique placeholder names in declaration order."""
    names: List[str] = []
    for match in _PATH_PLACEHOLDER_RE.finditer(_text(path_template)):
        name = match.group(1) or match.group(2) or match.group(3)
        if name and name not in names:
            names.append(name)
    return names


def detect_placeholder_style(path_template: str) -> str:
    """Report which placeholder family a template uses.

    Apifox exports ``/networks/{{network_id}}/members`` while the older
    OpenAPI/Apifox single-brace form is ``/networks/{network_id}/nats``. Both
    occur in the same imported project, so callers must not assume one style.
    """
    text = _text(path_template)
    if "{{" in text and "}}" in text:
        return "apifox_double_brace"
    if _PATH_PLACEHOLDER_RE.search(text) is None:
        return "none"
    if re.search(r"\{\s*[A-Za-z_][A-Za-z0-9_]*\s*\}", text):
        return "openapi_single_brace"
    return "colon"


def canonical_path_template(path_template: str) -> str:
    """Normalise every placeholder form to ``{name}`` for comparison."""
    return _PATH_PLACEHOLDER_RE.sub(
        lambda match: "{" + (match.group(1) or match.group(2) or match.group(3)) + "}",
        _text(path_template),
    )


def render_path_template(path_template: str, values: Mapping[str, Any]) -> Tuple[str, List[str]]:
    """Render a path template, returning ``(path, missing_names)``.

    Values are URL-encoded and empty values are reported as missing; a path
    segment is never silently collapsed.
    """
    values = values or {}
    missing: List[str] = []

    def replace(match: re.Match) -> str:
        name = match.group(1) or match.group(2) or match.group(3)
        value = values.get(name)
        if value is None or value == "":
            if name not in missing:
                missing.append(name)
            return match.group(0)
        return quote(str(value), safe="")

    return _PATH_PLACEHOLDER_RE.sub(replace, _text(path_template)), missing


# ---------------------------------------------------------------------------
# Upstream response references
# ---------------------------------------------------------------------------

def parse_upstream_ref(ref: str) -> Tuple[str, List[Any]]:
    """Split ``r_networks.list[0].network_id`` into ``(response_ref, path)``.

    Both ``list[0].id`` and the redacted-evidence ``list.0.id`` form are
    accepted so a definition can be traced back to the audit summary it came
    from without rewriting indices.
    """
    text = _text(ref)
    head = _REF_HEAD_RE.match(text)
    if not head:
        raise ChainDefinitionError("invalid upstream ref: {}".format(text or "<empty>"))
    response_ref, remainder = head.group(1), head.group(2)
    segments: List[Any] = []
    rest = remainder
    while rest:
        if rest.startswith("."):
            field = _REF_FIELD_RE.match(rest[1:])
            if not field:
                raise ChainDefinitionError("invalid upstream ref segment: {}".format(text))
            name = field.group(1)
            segments.append(int(name) if name.isdigit() else name)
            rest = rest[1 + field.end():]
        if rest.startswith("["):
            index = _REF_INDEX_RE.match(rest)
            if not index:
                raise ChainDefinitionError("invalid upstream ref index: {}".format(text))
            segments.append(int(index.group(1)))
            rest = rest[index.end():]
        elif rest and not rest.startswith("."):
            raise ChainDefinitionError("invalid upstream ref segment: {}".format(text))
    if not segments:
        raise ChainDefinitionError("upstream ref must address a field: {}".format(text))
    return response_ref, segments


def resolve_upstream_ref(sources: Mapping[str, Any], ref: str) -> Tuple[bool, Any]:
    """Walk an upstream reference through captured response JSON.

    Returns ``(found, value)``. ``found`` is false when any container key or
    list index is absent, so an empty optional source is distinguishable from a
    genuinely missing one.
    """
    response_ref, segments = parse_upstream_ref(ref)
    current: Any = (sources or {}).get(response_ref)
    if current is None and response_ref not in (sources or {}):
        return False, None
    for segment in segments:
        if isinstance(segment, int):
            if not isinstance(current, (list, tuple)) or segment >= len(current):
                return False, None
            current = current[segment]
        else:
            if not isinstance(current, Mapping) or segment not in current:
                return False, None
            current = current[segment]
    return True, current


# ---------------------------------------------------------------------------
# Secrets / raw identifier guard
# ---------------------------------------------------------------------------

def _scan_value(value: Any, pointer: str, findings: List[Dict[str, str]],
                strict_ids: bool = False) -> None:
    """Walk a definition and record secret or raw-identifier findings.

    ``strict_ids`` is set for the keys that can carry an executable value
    (``value``, ``path_template``); provenance keys such as ``source_ref`` are
    still scanned for tokens but may legitimately contain a date like
    ``20260915`` and must not be mistaken for a raw business identifier.
    """
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = _text(key)
            if key_text.lower() in _FORBIDDEN_KEYS:
                findings.append({"pointer": "{}.{}".format(pointer, key_text), "rule": "forbidden_key"})
            _scan_value(
                item, "{}.{}".format(pointer, key_text), findings,
                strict_ids=strict_ids or key_text in {"value", "path_template"},
            )
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _scan_value(item, "{}[{}]".format(pointer, index), findings, strict_ids=strict_ids)
        return
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if strict_ids and abs(value) > 99999999:
            findings.append({"pointer": pointer, "rule": "large_integer_identifier"})
        return
    if not isinstance(value, str):
        return
    for rule, pattern in _SECRET_VALUE_PATTERNS:
        if rule == "long_digit_run" and not strict_ids:
            continue
        if pattern.search(value):
            findings.append({"pointer": pointer, "rule": rule})
            return


def scan_definition_secrets(definition: Mapping[str, Any]) -> List[Dict[str, str]]:
    """Return every secret/raw-identifier finding in a definition."""
    findings: List[Dict[str, str]] = []
    _scan_value(definition, "$", findings)
    return findings


def assert_no_secrets(definition: Mapping[str, Any]) -> None:
    findings = scan_definition_secrets(definition)
    if findings:
        detail = ", ".join("{}:{}".format(item["pointer"], item["rule"]) for item in findings[:5])
        raise ChainDefinitionError(
            "chain definition would persist secrets or raw identifiers: {}".format(detail)
        )


# ---------------------------------------------------------------------------
# Normalisation and validation
# ---------------------------------------------------------------------------

def _normalize_parameter(raw: Mapping[str, Any], step_id: str) -> Dict[str, Any]:
    name = _text(raw.get("name"))
    if not name:
        raise ChainDefinitionError("{}: parameter name is required".format(step_id))
    position = _text(raw.get("position")).lower()
    if position not in PARAMETER_POSITIONS:
        raise ChainDefinitionError(
            "{}:{}: unsupported parameter position '{}'".format(step_id, name, position)
        )
    source = _text(raw.get("source")).lower()
    if source not in PARAMETER_SOURCES:
        raise ChainDefinitionError(
            "{}:{}: unsupported parameter source '{}'".format(step_id, name, source)
        )
    if _SENSITIVE_KEY_HINT_RE.search(name):
        raise ChainDefinitionError(
            "{}:{}: credentials must come from an account profile, never a parameter".format(step_id, name)
        )
    parameter: Dict[str, Any] = {
        "name": name,
        "position": position,
        "type": _text(raw.get("type")) or "string",
        "required": bool(raw.get("required", False)),
        "source": source,
    }
    if _text(raw.get("description")):
        parameter["description"] = _text(raw.get("description"))
    if source == "upstream_ref":
        ref = _text(raw.get("ref"))
        if not ref:
            raise ChainDefinitionError("{}:{}: upstream_ref requires ref".format(step_id, name))
        parse_upstream_ref(ref)
        parameter["ref"] = ref
        parameter["required_non_empty"] = bool(raw.get("required_non_empty", position == "path"))
        if _text(raw.get("source_response_ref")):
            parameter["source_response_ref"] = _text(raw.get("source_response_ref"))
    else:
        if "value" not in raw:
            raise ChainDefinitionError(
                "{}:{}: constant parameter requires an explicit value".format(step_id, name)
            )
        parameter["value"] = raw.get("value")
    return parameter


def _normalize_step(raw: Mapping[str, Any], index: int) -> Dict[str, Any]:
    step_id = _text(raw.get("step_id"))
    if not step_id:
        raise ChainDefinitionError("step {}: step_id is required".format(index))
    path_template = _text(raw.get("path_template"))
    if not path_template:
        raise ChainDefinitionError("{}: path_template is required".format(step_id))
    method = _text(raw.get("method")).upper()
    if method not in READ_METHODS:
        raise ChainDefinitionError(
            "{}: read chains only support GET/HEAD/OPTIONS, got '{}'".format(step_id, method or "<empty>")
        )
    response_ref = _text(raw.get("response_ref"))
    if not response_ref:
        raise ChainDefinitionError("{}: response_ref is required".format(step_id))
    step: Dict[str, Any] = {
        "step_id": step_id,
        "response_ref": response_ref,
        "pathid": _as_int(raw.get("pathid"), "{}:pathid".format(step_id)),
        "method": method,
        "path_template": path_template,
        "placeholder_style": detect_placeholder_style(path_template),
        "account_profile": _text(raw.get("account_profile")),
        "parameters": [
            _normalize_parameter(item or {}, step_id) for item in (raw.get("parameters") or [])
        ],
    }
    if _text(raw.get("description")):
        step["description"] = _text(raw.get("description"))
    if raw.get("depends_on"):
        step["depends_on"] = [_text(item) for item in raw.get("depends_on") or [] if _text(item)]
    return step


def _normalize_account_profiles(raw: Any) -> List[Dict[str, Any]]:
    profiles: List[Dict[str, Any]] = []
    seen = set()
    for item in raw or []:
        item = item or {}
        alias = _text(item.get("alias"))
        if not alias:
            raise ChainDefinitionError("account profile alias is required")
        if alias in seen:
            raise ChainDefinitionError("duplicate account profile alias: {}".format(alias))
        seen.add(alias)
        auth_mode = _text(item.get("auth_mode")) or "account"
        if auth_mode not in ACCOUNT_AUTH_MODES:
            raise ChainDefinitionError(
                "account profile {}: unsupported auth_mode '{}'".format(alias, auth_mode)
            )
        profile = {
            "alias": alias,
            "auth_mode": auth_mode,
            "profile_ref": _text(item.get("profile_ref")),
            "account_ref": _text(item.get("account_ref")),
            "provider_ref": _text(item.get("provider_ref")),
            "context_ref": _text(item.get("context_ref")),
            "role": _text(item.get("role")),
        }
        if _text(item.get("description")):
            profile["description"] = _text(item.get("description"))
        profiles.append(profile)
    return profiles


def normalize_chain_definition(raw: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a canonical, validated ``interface-chain.v1`` definition."""
    if not isinstance(raw, Mapping):
        raise ChainDefinitionError("chain definition must be a JSON object")
    schema_version = _text(raw.get("schema_version")) or CHAIN_SCHEMA_VERSION
    if schema_version != CHAIN_SCHEMA_VERSION:
        raise ChainDefinitionError("unsupported chain schema_version: {}".format(schema_version))
    name = _text(raw.get("name"))
    if not _NAME_RE.match(name):
        raise ChainDefinitionError(
            "chain name must match {} (got '{}')".format(_NAME_RE.pattern, name)
        )
    steps = [_normalize_step(item or {}, index) for index, item in enumerate(raw.get("steps") or [])]
    if not steps:
        raise ChainDefinitionError("chain definition requires at least one step")

    definition: Dict[str, Any] = {
        "schema_version": CHAIN_SCHEMA_VERSION,
        "name": name,
        "title": _text(raw.get("title")),
        "project_id": _text(raw.get("project_id")),
        "env_id": _text(raw.get("env_id")),
        "source_ref": _text(raw.get("source_ref")),
        "source_kind": _text(raw.get("source_kind")),
        "source_response_refs": [
            _text(item) for item in (raw.get("source_response_refs") or []) if _text(item)
        ],
        "account_profiles": _normalize_account_profiles(raw.get("account_profiles")),
        "steps": steps,
    }
    if _text(raw.get("description")):
        definition["description"] = _text(raw.get("description"))

    aliases = {item["alias"] for item in definition["account_profiles"]}
    step_ids = [step["step_id"] for step in steps]
    if len(set(step_ids)) != len(step_ids):
        raise ChainDefinitionError("step_id values must be unique")
    response_refs = [step["response_ref"] for step in steps]
    if len(set(response_refs)) != len(response_refs):
        raise ChainDefinitionError("response_ref values must be unique")

    earlier: Dict[str, int] = {}
    earlier_steps: Dict[str, int] = {}
    for index, step in enumerate(steps):
        step_id = step["step_id"]
        if step["account_profile"] and step["account_profile"] not in aliases:
            raise ChainDefinitionError(
                "{}: unknown account profile '{}'".format(step_id, step["account_profile"])
            )
        declared = list(step.get("depends_on") or [])
        derived: List[str] = []
        for parameter in step["parameters"]:
            if parameter["source"] != "upstream_ref":
                continue
            upstream_ref, _segments = parse_upstream_ref(parameter["ref"])
            if upstream_ref not in earlier:
                raise ChainDefinitionError(
                    "{}:{}: upstream ref '{}' must target an earlier step".format(
                        step_id, parameter["name"], parameter["ref"]
                    )
                )
            upstream_step = steps[earlier[upstream_ref]]["step_id"]
            if upstream_step not in derived:
                derived.append(upstream_step)
        for dependency in declared:
            if dependency not in earlier_steps:
                raise ChainDefinitionError(
                    "{}: depends_on '{}' must reference an earlier step".format(step_id, dependency)
                )
        for dependency in derived:
            if declared and dependency not in declared:
                raise ChainDefinitionError(
                    "{}: depends_on omits resolved upstream step '{}'".format(step_id, dependency)
                )
        step["depends_on"] = declared if declared else derived
        placeholders = placeholder_names(step["path_template"])
        path_parameters = {
            item["name"] for item in step["parameters"] if item["position"] == "path"
        }
        missing_declarations = [item for item in placeholders if item not in path_parameters]
        if missing_declarations:
            raise ChainDefinitionError(
                "{}: path placeholders lack a path parameter: {}".format(
                    step_id, ", ".join(missing_declarations)
                )
            )
        for item in placeholders:
            parameter = next(entry for entry in step["parameters"] if entry["name"] == item)
            if not parameter["required"]:
                raise ChainDefinitionError(
                    "{}: path parameter '{}' must be required".format(step_id, item)
                )
        earlier[step["response_ref"]] = index
        earlier_steps[step_id] = index

    assert_no_secrets(definition)
    return definition


def validate_chain_definition(raw: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate and return the canonical definition (alias of normalise)."""
    return normalize_chain_definition(raw)


# ---------------------------------------------------------------------------
# Serialisation / save / load
# ---------------------------------------------------------------------------

def canonical_definition_json(definition: Mapping[str, Any]) -> str:
    return json.dumps(definition, ensure_ascii=False, sort_keys=True, indent=2, separators=(",", ": "))


def chain_definition_sha256(definition: Mapping[str, Any]) -> str:
    payload = json.dumps(definition, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def serialize_chain_definition(definition: Mapping[str, Any]) -> str:
    """Canonical, stable JSON text for a definition (round-trips byte for byte)."""
    return canonical_definition_json(normalize_chain_definition(definition)) + "\n"


def deserialize_chain_definition(text: str) -> Dict[str, Any]:
    try:
        raw = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise ChainDefinitionError("chain definition is not valid JSON: {}".format(exc))
    return normalize_chain_definition(raw)


def load_chain_definition_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return deserialize_chain_definition(handle.read())


def save_chain_definition_file(path: str, definition: Mapping[str, Any]) -> str:
    text = serialize_chain_definition(definition)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return text


def chain_definition_document(definition: Mapping[str, Any], project_id: str = "",
                              env_id: str = "", operator: str = "",
                              status: str = "draft") -> Dict[str, Any]:
    """Build the Mongo document payload without touching the database."""
    canonical = normalize_chain_definition(definition)
    return {
        "name": canonical["name"],
        "schema_version": canonical["schema_version"],
        "project_id": _text(project_id) or canonical["project_id"],
        "env_id": _text(env_id) or canonical["env_id"],
        "title": canonical["title"],
        "description": canonical.get("description", ""),
        "source_ref": canonical["source_ref"],
        "source_kind": canonical["source_kind"],
        "status": status,
        "step_count": len(canonical["steps"]),
        "definition": canonical,
        "definition_sha256": chain_definition_sha256(canonical),
        "created_by": _text(operator),
        "updated_by": _text(operator),
    }


def persist_chain_definition(definition: Mapping[str, Any], project_id: str = "",
                             env_id: str = "", operator: str = "",
                             status: str = "draft") -> Tuple[Any, bool]:
    """Upsert a definition scoped by ``(project_id, env_id, name)``."""
    payload = chain_definition_document(
        definition, project_id=project_id, env_id=env_id, operator=operator, status=status,
    )
    existing = interface_chain_definition.objects(
        project_id=payload["project_id"], env_id=payload["env_id"], name=payload["name"],
    ).first()
    if existing:
        existing.title = payload["title"]
        existing.description = payload["description"]
        existing.source_ref = payload["source_ref"]
        existing.source_kind = payload["source_kind"]
        existing.status = payload["status"]
        existing.step_count = payload["step_count"]
        existing.definition = payload["definition"]
        existing.definition_sha256 = payload["definition_sha256"]
        existing.updated_by = payload["updated_by"]
        existing.save()
        return existing, False
    document = interface_chain_definition(**payload)
    document.save()
    return document, True


def load_chain_definition(name: str, project_id: str = "", env_id: str = "") -> Dict[str, Any]:
    document = interface_chain_definition.objects(
        name=_text(name), project_id=_text(project_id), env_id=_text(env_id),
    ).first()
    if not document:
        raise ChainDefinitionError(
            "chain definition '{}' not found for project '{}'".format(name, project_id)
        )
    return normalize_chain_definition(document.definition)


def list_chain_definitions(project_id: Optional[str] = None,
                           env_id: Optional[str] = None) -> List[Dict[str, Any]]:
    query: Dict[str, Any] = {}
    if project_id is not None:
        query["project_id"] = _text(project_id)
    if env_id is not None:
        query["env_id"] = _text(env_id)
    rows = []
    for document in interface_chain_definition.objects(**query).order_by("name"):
        rows.append({
            "name": document.name,
            "title": document.title,
            "status": document.status,
            "project_id": document.project_id,
            "env_id": document.env_id,
            "step_count": int(document.step_count or 0),
            "definition_sha256": document.definition_sha256,
            "source_ref": document.source_ref,
            "mtime": document.mtime,
        })
    return rows


# ---------------------------------------------------------------------------
# Source binding against the imported endpoint asset
# ---------------------------------------------------------------------------

def _endpoint_entry(endpoint_lookup: Any, pathid: int) -> Optional[Mapping[str, Any]]:
    if endpoint_lookup is None:
        return None
    if callable(endpoint_lookup):
        return endpoint_lookup(pathid)
    return endpoint_lookup.get(pathid) or endpoint_lookup.get(str(pathid))


def bind_chain_sources(definition: Mapping[str, Any], endpoint_lookup: Any) -> Dict[str, Any]:
    """Bind each step to its imported endpoint asset and report mismatches.

    ``endpoint_lookup`` maps a pathid to ``{method, path, domain, url,
    project_id}`` (the shape returned by the web endpoint context). Steps whose
    asset is missing or whose method/canonical path disagrees are reported as
    unbound so the caller can stop before composing requests.
    """
    canonical = normalize_chain_definition(definition)
    steps = []
    for step in canonical["steps"]:
        entry = _endpoint_entry(endpoint_lookup, step["pathid"])
        reasons: List[str] = []
        if not entry:
            reasons.append("endpoint_asset_missing")
        else:
            method = _text(entry.get("method")).upper()
            if method and method != step["method"]:
                reasons.append("method_mismatch")
            declared_path = _text(entry.get("path"))
            if declared_path and canonical_path_template(declared_path) != canonical_path_template(
                    step["path_template"]):
                reasons.append("path_template_mismatch")
            project_id = _text(entry.get("project_id"))
            if project_id and canonical["project_id"] and project_id != canonical["project_id"]:
                reasons.append("project_mismatch")
        steps.append({
            "step_id": step["step_id"],
            "pathid": step["pathid"],
            "response_ref": step["response_ref"],
            "bound": not reasons,
            "reason_codes": reasons,
        })
    return {
        "checked": endpoint_lookup is not None,
        "bound": all(item["bound"] for item in steps),
        "unbound_step_ids": [item["step_id"] for item in steps if not item["bound"]],
        "steps": steps,
    }


def account_profile_statuses(definition: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Report whether each declared account profile still needs platform binding.

    A definition stores references only. ``profile_ref`` / ``provider_ref`` /
    ``context_ref`` are filled from the project's ``ProjectAuthProfile`` when the
    chain is saved for a concrete environment.
    """
    canonical = normalize_chain_definition(definition)
    rows = []
    for profile in canonical["account_profiles"]:
        missing = [
            name for name in ("profile_ref", "provider_ref", "context_ref")
            if profile["auth_mode"] == "account" and not profile.get(name)
        ]
        rows.append({
            "alias": profile["alias"],
            "auth_mode": profile["auth_mode"],
            "role": profile["role"],
            "profile_ref": profile.get("profile_ref", ""),
            "account_ref": profile.get("account_ref", ""),
            "provider_ref": profile.get("provider_ref", ""),
            "context_ref": profile.get("context_ref", ""),
            "bound": not missing,
            "reason_codes": ["UNBOUND_ACCOUNT_PROFILE"] if missing else [],
        })
    return rows


def db_endpoint_lookup(project_id: str) -> Callable[[int], Optional[Dict[str, Any]]]:
    """Return an endpoint lookup backed by imported ``raw_data`` rows."""
    def lookup(pathid: int) -> Optional[Dict[str, Any]]:
        query: Dict[str, Any] = {"ptah_id": int(pathid)}
        if _text(project_id):
            query["project_id"] = _text(project_id)
        row = raw_data.objects(**query).first()
        if not row:
            return None
        return {
            "pathid": row.ptah_id,
            "method": row.method,
            "path": row.path,
            "url": row.url,
            "domain": row.domain,
            "project_id": row.project_id or "",
            "env_id": row.env_id or "",
        }
    return lookup


# ---------------------------------------------------------------------------
# In-memory resolution / dry run
# ---------------------------------------------------------------------------

def _block(step_result: Dict[str, Any], code: str, detail: str) -> None:
    step_result["status"] = "blocked"
    if code not in step_result["reason_codes"]:
        step_result["reason_codes"].append(code)
    if detail:
        step_result["notes"].append(detail)


def resolve_chain(definition: Mapping[str, Any], sources: Optional[Mapping[str, Any]] = None,
                  endpoint_lookup: Any = None,
                  step_failures: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Resolve every step in memory without sending a request.

    ``sources`` maps a step ``response_ref`` to that step's captured response
    JSON. ``step_failures`` lets a live caller inject already-failed steps so
    dependents are blocked with an explicit reason.
    """
    canonical = normalize_chain_definition(definition)
    sources = dict(sources or {})
    binding = bind_chain_sources(canonical, endpoint_lookup) if endpoint_lookup is not None else {
        "checked": False, "bound": None, "unbound_step_ids": [], "steps": [],
    }
    binding_by_step = {item["step_id"]: item for item in binding.get("steps") or []}
    failed = {_text(item) for item in (step_failures or []) if _text(item)}

    results: List[Dict[str, Any]] = []
    status_by_step: Dict[str, str] = {}
    for step in canonical["steps"]:
        step_id = step["step_id"]
        result: Dict[str, Any] = {
            "step_id": step_id,
            "response_ref": step["response_ref"],
            "pathid": step["pathid"],
            "method": step["method"],
            "path_template": step["path_template"],
            "placeholder_style": step["placeholder_style"],
            "account_profile": step["account_profile"],
            "depends_on": list(step.get("depends_on") or []),
            "status": "ready",
            "reason_codes": [],
            "notes": [],
            "resolved_parameters": {},
            "rendered_path": "",
        }
        blocked_dependencies = [item for item in step.get("depends_on") or [] if status_by_step.get(item) != "ready"]
        if failed and step_id in failed:
            result["status"] = "failed"
            result["reason_codes"].append(UPSTREAM_STEP_FAILED)
        elif blocked_dependencies:
            _block(
                result, UPSTREAM_STEP_BLOCKED,
                "blocked by upstream step(s): {}".format(", ".join(blocked_dependencies)),
            )
        bind_item = binding_by_step.get(step_id)
        if result["status"] == "ready" and bind_item and not bind_item["bound"]:
            _block(
                result, SOURCE_NOT_BOUND,
                "source binding failed: {}".format(", ".join(bind_item["reason_codes"])),
            )

        path_values: Dict[str, Any] = {}
        for parameter in step["parameters"]:
            name = parameter["name"]
            entry = {
                "position": parameter["position"],
                "type": parameter["type"],
                "required": parameter["required"],
                "source": parameter["source"],
            }
            if parameter.get("source_response_ref"):
                entry["source_response_ref"] = parameter["source_response_ref"]
            if parameter["source"] == "constant":
                entry["value"] = copy.deepcopy(parameter["value"])
                if result["status"] == "ready" and parameter["required"] and _is_empty_source(
                        parameter["value"]):
                    _block(result, MISSING_REQUIRED_PARAMETER,
                           "required constant '{}' has no value".format(name))
                result["resolved_parameters"][name] = entry
                if parameter["position"] == "path":
                    path_values[name] = parameter["value"]
                continue
            ref = parameter["ref"]
            found, value = resolve_upstream_ref(sources, ref)
            entry["ref"] = ref
            if not found:
                entry["resolved"] = False
                result["resolved_parameters"][name] = entry
                if parameter["required"]:
                    _block(result, MISSING_UPSTREAM_REF,
                           "'{}' cannot resolve '{}'".format(name, ref))
                else:
                    if OPTIONAL_UPSTREAM_REF_EMPTY not in result["reason_codes"]:
                        result["reason_codes"].append(OPTIONAL_UPSTREAM_REF_EMPTY)
                    result["notes"].append("optional '{}' omitted: '{}' not present".format(name, ref))
                continue
            entry["resolved"] = True
            entry["value"] = value
            result["resolved_parameters"][name] = entry
            if parameter["position"] == "path":
                path_values[name] = value
            if parameter.get("required_non_empty") and _is_empty_source(value):
                _block(result, EMPTY_REQUIRED_SOURCE,
                       "'{}' resolved from '{}' but is empty".format(name, ref))

        rendered, missing = render_path_template(step["path_template"], path_values)
        result["rendered_path"] = rendered
        if missing and result["status"] == "ready":
            _block(result, UNRESOLVED_PATH_PARAMETER,
                   "unresolved path parameter(s): {}".format(", ".join(missing)))
        results.append(result)
        status_by_step[step_id] = result["status"]

    ready = [item["step_id"] for item in results if item["status"] == "ready"]
    blocked = [item["step_id"] for item in results if item["status"] == "blocked"]
    failed_ids = [item["step_id"] for item in results if item["status"] == "failed"]
    return {
        "name": canonical["name"],
        "schema_version": canonical["schema_version"],
        "project_id": canonical["project_id"],
        "env_id": canonical["env_id"],
        "title": canonical["title"],
        "definition_sha256": chain_definition_sha256(canonical),
        "binding": binding,
        "account_binding": account_profile_statuses(canonical),
        "steps": results,
        "ready_step_ids": ready,
        "blocked_step_ids": blocked,
        "failed_step_ids": failed_ids,
        "safe_to_execute": bool(ready) and not blocked and not failed_ids,
        "sources_provided": sorted(sources.keys()),
        "network_requests": 0,
        "security_verdict": "not_evaluated",
        "verdict_note": "ordinary HTTP 2xx is not a security verdict",
    }


def dry_run_chain(definition: Mapping[str, Any], sources: Optional[Mapping[str, Any]] = None,
                  endpoint_lookup: Any = None,
                  step_failures: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Offline plan: resolve bindings and report, without any network request."""
    return resolve_chain(
        definition, sources=sources, endpoint_lookup=endpoint_lookup, step_failures=step_failures,
    )


def chain_blocker_summary(plan: Mapping[str, Any]) -> List[str]:
    """Human-readable blocker lines for a resolved plan."""
    lines: List[str] = []
    for step in plan.get("steps") or []:
        if step["status"] == "ready":
            continue
        lines.append("{} [{}] {}".format(
            step["step_id"], ",".join(step["reason_codes"]) or "blocked",
            "; ".join(step["notes"]),
        ))
    return lines


# ---------------------------------------------------------------------------
# Explicit live execution (never invoked by default)
# ---------------------------------------------------------------------------

def _chain_template_key(definition: Mapping[str, Any], step_id: str) -> str:
    return "{}:{}:{}".format(CHAIN_ADAPTER_ID, chain_definition_sha256(definition), step_id)


def _step_url(step: Mapping[str, Any], endpoint: Mapping[str, Any], path_values: Mapping[str, Any]) -> str:
    url = _text(endpoint.get("url"))
    if not url:
        domain = _text(endpoint.get("domain"))
        if not domain:
            raise ChainDefinitionError(
                "{}: endpoint asset has neither url nor domain".format(step["step_id"])
            )
        url = domain + step["path_template"]
    rendered, missing = render_path_template(url, path_values)
    if missing:
        raise ChainDefinitionError(
            "{}: endpoint url lacks placeholder(s): {}".format(step["step_id"], ", ".join(missing))
        )
    return rendered


def _merge_query(rendered_url: str, query: Mapping[str, Any]) -> str:
    split = urlsplit(rendered_url)
    replace_keys = {str(key) for key in (query or {}).keys()}
    pairs = [(key, value) for key, value in parse_qsl(split.query, keep_blank_values=True)
             if key not in replace_keys]
    for key, value in (query or {}).items():
        if isinstance(value, list):
            pairs.extend((key, item) for item in value)
        else:
            pairs.append((key, value))
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(pairs, doseq=True), split.fragment))


def replay_chain_live(definition: Mapping[str, Any], *, context: Any,
                      endpoint_lookup: Any, account_context_resolver: Any = None,
                      sources: Optional[Mapping[str, Any]] = None,
                      allow_live_requests: bool = False,
                      request_options: Optional[Dict[str, Any]] = None,
                      operator: str = "", max_steps: Optional[int] = None) -> Dict[str, Any]:
    """Execute a read chain in order against live targets.

    This is the only network-touching entry point and it refuses to run unless
    ``allow_live_requests=True``. Each step is composed through the standard
    ``create_request_snapshot`` -> ``replay_snapshot_with_json`` path, and each
    result is stored through the standard execution contract with a
    ``not_evaluable`` verdict.
    """
    if not allow_live_requests:
        raise ChainLiveExecutionNotConfirmed(
            "live chain replay requires explicit allow_live_requests=True"
        )
    from apiAnalysis.tool.account_context import AccountContext, AccountContextInvalid
    from apiAnalysis.tool.compose_request import create_request_snapshot
    from apiAnalysis.tool.execution_contract import create_execution_run, record_execution_result
    from apiAnalysis.tool.execution_scheduler import (
        classify_execution_result, sanitize_execution_evidence,
    )
    from apiAnalysis.tool.snapshot_runner import replay_snapshot_with_json

    canonical = normalize_chain_definition(definition)
    binding = bind_chain_sources(canonical, endpoint_lookup)
    if not binding["bound"]:
        raise ChainDefinitionError(
            "chain source binding failed: {}".format(", ".join(binding["unbound_step_ids"]))
        )
    accounts = {item["alias"]: item for item in canonical["account_profiles"]}
    run = create_execution_run(
        name="interface-chain:{}".format(canonical["name"]),
        check_type=CHAIN_CHECK_TYPE,
        context=context,
        scope={
            "chain_name": canonical["name"],
            "chain_sha256": chain_definition_sha256(canonical),
            "step_count": len(canonical["steps"]),
        },
        operator=operator,
    )

    captured: Dict[str, Any] = dict(sources or {})
    executed: List[Dict[str, Any]] = []
    failures: List[str] = []
    limit = len(canonical["steps"]) if max_steps is None else max(0, int(max_steps))
    for step in canonical["steps"][:limit]:
        step_id = step["step_id"]
        plan = resolve_chain(canonical, sources=captured, endpoint_lookup=endpoint_lookup,
                             step_failures=failures)
        step_plan = next(item for item in plan["steps"] if item["step_id"] == step_id)
        if step_plan["status"] != "ready":
            failures.append(step_id)
            executed.append({
                "step_id": step_id,
                "status": "blocked",
                "reason_codes": step_plan["reason_codes"],
                "notes": step_plan["notes"],
            })
            continue

        endpoint = _endpoint_entry(endpoint_lookup, step["pathid"]) or {}
        path_values = {
            name: entry["value"] for name, entry in step_plan["resolved_parameters"].items()
            if entry["position"] == "path"
        }
        query_values = {
            name: entry["value"] for name, entry in step_plan["resolved_parameters"].items()
            if entry["position"] == "query" and "value" in entry
        }
        account = accounts.get(step["account_profile"]) or {}
        account_context = None
        if context.auth_mode == "account":
            if account_context_resolver is None:
                raise ChainDefinitionError("account auth requires an account context resolver")
            account_context = account_context_resolver(step["account_profile"] or context.account_id)
            if not isinstance(account_context, AccountContext):
                raise AccountContextInvalid("resolver did not return an AccountContext")

        snapshot = create_request_snapshot(
            step["pathid"],
            account_id=context.account_id or None,
            env_id=context.env_id or None,
            project_id=context.project_id,
            auth_mode=context.auth_mode,
            source=CHAIN_ADAPTER_ID,
            execution_metadata=dict(
                context.snapshot_metadata(),
                chain_name=canonical["name"],
                chain_sha256=chain_definition_sha256(canonical),
                chain_step_id=step_id,
                chain_response_ref=step["response_ref"],
                account_profile=step["account_profile"],
            ),
        )
        if snapshot is None:
            raise ChainDefinitionError("{}: pathid {} has no imported asset".format(step_id, step["pathid"]))
        snapshot.url = _merge_query(_step_url(step, endpoint, path_values), query_values)
        snapshot.query = query_values
        snapshot.path_params = path_values
        snapshot.adapter_id = CHAIN_ADAPTER_ID
        snapshot.adapter_version = "1"
        snapshot.template_key = _chain_template_key(canonical, step_id)
        snapshot.save()

        evidence, body = replay_snapshot_with_json(
            snapshot,
            auth_mode=context.auth_mode,
            request_options=request_options,
            account_context=account_context,
        )
        sanitized = sanitize_execution_evidence(evidence)
        verdict, reason_codes, confidence = classify_execution_result(
            evidence, CHAIN_CHECK_TYPE, context.auth_mode,
        )
        record_execution_result(
            run, snapshot,
            case_name="{}:{}".format(canonical["name"], step_id),
            check_type=CHAIN_CHECK_TYPE,
            verdict=verdict,
            evidence_summary=sanitized,
            reason_codes=reason_codes,
            confidence=confidence,
            execution_key="{}:{}:{}".format(CHAIN_ADAPTER_ID, run.id, step_id),
            related_pathid=step["pathid"],
        )
        ok = bool(evidence.get("ok")) and body is not None
        if ok:
            captured[step["response_ref"]] = body
        else:
            failures.append(step_id)
        executed.append({
            "step_id": step_id,
            "status": "executed" if ok else "failed",
            "http_status": evidence.get("status_code"),
            "verdict": verdict,
            "reason_codes": reason_codes,
            "response_sha256": evidence.get("response_sha256"),
            "account_profile": step["account_profile"],
            "account_role": account.get("role", ""),
        })

    return {
        "run_id": str(run.id),
        "name": canonical["name"],
        "definition_sha256": chain_definition_sha256(canonical),
        "steps": executed,
        "failed_step_ids": failures,
        "captured_response_refs": sorted(captured.keys()),
        "security_verdict": "not_evaluated",
        "verdict_note": "ordinary HTTP 2xx is not a security verdict",
    }
