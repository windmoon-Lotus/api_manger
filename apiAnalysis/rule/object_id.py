"""
Object-identifier detection and cross-account substitution for horizontal IDOR.

A real horizontal authorization (IDOR) test is not "two accounts both call the
same endpoint and get similar data". It is "the attacker account requests the
*victim's* object id and still gets the victim's data". This module provides the
pure, database-independent core for that:

- `is_object_id_param(name)`     decide if a parameter name refers to an object
                                 instance identifier (user_id, deviceId, ...),
                                 while ignoring pagination / noise keys.
- `collect_object_ids(payload)`  list the object-id parameters and values found
                                 in a composed request payload.
- `build_idor_payload(attacker, victim)`
                                 deep-copy the attacker payload and swap its
                                 object-id values for the victim's real values,
                                 returning the new payload plus the list of
                                 swaps performed (for evidence / reason codes).

The functions never mutate their inputs.
"""
import copy
import re
from typing import Any, Dict, List, Tuple


# Standalone tokens that are object identifiers on their own (e.g. ?id=123).
# `sid` is intentionally excluded: it is overwhelmingly a session id (auth
# context), not a swappable object id.
ID_TOKENS = {
    "id", "ids", "uid", "uids", "uuid", "guid",
    "gid", "oid", "pid", "fid", "tid", "mid", "rid", "cid", "aid", "eid",
}

# Business-object identifiers that stand alone without an "id" suffix.
STANDALONE_OBJECT_IDS = {"account", "acct"}

# Session / auth identifiers: they end in "id" but are credential context, not
# swappable object ids, so they are excluded from IDOR substitution.
SESSION_ID_TOKENS = {"sid", "sessionid", "jsessionid", "phpsessid", "ssid"}

# Words that merely end in "id" but are not identifiers; the suffix rule below
# treats any "<x>id" / "<x>ids" token as an id unless its leaf is listed here.
TRAP_ID_WORDS = {
    "valid", "invalid", "android", "paid", "unpaid", "prepaid", "void",
    "avoid", "rapid", "solid", "grid", "hybrid", "fluid", "liquid", "acid",
    "raid", "squid", "candid", "splendid", "vivid", "lucid", "humid", "timid",
    "morbid", "placid", "rigid", "forbid", "overid", "afraid", "mermaid",
}

# Words that name a business object; used to confirm single-token ids such as
# "userid" and to disambiguate generic suffixes.
OBJECT_WORDS = {
    "user", "account", "acct", "member", "customer", "client", "uid",
    "org", "organization", "tenant", "company", "team", "group", "dept",
    "department", "employee", "staff",
    "device", "machine", "host", "node", "terminal", "gateway",
    "order", "trade", "pay", "payment", "bill", "invoice", "ticket", "task",
    "job", "contract", "plan", "subscription",
    "file", "doc", "document", "image", "img", "photo", "attachment", "video",
    "record", "item", "product", "goods", "sku", "project", "app",
    "application", "session", "msg", "message", "comment", "post", "article",
    "address", "role", "menu", "resource", "asset", "domain", "mail", "email",
    "phone",
}

# Keys that look id-ish but are pagination / transport noise and must never be
# treated as object identifiers.
NOISE_TOKENS = {
    "page", "pagesize", "size", "offset", "limit", "count", "total", "num",
    "timestamp", "time", "ts", "date", "nonce", "sign", "signature", "token",
    "callback", "version", "ver", "lang", "locale", "sort", "order", "format",
    "type", "kind", "status", "state", "flag", "level", "code", "no",
}


def _tokens(name: str) -> List[str]:
    """Split a parameter name into lowercase tokens on separators and camelCase."""
    if not name:
        return []
    # take the leaf of a dotted path like "data.user_id"
    leaf = str(name).split(".")[-1]
    spaced = re.sub(r"[^0-9A-Za-z]+", " ", leaf)
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", spaced)
    return [tok.lower() for tok in spaced.split() if tok]


def is_object_id_param(name: str) -> bool:
    """Return True if `name` names an object-instance identifier."""
    toks = _tokens(name)
    if not toks:
        return False
    # a single pure-noise token (page, timestamp, sign...) is never an id
    if len(toks) == 1 and toks[0] in NOISE_TOKENS:
        return False
    last = toks[-1]

    # english words that merely end in "id" but are not identifiers
    if last in TRAP_ID_WORDS:
        return False

    # session / auth ids are credential context, never swappable object ids
    if last in SESSION_ID_TOKENS:
        return False

    # exact id token as the final token: ?id=, user.id, deviceId -> ["device","id"]
    if last in ID_TOKENS:
        return True

    # standalone business-object identifier, e.g. "account" (== login id)
    if last in STANDALONE_OBJECT_IDS:
        return True

    # any token ending in an id suffix: userid, tagid, remoteids, x_uuid.
    # The denylist above already removed the english-word traps.
    if last.endswith(("uuid", "guid", "ids", "id")) and len(last) > 2:
        return True

    # multi-token name carrying both an object word and an id token,
    # e.g. ["target", "user", "id"] or ["owner", "uid"]
    has_object = any(tok in OBJECT_WORDS for tok in toks)
    has_id = any(
        tok in ID_TOKENS or tok.endswith("id") or tok.endswith("ids")
        for tok in toks
    )
    if has_object and has_id:
        return True

    return False


def _leaf_name(dotted: str) -> str:
    return str(dotted).split(".")[-1]


def _index_leaf_values(obj: Any, index: Dict[str, Any]) -> None:
    """Map leaf-key name -> value for the first occurrence in a nested body."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, (dict, list)):
                _index_leaf_values(value, index)
            else:
                index.setdefault(key, value)
    elif isinstance(obj, list):
        for item in obj:
            _index_leaf_values(item, index)


def _collect_from_flat(mapping: Dict[str, Any], location: str) -> List[Dict[str, Any]]:
    found = []
    for key, value in (mapping or {}).items():
        if is_object_id_param(key):
            found.append({"location": location, "param": key, "value": value})
    return found


def _collect_from_body(obj: Any, found: List[Dict[str, Any]], prefix: str = "") -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = "{}.{}".format(prefix, key) if prefix else key
            if isinstance(value, (dict, list)):
                _collect_from_body(value, found, path)
            elif is_object_id_param(key):
                found.append({"location": "body", "param": path, "value": value})
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _collect_from_body(item, found, "{}[{}]".format(prefix, i))


def collect_object_ids(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """List object-id parameters (with values) present in a composed payload."""
    found: List[Dict[str, Any]] = []
    found.extend(_collect_from_flat(payload.get("query"), "query"))
    found.extend(_collect_from_flat(payload.get("path_params"), "path"))
    _collect_from_body(payload.get("body"), found)
    return found


def _is_usable(value: Any) -> bool:
    return value is not None and str(value).strip() != ""


def _swap_flat(target: Dict[str, Any], victim: Dict[str, Any], location: str,
               swaps: List[Dict[str, Any]]) -> None:
    for key in list((target or {}).keys()):
        if not is_object_id_param(key):
            continue
        victim_value = (victim or {}).get(key)
        attacker_value = target.get(key)
        if _is_usable(victim_value) and str(victim_value) != str(attacker_value):
            swaps.append({
                "location": location,
                "param": key,
                "attacker": attacker_value,
                "victim": victim_value,
            })
            target[key] = victim_value


def _swap_body(obj: Any, victim_index: Dict[str, Any], swaps: List[Dict[str, Any]],
               prefix: str = "") -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = "{}.{}".format(prefix, key) if prefix else key
            if isinstance(value, (dict, list)):
                _swap_body(value, victim_index, swaps, path)
            elif is_object_id_param(key):
                victim_value = victim_index.get(key)
                if _is_usable(victim_value) and str(victim_value) != str(value):
                    swaps.append({
                        "location": "body",
                        "param": path,
                        "attacker": value,
                        "victim": victim_value,
                    })
                    obj[key] = victim_value
    elif isinstance(obj, list):
        for item in obj:
            _swap_body(item, victim_index, swaps, prefix)


def build_idor_payload(attacker_payload: Dict[str, Any],
                       victim_payload: Dict[str, Any]
                       ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Produce an IDOR attempt: the attacker's request with its object-id values
    replaced by the victim's real values. Returns (new_payload, swaps).

    An empty `swaps` list means there was no cross-account object identifier to
    substitute, so the result is NOT a meaningful horizontal IDOR test and the
    caller should fall back to plain comparison.
    """
    new_payload = copy.deepcopy(attacker_payload or {})
    swaps: List[Dict[str, Any]] = []
    if not victim_payload:
        return new_payload, swaps

    _swap_flat(new_payload.get("query"), victim_payload.get("query"), "query", swaps)
    _swap_flat(new_payload.get("path_params"), victim_payload.get("path_params"), "path", swaps)

    victim_index: Dict[str, Any] = {}
    _index_leaf_values(victim_payload.get("body"), victim_index)
    _swap_body(new_payload.get("body"), victim_index, swaps)

    # keep the rendered url consistent with the swapped query/path if present
    try:
        from apiAnalysis.tool.compose_request import render_request_url
        new_payload["rendered_url"] = render_request_url(new_payload)
    except Exception:
        pass

    return new_payload, swaps
