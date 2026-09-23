import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.db.collection import parameter_archive, parameter_data, req_data
from apiAnalysis.db.save import get_next_sequence
from apiAnalysis.main import _ensure_mongo_connection


PARAM_ALIASES = {
    "userid": ["userid", "user_id", "uid", "owner_id"],
    "remoteid": ["remoteid", "remote_id", "remoteids"],
    "tagid": ["tagid", "tag_id", "tagids", "parent_tagid"],
    "clientid": ["clientid", "client_id"],
    "packageid": ["packageid", "package_id"],
    "install_package": ["install_package", "install_packages", "package", "packages"],
    "productid": ["productid", "product_id"],
    "policy_id": ["policy_id", "policyid"],
    "system_policy_id": ["system_policy_id", "system_policyid", "system_policy_ids"],
    "policy_name": ["policy_name"],
    "seatid": ["seat_id", "seatid"],
    "macid": ["mac_id", "macid"],
    "entid": ["entid", "ent_id"],
    "ent_userid": ["ent_userid"],
    "security_id": ["security_id"],
    "order_id": ["order_id"],
    "blacklist_user_id": ["blacklist_user_id"],
    "blacklist_client_id": ["blacklist_client_id"],
    "fastcode": ["fastcode", "fastcodes"],
    "transferid": ["transferid", "transfer_id"],
    "desktop_id": ["desktop_id", "desktopid"],
    "id": ["id"],
    "moduleid": ["moduleid", "module_id"],
    "account": ["account"],
    "sn": ["sn"],
    "departmentid": ["departmentid", "department_id", "department_ids"],
    "grant_id": ["grant_id", "grantid"],
    "featureid": ["featureid", "feature_id"],
    "script_id": ["script_id", "scriptid"],
    "task_id": ["task_id", "taskid", "taskId"],
    "zj_id": ["zj_id", "zjid"],
    "configid": ["configid", "config_id", "configId"],
    "roleid": ["roleid", "role_id"],
    # --- domain object ids (additive; some responses lack these keys) ---
    "networkid": ["networkid", "network_id", "networkids"],
    "vpnid": ["vpnid", "vpn_id"],
    "memberid": ["memberid", "member_id"],
    "groupid": ["groupid", "group_id"],
    "labelid": ["labelid", "label_id"],
    "webhookid": ["webhookid", "webhook_id"],
    "messageid": ["messageid", "message_id"],
    "settingid": ["settingid", "setting_id"],
    "serviceid": ["serviceid", "service_id"],
    "bandwidthid": ["bandwidthid", "bandwidth_id"],
    "customizeid": ["customizeid", "customize_id"],
    "tplid": ["tplid", "template_id", "templateid"],
}


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def value_ok(value: Any) -> bool:
    if value in (None, "", [], {}):
        return False
    if isinstance(value, bool):
        return False
    text = str(value).strip()
    if text.lower() in {"0", "false", "true", "null", "none"}:
        return False
    return len(text) >= 2


def norm_key(key: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", str(key or "").lower())


def canonical_for(key: str) -> str:
    normalized = norm_key(key)
    for canonical, aliases in PARAM_ALIASES.items():
        if normalized in {norm_key(a) for a in aliases}:
            return canonical
    return ""


def collect_ids(node: Any, found: Dict[str, List[Any]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            canonical = canonical_for(key)
            if canonical and value_ok(value):
                found.setdefault(canonical, [])
                if value not in found[canonical]:
                    found[canonical].append(value)
            collect_ids(value, found)
    elif isinstance(node, list):
        for item in node[:50]:
            collect_ids(item, found)


def dedupe(values: Iterable[Any], limit: int = 30) -> List[Any]:
    result = []
    seen = set()
    for value in values:
        try:
            key = json.dumps(value, ensure_ascii=False, sort_keys=True)
        except TypeError:
            key = str(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
        if len(result) >= limit:
            break
    return result


def pathids_for(name: str) -> List[int]:
    ids = set()
    for item in req_data.objects(parameter=name):
        if item.raw_data:
            ids.add(item.raw_data.ptah_id)
    return sorted(ids)


def ensure_parameter_data(name: str, pathids: List[int], values: List[Any], value_kind: str = "req") -> List[int]:
    data = parameter_data.objects(parameter=name).first()
    if not data:
        data = parameter_data(parameter=name, parameterid=get_next_sequence("parameter_data"))
    if value_kind == "res":
        data.res_pathid = sorted(set(data.res_pathid or []).union(pathids))
        data.res_value = dedupe(list(data.res_value or []) + values)
        data.req_pathid = data.req_pathid or []
        data.req_value = data.req_value or []
    else:
        data.req_pathid = sorted(set(data.req_pathid or []).union(pathids))
        data.req_value = dedupe(list(data.req_value or []) + values)
        data.res_pathid = data.res_pathid or []
        data.res_value = data.res_value or []
    data.modificator = data.modificator or "seed_parameter_archive_from_round"
    data.save()
    return [data.parameterid]


def save_archive(account_id: str, canonical: str, values: List[Any], value_kind: str = "req",
                 pathids: List[int] = None, project_id: str = "", env_id: str = "") -> int:
    """Write one archive record under the full ``{account, project, env}`` identity.

    The identity must match the one used by ``rule.analysis.parameter_archive``
    and by ``parameter_dependency._archive_value``. Writing only ``account_id``
    produced rows that no project-scoped lookup could ever reach.
    """
    if not project_id:
        raise ValueError("save_archive requires an explicit project_id")
    if not account_id:
        raise ValueError("save_archive requires an explicit account_id")
    identity = {"account_id": account_id, "project_id": str(project_id), "env_id": str(env_id or "")}
    written = 0
    for name in PARAM_ALIASES.get(canonical, [canonical]):
        pids = sorted(set((pathids or []) + pathids_for(name)))
        paramids = ensure_parameter_data(name, pids, values, value_kind=value_kind)
        record = parameter_archive.objects(parameter=name, **identity).first()
        if not record:
            record = parameter_archive(parameter=name, **identity)
        record.parameterid = paramids
        if value_kind == "res":
            record.res_pathid = sorted(set(record.res_pathid or []).union(pids))
            record.res_value = dedupe(list(record.res_value or []) + values)
            record.req_pathid = record.req_pathid or []
            record.req_value = record.req_value or []
        else:
            record.req_pathid = sorted(set(record.req_pathid or []).union(pids))
            record.req_value = dedupe(list(record.req_value or []) + values)
            record.res_pathid = record.res_pathid or []
            record.res_value = record.res_value or []
        record.properties = dedupe(list(record.properties or []) + [canonical, "round_extract", f"kind:{value_kind}"], limit=30)
        record.modificator = "seed_parameter_archive_from_round"
        record.save()
        written += 1
    return written


def merge_found(target: Dict[str, Dict[str, List[Any]]], account_id: str, found: Dict[str, List[Any]], value_kind: str) -> None:
    bucket = target.setdefault(account_id, {}).setdefault(value_kind, {})
    for canonical, values in found.items():
        bucket.setdefault(canonical, [])
        for value in values:
            if value not in bucket[canonical]:
                bucket[canonical].append(value)


def pair_pathids(row: Dict[str, Any]) -> List[int]:
    ids = []
    pair = row.get("pair") or {}
    for key in ["primary", "cleanup", "verify"]:
        pathid = (pair.get(key) or {}).get("pathid")
        if isinstance(pathid, int):
            ids.append(pathid)
    target = row.get("target") or {}
    if isinstance(target.get("pathid"), int):
        ids.append(target["pathid"])
    return sorted(set(ids))


ACCOUNT_KEY_BY_INDEX: Dict[str, str] = {}


def account_key_for_index(index: Any) -> str:
    """Map an evidence ``accountIndex`` onto a real project account key.

    Round evidence carries only a positional index. The archive identity, and the
    runtime resolver, key on the project's ``account_key`` (``owner``, ``peer``,
    ...). There is deliberately no fallback: an unmapped index would produce a
    record no account-scoped lookup could ever reach, so we refuse instead.
    """
    key = ACCOUNT_KEY_BY_INDEX.get(str(index))
    if not key:
        raise ValueError(
            "no account key for accountIndex {0!r}; pass --account-key {0}=<owner|peer|...>".format(index)
        )
    return key


def extract_generic_row(row: Dict[str, Any], by_account: Dict[str, Dict[str, Dict[str, List[Any]]]]) -> None:
    direction = row.get("direction") or {}
    owner_index = direction.get("ownerAccountIndex")
    attacker_index = direction.get("attackerAccountIndex")
    if owner_index is None:
        owner_index = 0
    if attacker_index is None:
        attacker_index = 1
    owner_account = account_key_for_index(owner_index)
    attacker_account = account_key_for_index(attacker_index)
    body_found: Dict[str, List[Any]] = {}
    collect_ids(row.get("body"), body_found)
    if body_found:
        merge_found(by_account, owner_account, body_found, "req")
    for key in [
        "ownerCreate", "ownerVerifyBeforeDelete", "ownerVerifyAfterDelete",
        "ownerCleanup", "ownerGetBefore", "ownerGetAfter", "verifyResult",
    ]:
        result = row.get(key)
        if not isinstance(result, dict):
            continue
        found: Dict[str, List[Any]] = {}
        collect_ids(result.get("bodySample"), found)
        if found:
            merge_found(by_account, owner_account, found, "res")
    for key in ["attackerDelete", "attackerWrite", "attackerDeleteApiStdWithEntid", "attackerDeleteWebapiNoEntid"]:
        result = row.get(key)
        if not isinstance(result, dict):
            continue
        found: Dict[str, List[Any]] = {}
        collect_ids(result.get("bodySample"), found)
        if found:
            merge_found(by_account, attacker_account, found, "res")


def seed_from_round(paths: List[Path], *, project_id: str, env_id: str = "") -> Dict[str, Any]:
    by_account: Dict[str, Dict[str, Dict[str, List[Any]]]] = {}
    pathids_by_account_kind_param: Dict[str, Dict[str, Dict[str, List[int]]]] = {}
    for path in paths:
        doc = load_json(path)
        for row in doc.get("results") or []:
            row_pathids = pair_pathids(row)
            for account_row in row.get("accounts") or []:
                index = account_row.get("accountIndex")
                if index is None:
                    continue
                result = account_row.get("result") or {}
                if result.get("statusCode") != 200:
                    continue
                account_id = account_key_for_index(index)
                found: Dict[str, List[Any]] = {}
                collect_ids(result.get("bodySample"), found)
                merge_found(by_account, account_id, found, "res")
                for canonical in found:
                    pathids_by_account_kind_param.setdefault(account_id, {}).setdefault("res", {}).setdefault(canonical, [])
                    pathids_by_account_kind_param[account_id]["res"][canonical] = dedupe(
                        pathids_by_account_kind_param[account_id]["res"][canonical] + row_pathids,
                        limit=100,
                    )
            extract_generic_row(row, by_account)
            for account_id, by_kind in by_account.items():
                for value_kind, values_by_name in by_kind.items():
                    for canonical in values_by_name:
                        pathids_by_account_kind_param.setdefault(account_id, {}).setdefault(value_kind, {}).setdefault(canonical, [])
                        pathids_by_account_kind_param[account_id][value_kind][canonical] = dedupe(
                            pathids_by_account_kind_param[account_id][value_kind][canonical] + row_pathids,
                            limit=100,
                        )
        # Some focused evidence files store a single case at top level.
        if not doc.get("results"):
            extract_generic_row(doc, by_account)
    written = 0
    account_summary = {}
    for account_id, by_kind in by_account.items():
        account_summary[account_id] = {}
        for value_kind, values_by_name in by_kind.items():
            account_summary[account_id][value_kind] = {key: len(dedupe(values)) for key, values in values_by_name.items()}
            for canonical, values in values_by_name.items():
                pids = pathids_by_account_kind_param.get(account_id, {}).get(value_kind, {}).get(canonical, [])
                written += save_archive(account_id, canonical, dedupe(values), value_kind=value_kind,
                                        pathids=pids, project_id=project_id, env_id=env_id)
    return {"accounts": account_summary, "archive_records_written": written}


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract account-bound ids from readonly round evidence into parameter_archive.")
    parser.add_argument("--round", action="append", required=True)
    parser.add_argument("--project-id", required=True,
                        help="Target project_id; archive identity must match the runtime resolver.")
    parser.add_argument("--env-id", default="", help="Target env_id (empty means the project default).")
    parser.add_argument("--account-key", action="append", default=[],
                        metavar="INDEX=KEY",
                        help="Map an evidence accountIndex to a project account key, e.g. 0=owner. Repeatable.")
    args = parser.parse_args()

    for item in args.account_key:
        if "=" not in item:
            parser.error("--account-key expects INDEX=KEY, got {0!r}".format(item))
        index, key = item.split("=", 1)
        ACCOUNT_KEY_BY_INDEX[index.strip()] = key.strip()

    _ensure_mongo_connection()
    summary = seed_from_round([Path(item) for item in args.round],
                              project_id=args.project_id, env_id=args.env_id)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
