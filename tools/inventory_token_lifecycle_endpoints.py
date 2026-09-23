"""Inventory Apifox operations related to token lifecycle and auth bridging."""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Set, Tuple


PROJECT_RE = re.compile(r"apifox-export-(\d+)-.+\.openapi\.json$")
ENDPOINT_RE = re.compile(r"/apis/api-(\d+)-run(?:$|[/?#])")
RULES = {
    "refresh_or_rotate": (
        r"refresh[_ /-]?(token|jwt)|(?:token|jwt)[_ /-]?refresh|"
        r"(?:token|jwt).{0,12}(?:rotate|renew)|(?:rotate|renew).{0,12}(?:token|jwt)|"
        r"刷新.{0,8}(token|令牌|凭证)|(?:token|令牌|凭证).{0,8}(?:刷新|轮换|续费|更新)",
    ),
    "exchange_or_switch": (
        r"token[_ /-]?(exchange|switch|convert)|exchange[_ /-]?token|grant[_ -]?type|"
        r"authorization[_ -]?code|code[_ -]?exchange|切换.{0,8}(token|令牌|凭证)|"
        r"兑换.{0,8}(token|令牌|凭证)|换取.{0,8}(token|令牌|凭证)|票据换取",
    ),
    "issue_or_login": (
        r"(^|[/ _-])(login|signin|authorization)([/ _-]|$)|access[_ -]?token|id[_ -]?token|"
        r"client[_ -]?token|product[_ -]?token|登录|签发.{0,8}(token|令牌|凭证)|获取.{0,8}(token|令牌)",
    ),
    "revoke_or_logout": (
        r"(^|[/ _-])(logout|signout|revoke|invalidate)([/ _-]|$)|注销|退出登录|"
        r"(token|令牌|凭证).{0,8}(失效|吊销|删除)",
    ),
    "verify_or_introspect": (
        r"introspect|verify[_ /-]?(token|jwt)|check[_ /-]?(token|jwt)|"
        r"(token|jwt|令牌|凭证).{0,8}(校验|验证|检查)|鉴权|验签",
    ),
    "session_cookie_bridge": (
        r"session|cookie|sso|single[_ -]?sign|单点登录|会话|bearer",
    ),
    "generic_token_surface": (
        r"(^|[^a-z0-9])(token|jwt|oauth|oidc)([^a-z0-9]|$)|令牌|凭证|票据",
    ),
}


def schema_terms(value: Any, prefix: str = "", depth: int = 0) -> Iterable[str]:
    if depth > 5 or not isinstance(value, Mapping):
        return
    properties = value.get("properties")
    if isinstance(properties, Mapping):
        for key, child in properties.items():
            name = "{}.{}".format(prefix, key).strip(".")
            yield name
            if isinstance(child, Mapping):
                description = str(child.get("description") or "")
                if description:
                    yield description
                yield from schema_terms(child, name, depth + 1)
    items = value.get("items")
    if isinstance(items, Mapping):
        yield from schema_terms(items, prefix + "[]", depth + 1)


def operation_text(route: str, path_item: Mapping[str, Any], operation: Mapping[str, Any]) -> Tuple[str, List[str]]:
    fields = [
        route,
        str(operation.get("summary") or ""),
        str(operation.get("description") or ""),
        str(operation.get("x-apifox-folder") or ""),
        " ".join(str(x) for x in operation.get("tags") or []),
    ]
    parameter_names = []
    for item in list(path_item.get("parameters") or []) + list(operation.get("parameters") or []):
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "")
        location = str(item.get("in") or "")
        parameter_names.append("{}:{}".format(location, name))
        fields.extend((name, str(item.get("description") or "")))
    request_body = operation.get("requestBody")
    if isinstance(request_body, Mapping):
        for media in (request_body.get("content") or {}).values():
            if isinstance(media, Mapping):
                fields.extend(schema_terms(media.get("schema") or {}))
    return "\n".join(fields).lower(), parameter_names


def load_placement(path: Path) -> Dict[Tuple[str, str, str], Mapping[str, Any]]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        result[(str(item["project_id"]), str(item["method"]).lower(), str(item["path"]))] = item
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--openapi-dir", type=Path, required=True)
    parser.add_argument("--placement-jsonl", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    placement = load_placement(args.placement_jsonl)
    selected_projects = {key[0] for key in placement}
    records: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    declared_schemes: Dict[Tuple[str, str], Dict[str, Any]] = {}
    scheme_usage: Counter = Counter()
    for source in args.openapi_dir.glob("*.openapi.json"):
        match = PROJECT_RE.match(source.name)
        if not match:
            continue
        project_id = match.group(1)
        if project_id not in selected_projects:
            continue
        doc = json.loads(source.read_text(encoding="utf-8-sig"))
        for scheme_name, definition in ((doc.get("components") or {}).get("securitySchemes") or {}).items():
            if not isinstance(definition, Mapping):
                continue
            flows = definition.get("flows") if isinstance(definition.get("flows"), Mapping) else {}
            declared_schemes[(project_id, str(scheme_name))] = {
                "project_id": project_id,
                "name": str(scheme_name),
                "type": str(definition.get("type") or ""),
                "location": str(definition.get("in") or ""),
                "transport_name": str(definition.get("name") or ""),
                "http_scheme": str(definition.get("scheme") or ""),
                "bearer_format": str(definition.get("bearerFormat") or ""),
                "oauth_flows": sorted(str(name) for name in flows.keys()),
                "source_file": source.name,
            }
        for route, path_item in (doc.get("paths") or {}).items():
            if not isinstance(path_item, Mapping):
                continue
            for method, operation in path_item.items():
                if str(method).lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                    continue
                if not isinstance(operation, Mapping):
                    continue
                operation_security = operation.get("security")
                if operation_security is None:
                    operation_security = doc.get("security") or []
                security_schemes = sorted({
                    str(name)
                    for requirement in operation_security or []
                    if isinstance(requirement, Mapping)
                    for name in requirement.keys()
                })
                for scheme_name in security_schemes:
                    scheme_usage[(project_id, scheme_name)] += 1
                text, parameter_names = operation_text(str(route), path_item, operation)
                categories = sorted(name for name, patterns in RULES.items() if any(re.search(pattern, text, re.I) for pattern in patterns))
                strong = [name for name in categories if name != "generic_token_surface"]
                if not categories or (categories == ["session_cookie_bridge"] and not re.search(r"auth|login|token|jwt|oauth|sso|cookie|session|认证|鉴权|登录|令牌|凭证", text, re.I)):
                    continue
                folder = str(operation.get("x-apifox-folder") or "(root)")
                run_url = str(operation.get("x-run-in-apifox") or "")
                endpoint_match = ENDPOINT_RE.search(run_url)
                mapped = placement.get((project_id, str(method).lower(), str(route)), {})
                if not mapped:
                    # Keep this inventory aligned with the eight projects in
                    # the current Host-placement registry.
                    continue
                token_locations = sorted({
                    item for item in parameter_names
                    if re.search(r"token|jwt|authorization|cookie|session|ticket|令牌|凭证|票据", item, re.I)
                })
                records[(project_id, str(method).upper(), str(route), folder)] = {
                    "project_id": project_id,
                    "endpoint_id": int(endpoint_match.group(1)) if endpoint_match else None,
                    "method": str(method).upper(),
                    "path": str(route),
                    "summary": str(operation.get("summary") or ""),
                    "folder": folder,
                    "categories": categories,
                    "priority": "high" if strong and ("exchange_or_switch" in strong or "refresh_or_rotate" in strong or token_locations) else "review",
                    "credential_parameter_locations": token_locations,
                    "declared_security_schemes": security_schemes,
                    "placement_status": mapped.get("placement_status") or "not_in_placement",
                    "host_candidates": sorted({x.get("host") for x in mapped.get("host_candidates") or [] if x.get("host")}),
                    "source_file": source.name,
                }
    ordered = sorted(records.values(), key=lambda x: (
        0 if x["priority"] == "high" else 1, x["project_id"], x["method"], x["path"], x["folder"],
    ))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    jsonl = args.output_dir / "token-lifecycle-endpoints.jsonl"
    with jsonl.open("w", encoding="utf-8") as handle:
        for item in ordered:
            handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
    high_priority = [item for item in ordered if item["priority"] == "high"]
    with (args.output_dir / "token-change-high-priority.jsonl").open("w", encoding="utf-8") as handle:
        for item in high_priority:
            handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
    core_categories = {"exchange_or_switch", "refresh_or_rotate", "revoke_or_logout"}
    core_priority = [item for item in ordered if core_categories.intersection(item["categories"])]
    with (args.output_dir / "token-lifecycle-core.jsonl").open("w", encoding="utf-8") as handle:
        for item in core_priority:
            handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
    scheme_output = []
    for key, item in sorted(declared_schemes.items()):
        record = dict(item)
        record["operation_usage_count"] = int(scheme_usage.get(key, 0))
        scheme_output.append(record)
    (args.output_dir / "declared-token-schemes.json").write_text(
        json.dumps({
            "schema_version": "declared-token-schemes.v1",
            "schemes": scheme_output,
            "boundary": "Definitions and usage counts come from OpenAPI declarations; runtime token acceptance is separate.",
        }, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    categories = Counter(category for item in ordered for category in item["categories"])
    projects = Counter(item["project_id"] for item in ordered)
    methods = Counter(item["method"] for item in ordered)
    high = len(high_priority)
    lines = [
        "# Token 生命周期与兼容接口资产", "",
        "> 静态来源为 Apifox/OpenAPI；候选不等于漏洞。Token、Cookie、账号和真实资源 ID 均未写入。", "",
        "## 总览", "",
        "- 候选接口：{}".format(len(ordered)),
        "- 高优先复核：{}".format(high),
        "- 方法分布：{}".format(", ".join("{}={}".format(k, v) for k, v in sorted(methods.items()))),
        "- 项目分布：{}".format(", ".join("{}={}".format(k, v) for k, v in sorted(projects.items()))),
        "- 类型分布：{}".format(", ".join("{}={}".format(k, v) for k, v in sorted(categories.items()))),
        "", "## 判定边界", "",
        "- `exchange_or_switch`、`refresh_or_rotate` 和凭证出现在 query/path/header 的接口优先。",
        "- 公开接口忽略无效 Authorization 头不等于越权；必须有受保护资源和合法身份基线。",
        "- 跨 Token 类型兼容需要比较 issuer/audience/token kind/tenant/user/resource owner，不能只比较 HTTP 200。",
        "- 逐条明细见 `token-lifecycle-endpoints.jsonl`。",
        "- 高优先切换/变更候选见 `token-change-high-priority.jsonl`。",
        "- 刷新/兑换/切换/注销核心集合见 `token-lifecycle-core.jsonl`。",
        "- OpenAPI 声明的 Token 方案及使用量见 `declared-token-schemes.json`。",
    ]
    (args.output_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({
        "candidates": len(ordered), "high_priority": high, "core_priority": len(core_priority),
        "projects": dict(projects), "categories": dict(categories),
        "output_dir": str(args.output_dir),
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
