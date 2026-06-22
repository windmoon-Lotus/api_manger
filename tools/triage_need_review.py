import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Set


PUBLIC_PATH_HINTS = (
    "/advertisement/", "/passport/check", "/passport/agree", "/passport/get-regist",
    "/passport/verify", "/passport/alter", "/passport/register", "/passport/login",
    "/passport/reset", "/tryout/limit", "/image/",
)


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def text_of(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except TypeError:
        return str(value)


def xml_error(value: Any) -> str:
    text = text_of(value)
    if "<category>error</category>" in text or "<action>error</action>" in text:
        msg = re.search(r"<message>(.*?)</message>", text, re.S)
        code = re.search(r"<code>(.*?)</code>", text, re.S)
        return f"xml_error:{code.group(1) if code else ''}:{msg.group(1) if msg else ''}"
    if "AUTH_FAILED" in text or "MISSING_PARAMETERS" in text or "USER_NOT_EXISTS" in text:
        return "xml_error"
    return ""


def collect_values(value: Any, keys: Set[str]) -> Dict[str, Set[str]]:
    found = {key: set() for key in keys}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                lk = str(key).lower()
                if lk in keys and child not in (None, "", [], {}):
                    found[lk].add(str(child))
                walk(child)
        elif isinstance(node, list):
            for child in node[:20]:
                walk(child)

    walk(value)
    return found


def account_bodies(row: Dict[str, Any]) -> List[Any]:
    if "accounts" in row:
        return [(item.get("result") or {}).get("bodySample") for item in row.get("accounts") or []]
    return [(row.get("owner") or {}).get("bodySample"), (row.get("attacker") or {}).get("bodySample")]


def account_statuses(row: Dict[str, Any]) -> List[int]:
    if "accounts" in row:
        return [(item.get("result") or {}).get("statusCode") for item in row.get("accounts") or []]
    return [(row.get("owner") or {}).get("statusCode"), (row.get("attacker") or {}).get("statusCode")]


def classify(row: Dict[str, Any]) -> Dict[str, Any]:
    path = row.get("path") or ""
    bodies = account_bodies(row)
    statuses = account_statuses(row)
    if any(status and status >= 500 for status in statuses):
        return {"triage": "error_like", "reason": "server_error"}
    errors = [xml_error(body) for body in bodies]
    if errors and all(errors) and len(set(errors)) == 1:
        return {"triage": "error_like", "reason": errors[0]}
    if any(hint in path for hint in PUBLIC_PATH_HINTS):
        values = [collect_values(body, {"userid", "user_id", "owner_id"}) for body in bodies]
        flat = [set().union(*v.values()) for v in values]
        if len(flat) >= 2 and flat[0] and flat[1] and flat[0].isdisjoint(flat[1]):
            return {"triage": "account_isolated", "reason": "response_contains_each_account_own_userid"}
        return {"triage": "likely_public_data", "reason": "public_path_hint"}
    if len(bodies) >= 2 and text_of(bodies[0]) == text_of(bodies[1]):
        if len(text_of(bodies[0])) < 800:
            return {"triage": "likely_public_data", "reason": "short_identical_response"}
        return {"triage": "ownership_unclear", "reason": "identical_non_empty_response"}
    values = [collect_values(body, {"userid", "user_id", "owner_id", "remote_id", "remoteid"}) for body in bodies]
    flat = [set().union(*v.values()) for v in values]
    if len(flat) >= 2 and flat[0] and flat[1] and flat[0].isdisjoint(flat[1]):
        return {"triage": "account_isolated", "reason": "identity_values_differ_by_account"}
    return {"triage": "ownership_unclear", "reason": "manual_review_needed"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Second-pass triage for need_review evidence.")
    parser.add_argument("--input", action="append", required=True)
    parser.add_argument("--out-json", default=str(Path("..") / ".secrets" / "need-review-triage.private.json"))
    parser.add_argument("--out-md", default=str(Path("security_reports") / "need_review_triage.md"))
    args = parser.parse_args()

    rows = []
    for input_path in args.input:
        doc = load_json(Path(input_path))
        for row in doc.get("results") or []:
            if (row.get("judgement") or {}).get("verdict") != "need_review":
                continue
            triage = classify(row)
            rows.append({
                "source": input_path,
                "pathid": row.get("pathid"),
                "method": row.get("method"),
                "path": row.get("path"),
                "name": row.get("name", ""),
                "judgement": row.get("judgement"),
                **triage,
            })
    summary: Dict[str, int] = {}
    for row in rows:
        summary[row["triage"]] = summary.get(row["triage"], 0) + 1
    output = {"summary": summary, "total": len(rows), "items": rows}
    Path(args.out_json).write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = ["# Need Review Triage", "", "## Summary", ""]
    for key, value in sorted(summary.items()):
        lines.append(f"- {key}: {value}")
    for bucket in ("ownership_unclear", "account_isolated", "likely_public_data", "error_like"):
        lines.extend(["", f"## {bucket}", ""])
        for row in [r for r in rows if r["triage"] == bucket][:100]:
            lines.append(f"- `{row['pathid']}` `{row['method']} {row['path']}`: {row['reason']}")
    out_md = Path(args.out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"total": len(rows), "summary": summary, "out_json": args.out_json, "out_md": str(out_md)}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
