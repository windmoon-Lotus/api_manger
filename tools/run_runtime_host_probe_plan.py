"""Execute bounded anonymous GET route confirmation for a Host probe plan."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence, Tuple

import requests


TRACE_HEADERS = ("x-trace-id", "traceid", "trace-id", "x-request-id", "request-id")


def json_shape(value: Any, depth: int = 0) -> Any:
    if depth >= 3:
        return type(value).__name__
    if isinstance(value, Mapping):
        return {str(key): json_shape(item, depth + 1) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return ["list", json_shape(value[0], depth + 1)] if value else ["list"]
    if value is None:
        return "null"
    return type(value).__name__


def safe_scalar(value: Any) -> Any:
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    text = str(value or "")[:120]
    return "[redacted-long-value]" if len(text) >= 24 else text


def fingerprint(response: requests.Response) -> Dict[str, Any]:
    raw = response.content or b""
    result: Dict[str, Any] = {
        "status": int(response.status_code),
        "content_type": str(response.headers.get("Content-Type") or "").split(";", 1)[0].lower(),
        "body_length": len(raw),
        "body_sha256_16": hashlib.sha256(raw).hexdigest()[:16],
    }
    try:
        body = response.json()
    except Exception:
        body = None
    if isinstance(body, Mapping):
        result["json_keys"] = sorted(str(key) for key in body.keys())[:80]
        result["json_shape"] = json_shape(body)
        result["result_fields"] = {
            key: safe_scalar(body.get(key)) for key in ("code", "errno", "errcode", "error", "status", "success")
            if key in body
        }
        result["message_fields"] = {
            key: safe_scalar(body.get(key)) for key in ("message", "msg", "errmsg", "error_description")
            if key in body
        }
    for key in TRACE_HEADERS:
        if response.headers.get(key):
            result.setdefault("trace_ids", {})[key] = str(response.headers[key])[:160]
    return result


def structural(item: Mapping[str, Any]) -> Tuple[Any, ...]:
    return (
        item.get("status"), item.get("content_type"),
        json.dumps(item.get("json_shape"), ensure_ascii=False, sort_keys=True),
        json.dumps(item.get("result_fields"), ensure_ascii=False, sort_keys=True),
        json.dumps(item.get("message_fields"), ensure_ascii=False, sort_keys=True),
    )


def request_get(session: requests.Session, url: str, timeout: float) -> Dict[str, Any]:
    started = time.monotonic()
    try:
        response = session.get(url, timeout=timeout, allow_redirects=False)
        result = fingerprint(response)
    except requests.RequestException as exc:
        result = {"transport_error": exc.__class__.__name__}
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def atomic_write(path: Path, document: Mapping[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(str(temporary), str(path))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--interval", type=float, default=0.3)
    parser.add_argument("--checkpoint-every", type=int, default=10)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    modules = list(plan.get("modules") or [])
    if args.offset > 0:
        modules = modules[args.offset:]
    if args.limit > 0:
        modules = modules[:args.limit]
    timeout = max(2.0, min(args.timeout, 30.0))
    interval = max(0.25, args.interval)
    session = requests.Session()
    session.headers.update({"Accept": "application/json", "User-Agent": "api-manager-host-route-probe/2.0"})
    controls: Dict[str, Sequence[Dict[str, Any]]] = {}
    results = []
    document: Dict[str, Any] = {
        "schema_version": "runtime-host-probe-results.v1",
        "request_policy": {
            "method": "GET", "authentication": "none", "tls_verify": True,
            "redirects": False, "timeout_seconds": timeout,
            "minimum_interval_seconds": interval, "random_controls_per_host": 2,
        },
        "source_plan": str(args.plan), "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for index, module in enumerate(modules, start=1):
        representative = module["representative"]
        route = str(representative["path"])
        probe_route = str(representative.get("probe_path") or route)
        observations = []
        winner = ""
        for candidate in module.get("candidate_hosts") or []:
            host = str(candidate["host"])
            if host not in controls:
                host_controls = []
                for _ in range(2):
                    host_controls.append(request_get(
                        session,
                        "https://{}/__host_asset_control_{}".format(host, secrets.token_hex(10)),
                        timeout,
                    ))
                    time.sleep(interval)
                controls[host] = host_controls
            actual = request_get(session, "https://{}{}".format(host, probe_route), timeout)
            time.sleep(interval)
            status = int(actual.get("status") or 0)
            controls_ready = all(not item.get("transport_error") for item in controls[host])
            structural_distinct = (
                controls_ready and not actual.get("transport_error")
                and all(structural(actual) != structural(item) for item in controls[host])
            )
            stable_control_body = (
                controls_ready
                and controls[host][0].get("body_sha256_16") == controls[host][1].get("body_sha256_16")
                and controls[host][0].get("body_length") == controls[host][1].get("body_length")
            )
            stable_body_distinct = (
                stable_control_body and not actual.get("transport_error")
                and int(actual.get("body_length") or 0) > 0
                and actual.get("body_sha256_16") != controls[host][0].get("body_sha256_16")
            )
            distinct = bool(structural_distinct or stable_body_distinct)
            acceptable_status = bool(status and status < 500 and status not in {404, 429})
            confirmed = bool(distinct and acceptable_status)
            observations.append({
                "host": host, "candidate_score": candidate.get("score"),
                "candidate_reasons": candidate.get("reasons") or [],
                "random_controls": controls[host], "actual": actual,
                "structural_distinct": structural_distinct,
                "stable_body_distinct": stable_body_distinct,
                "structurally_distinct_from_both_controls": distinct,
                "route_confirmed": confirmed,
            })
            if confirmed:
                winner = host
                break
        results.append({
            "project_id": module["project_id"], "folder": module["folder"],
            "unknown_operations_covered": module["unknown_operations_covered"],
            "method": "GET", "path": route,
            "probe_path": probe_route,
            "endpoint_id": representative.get("id"),
            "confirmed_host": winner,
            "route_confirmed": bool(winner),
            "observations": observations,
        })
        if index % max(1, args.checkpoint_every) == 0:
            document["completed_modules"] = index
            document["confirmed_modules"] = sum(item["route_confirmed"] for item in results)
            atomic_write(args.output, document)
    document["completed_modules"] = len(results)
    document["confirmed_modules"] = sum(item["route_confirmed"] for item in results)
    document["confirmed_unknown_operations"] = sum(
        int(item["unknown_operations_covered"]) for item in results if item["route_confirmed"]
    )
    atomic_write(args.output, document)
    print(json.dumps({
        "completed_modules": document["completed_modules"],
        "confirmed_modules": document["confirmed_modules"],
        "confirmed_unknown_operations": document["confirmed_unknown_operations"],
        "output": str(args.output),
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
