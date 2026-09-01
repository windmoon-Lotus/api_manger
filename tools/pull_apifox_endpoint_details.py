import argparse
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def load_json(path: Path) -> Dict[str, Any]:
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-16", "utf-16le", "gbk"):
        try:
            return json.loads(raw.decode(encoding))
        except Exception:
            continue
    raise ValueError(f"Cannot decode JSON file: {path}")


def endpoints_from_list(path: Path, statuses: Iterable[str] = ()) -> List[Dict[str, Any]]:
    doc = load_json(path)
    wanted = {item.strip().lower() for item in statuses if item.strip()}
    endpoints = []
    for item in doc.get("data") or []:
        if not item.get("id"):
            continue
        status = str(item.get("status") or "").lower()
        if wanted and status not in wanted:
            continue
        endpoints.append(item)
    return endpoints


def run_apifox_list(apifox_cmd: str, project_id: int, timeout: int) -> Dict[str, Any]:
    """Read the current endpoint list without persisting CLI output."""
    cmd = [apifox_cmd, "endpoint", "list", "--project", str(project_id)]
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=apifox_cmd.lower().endswith((".cmd", ".bat")),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise ValueError("Apifox endpoint list timed out") from None
    if completed.returncode != 0:
        raise ValueError(
            "Apifox endpoint list failed: {}".format(
                (completed.stderr.strip() or completed.stdout.strip())[:300]
            )
        )
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("Apifox endpoint list returned invalid JSON") from exc
    if not document.get("success") or not isinstance(document.get("data"), list):
        raise ValueError("Apifox endpoint list returned no data")
    return document


def endpoints_from_document(document: Dict[str, Any],
                            statuses: Iterable[str] = ()) -> List[Dict[str, Any]]:
    wanted = {item.strip().lower() for item in statuses if item.strip()}
    endpoints = []
    for item in document.get("data") or []:
        if not item.get("id"):
            continue
        status = str(item.get("status") or "").lower()
        if wanted and status not in wanted:
            continue
        endpoints.append(item)
    return endpoints


def run_apifox_get(apifox_cmd: str, project_id: int, endpoint_id: int, timeout: int) -> Dict[str, Any]:
    cmd = [apifox_cmd, "endpoint", "get", str(endpoint_id), "--project", str(project_id)]
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=apifox_cmd.lower().endswith((".cmd", ".bat")),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "endpoint_id": endpoint_id,
            "error": f"timeout after {timeout}s",
        }
    if completed.returncode != 0:
        return {
            "success": False,
            "endpoint_id": endpoint_id,
            "error": completed.stderr.strip() or completed.stdout.strip(),
        }
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return {
            "success": False,
            "endpoint_id": endpoint_id,
            "error": f"invalid json: {exc}",
            "stdout_sample": completed.stdout[:500],
        }


def pull_one(apifox_cmd: str, project_id: int, endpoint_id: int, out_path: Path, force: bool, timeout: int) -> Tuple[str, Dict[str, Any]]:
    if out_path.exists() and not force:
        return "skipped", {"endpoint_id": endpoint_id}
    detail = run_apifox_get(apifox_cmd, project_id, endpoint_id, timeout)
    if not detail.get("success"):
        return "failed", {"endpoint_id": endpoint_id, "error": detail.get("error", "")[:300]}
    out_path.write_text(json.dumps(detail, ensure_ascii=False, indent=2), encoding="utf-8")
    return "pulled", {"endpoint_id": endpoint_id}


def main() -> int:
    parser = argparse.ArgumentParser(description="Pull full Apifox endpoint detail JSON files from an endpoint list.")
    parser.add_argument("--project", type=int, required=True)
    parser.add_argument(
        "--endpoint-list",
        help="Cached endpoint-list JSON. Omit to read the current list from Apifox.",
    )
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--apifox-cmd", default="", help="Apifox executable. Defaults to apifox.cmd on Windows when available.")
    parser.add_argument("--statuses", default="released,deprecated,obsolete", help="Comma-separated statuses to include; empty means all.")
    parser.add_argument(
        "--all-statuses", action="store_true",
        help="Include developing/testing and any other current endpoint status.",
    )
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent apifox endpoint get workers.")
    parser.add_argument("--request-timeout", type=int, default=90, help="Per-endpoint apifox command timeout in seconds.")
    args = parser.parse_args()

    apifox_cmd = args.apifox_cmd or shutil.which("apifox.cmd") or shutil.which("apifox") or "apifox"
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    statuses = (
        [] if args.all_statuses
        else ([item.strip() for item in args.statuses.split(",")] if args.statuses else [])
    )
    if args.endpoint_list:
        endpoints = endpoints_from_list(Path(args.endpoint_list), statuses=statuses)
        list_source = "cached"
    else:
        endpoints = endpoints_from_document(
            run_apifox_list(apifox_cmd, args.project, args.request_timeout),
            statuses=statuses,
        )
        list_source = "live"
    if args.limit and args.limit > 0:
        endpoints = endpoints[: args.limit]

    pulled = 0
    skipped = 0
    failed = 0
    failures = []
    jobs = [
        (int(item["id"]), out_dir / f"{int(item['id'])}.json")
        for item in endpoints
    ]
    workers = max(1, int(args.workers or 1))
    if workers == 1:
        for endpoint_id, out_path in jobs:
            state, detail = pull_one(apifox_cmd, args.project, endpoint_id, out_path, args.force, args.request_timeout)
            if state == "pulled":
                pulled += 1
            elif state == "skipped":
                skipped += 1
            else:
                failed += 1
                failures.append(detail)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(pull_one, apifox_cmd, args.project, endpoint_id, out_path, args.force, args.request_timeout)
                for endpoint_id, out_path in jobs
            ]
            for future in as_completed(futures):
                state, detail = future.result()
                if state == "pulled":
                    pulled += 1
                elif state == "skipped":
                    skipped += 1
                else:
                    failed += 1
                    failures.append(detail)

    summary = {
        "list_source": list_source,
        "endpoints": len(endpoints),
        "pulled": pulled,
        "skipped": skipped,
        "failed": failed,
        "failures_sample": failures[:20],
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
