"""Post-run cleanup audit: sweep live services for leftover test objects.

After a test round that created objects (tagged with a known prefix), this
tool re-queries the live list endpoints and searches responses for those
prefixes. A round is only clean when the sweep finds zero matches.

Target-specifics (URLs, headers, prefixes) all come from a sweep config file
so this tool itself stays publishable - no hosts, no credentials in repo.

Sweep config (JSON):
  {
    "sweeps": [
      {"url": "https://host.example.com/api/list", "prefixes": ["evalrun1_"],
       "note": "created objects"}
    ]
  }

Headers can come from --headers-file (recommended, outside the repo) or
--header (repeatable, 'Name: value').

Usage:
  python -m tools.audit.cleanup_audit --config sweeps.json \
      --header "Authorization: Bearer ..." [--out report.json]
"""
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]

CONTEXT_CHARS = 60
EXIT_CLEAN = 0
EXIT_RESIDUE = 1
EXIT_NOT_EVALUABLE = 2


def find_prefix_hits(body: str, prefixes: List[str]) -> List[Dict[str, Any]]:
    """Find prefix occurrences in a response body with bounded context."""
    hits: List[Dict[str, Any]] = []
    for prefix in prefixes:
        start = 0
        count = 0
        while True:
            idx = body.find(prefix, start)
            if idx < 0:
                break
            count += 1
            if count <= 5:
                lo = max(0, idx - CONTEXT_CHARS)
                hi = min(len(body), idx + len(prefix) + CONTEXT_CHARS)
                hits.append({
                    "prefix": prefix,
                    "context": body[lo:hi],
                    "position": idx,
                })
            start = idx + len(prefix)
        if count > 5:
            hits.append({"prefix": prefix, "truncated": True,
                         "totalMatches": count})
    return hits


def sweep_one(url: str, prefixes: List[str], headers: Dict[str, str],
              timeout: float,
              fetch=None) -> Dict[str, Any]:
    fetch = fetch or _default_fetch
    try:
        status, body = fetch(url, headers, timeout)
    except Exception as exc:
        return {"url": url, "status": None, "error": f"{type(exc).__name__}: {exc}",
                "hitCount": 0, "hits": [], "result": "not_evaluable"}
    hits = find_prefix_hits(body or "", prefixes) if status == 200 else []
    if status == 200:
        result = "residue" if hits else "clean"
    else:
        # non-200 = THIS sweep could not check (wrong route, or the endpoint is
        # owner-scoped and this account cannot see it). Not clean, not residue.
        result = "not_evaluable"
    return {
        "url": url,
        "status": status,
        "hitCount": len(hits),
        "hits": hits,
        "result": result,
        "note": "non-200 status: sweep could not verify this endpoint with this "
                "account (wrong route, or owner-scoped visibility)"
                if status != 200 else "",
    }


def _default_fetch(url: str, headers: Dict[str, str], timeout: float):
    import requests
    r = requests.get(url, headers=headers, timeout=timeout, verify=False,
                     allow_redirects=False)
    return r.status_code, (r.content or b"").decode("utf-8", errors="replace")


def run_sweeps(config: Dict[str, Any], headers: Dict[str, str], timeout: float,
               fetch=None) -> Dict[str, Any]:
    results = [sweep_one(s.get("url") or "", list(s.get("prefixes") or []),
                         headers, timeout, fetch=fetch)
               for s in config.get("sweeps") or []]
    any_residue = any(r["result"] == "residue" for r in results)
    any_not_evaluable = any(r["result"] == "not_evaluable" for r in results)
    if any_residue:
        verdict = "residue"
    elif not results:
        verdict = "no_sweeps"
    elif any_not_evaluable:
        verdict = "not_evaluable"
    else:
        verdict = "clean"
    return {
        "tool": "cleanup_audit",
        "sweeps": results,
        "verdict": verdict,
    }


def verdict_exit_code(verdict: str) -> int:
    """Map verdicts to fail-closed process exit codes."""
    if verdict == "clean":
        return EXIT_CLEAN
    if verdict == "residue":
        return EXIT_RESIDUE
    return EXIT_NOT_EVALUABLE


def main() -> int:
    parser = argparse.ArgumentParser(description="Sweep live endpoints for leftover test objects.")
    parser.add_argument("--config", required=True, help="sweep config JSON file")
    parser.add_argument("--header", action="append", default=[],
                        help="request header, 'Name: value' (repeatable)")
    parser.add_argument("--headers-file",
                        help="JSON file holding a {Name: value} header dict "
                             "(merged after --header; keep secrets out of argv)")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--out", help="write report JSON here (default: stdout only)")
    args = parser.parse_args()

    headers = {}
    if args.headers_file:
        loaded = json.loads(Path(args.headers_file).read_text(encoding="utf-8-sig"))
        if not isinstance(loaded, dict):
            raise SystemExit("--headers-file must contain a JSON object of headers")
        headers.update(loaded)
    for h in args.header:
        if ":" not in h:
            raise SystemExit(f"--header expects 'Name: value', got {h!r}")
        name, value = h.split(":", 1)
        headers[name.strip()] = value.strip()
    headers.setdefault("User-Agent", "cleanup-audit/1.0")

    config = json.loads(Path(args.config).read_text(encoding="utf-8-sig"))
    report = run_sweeps(config, headers, args.timeout)

    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    return verdict_exit_code(str(report.get("verdict") or ""))


if __name__ == "__main__":
    raise SystemExit(main())
