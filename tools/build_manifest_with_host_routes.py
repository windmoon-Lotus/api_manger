"""Overlay host-router (per-path host mapping from 3690 probe) onto
build_sqli_screen_manifest output, so SQLi adapter dispatches each path
to the host that the baseline probe confirmed accepts it (business host
for 126 paths, slapi.oray.net catch-all for 596 paths), and 16 unresolvable
paths are marked excluded and skipped by persist_sqli_screen_snapshots.

This is a thin post-processor; it does not modify sqli_screen.py.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PENDING_ROUTE_MARKER = "__pending_route__"


def _load_router(path: Path) -> Dict[Tuple[str, str], str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    by_key: Dict[Tuple[str, str], str] = {}
    for entry in data.get("business", []) + data.get("catch_all", []):
        by_key[(str(entry["method"]).upper(), str(entry["path"]))] = str(entry["host"])
    return by_key


def _load_excluded(path: Path) -> set:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        (str(e["method"]).upper(), str(e["path"]))
        for e in data.get("excluded", [])
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--openapi", required=True, help="Path to OpenAPI export JSON.")
    parser.add_argument("--host-router", required=True,
                        help="Path to a private route-resolution JSON manifest.")
    parser.add_argument("--output", required=True, help="Output manifest path (overlaid).")
    args = parser.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from apiAnalysis.tool.sqli_screen import build_sqli_screen_manifest

    base = build_sqli_screen_manifest(args.openapi)
    router = _load_router(Path(args.host_router))
    excluded = _load_excluded(Path(args.host_router))

    items = base.get("items") or []
    overlaid: List[Dict[str, Any]] = []
    coverage = {
        "business": 0,
        "catch_all": 0,
        "regex_default": 0,
        "pending_after_overlay": 0,
        "excluded": 0,
    }
    for item in items:
        method = str(item.get("method") or "GET").upper()
        path = str(item.get("path") or "")
        key = (method, path)
        new_item = dict(item)
        if key in excluded:
            new_item["host"] = PENDING_ROUTE_MARKER
            new_item["routePending"] = True
            new_item["excludedReason"] = "5-host probe: all 4xx/5xx (see host-routes-manifest-2026-08-27.json)"
            coverage["excluded"] += 1
        elif key in router:
            new_item["host"] = router[key]
            new_item["routePending"] = False
            new_item["routeSource"] = (
                "business_routed" if (method, path) in
                {(str(b["method"]).upper(), str(b["path"])) for b in
                 json.loads(Path(args.host_router).read_text(encoding="utf-8")).get("business", [])}
                else "catch_all"
            )
            if new_item["routeSource"] == "business_routed":
                coverage["business"] += 1
            else:
                coverage["catch_all"] += 1
        else:
            # leave the original host_overrides resolution; just count
            if item.get("routePending"):
                coverage["pending_after_overlay"] += 1
            else:
                coverage["regex_default"] += 1
        overlaid.append(new_item)

    # rebuild pending list to match the overlaid manifest
    pending = [
        {"method": it.get("method"), "path": it.get("path"), "host": it.get("host"),
         "paramCount": len(it.get("params") or [])}
        for it in overlaid if it.get("routePending")
    ]

    out = dict(base)
    out["items"] = overlaid
    out["pendingRouteResolution"] = pending
    out["hostOverlay"] = {
        "router_source": args.host_router,
        "stats": coverage,
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print("wrote {}: items={}, pending={}, overlay stats={}".format(
        args.output, len(overlaid), len(pending), coverage,
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
