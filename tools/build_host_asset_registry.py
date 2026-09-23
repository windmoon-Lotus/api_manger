"""Aggregate operation-level placement into a Host-level asset registry."""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Tuple


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--placement-jsonl", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    assets: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    with args.placement_jsonl.open("r", encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            seen = set()
            for candidate in row.get("host_candidates") or []:
                key = (
                    str(row["project_id"]), str(candidate["host"]),
                    str(candidate.get("environment_class") or "unknown"),
                )
                if key in seen:
                    continue
                seen.add(key)
                asset = assets.setdefault(key, {
                    "project_id": key[0], "host": key[1], "environment_class": key[2],
                    "runtime_confirmed_operations": 0,
                    "direct_candidate_operations": 0,
                    "module_candidate_operations": 0,
                    "conflict_operations": 0,
                    "evidence_sources": set(),
                    "confirmed_paths": set(),
                })
                status = str(row.get("placement_status") or "")
                if status == "runtime_confirmed" and candidate.get("confidence") == "confirmed":
                    asset["runtime_confirmed_operations"] += 1
                    asset["confirmed_paths"].add("{} {}".format(row["method"], row["path"]))
                elif status == "direct_candidate":
                    asset["direct_candidate_operations"] += 1
                elif status == "module_candidate":
                    asset["module_candidate_operations"] += 1
                elif status == "conflict":
                    asset["conflict_operations"] += 1
                asset["evidence_sources"].add(str(candidate.get("source") or ""))

    output = []
    for key in sorted(assets):
        asset = assets[key]
        asset["asset_status"] = (
            "runtime_confirmed" if asset["runtime_confirmed_operations"]
            else "candidate_only"
        )
        asset["evidence_sources"] = sorted(x for x in asset["evidence_sources"] if x)
        asset["confirmed_paths"] = sorted(asset["confirmed_paths"])
        output.append(asset)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "host-asset-registry.json").write_text(
        json.dumps({"schema_version": "host-asset-registry.v1", "assets": output},
                   ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    fields = (
        "project_id", "host", "environment_class", "asset_status",
        "runtime_confirmed_operations", "direct_candidate_operations",
        "module_candidate_operations", "conflict_operations",
        "evidence_sources", "confirmed_paths",
    )
    with (args.output_dir / "host-asset-registry.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in output:
            writer.writerow({
                **item,
                "evidence_sources": ";".join(item["evidence_sources"]),
                "confirmed_paths": ";".join(item["confirmed_paths"]),
            })
    print(json.dumps({
        "assets": len(output),
        "runtime_confirmed_assets": sum(x["asset_status"] == "runtime_confirmed" for x in output),
        "output_dir": str(args.output_dir),
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
