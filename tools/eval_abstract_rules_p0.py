"""Run the public synthetic P0 corpus and print a value-free JSON comparison."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.rule.builtin_rules import (
    legacy_relation_outcome,
    parameter_occurrence_from_values,
    run_builtin_p0,
)
from apiAnalysis.rule.framework import EndpointFact


DEFAULT_CORPUS = Path(__file__).parents[1] / "tests" / "fixtures" / "abstract_rule_p0_corpus.json"


def _load(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    endpoints = tuple(EndpointFact(
        fact_id=item["fact_id"], project_id=item["project_id"], env_id=item["env_id"],
        pathid=item["pathid"], method=item["method"], path_template=item["path_template"],
        action=item.get("action", ""), classification_source=item.get("classification_source", "none"),
        has_request_body=item.get("has_request_body", False),
        response_status_codes=tuple(item.get("response_status_codes", ())),
    ) for item in data["endpoints"])
    parameters = []
    for item in data["parameters"]:
        locator = {
            "version": 2, "direction": item["direction"], "position": item["position"],
            "kind": "parameter" if item["position"] != "body" else "instance",
            "schema_path": item["canonical_name"], "canonical_name": item["canonical_name"],
            "tokens": [{"kind": "property", "value": item["canonical_name"], "dynamic": False}],
        }
        parameters.append(parameter_occurrence_from_values(
            fact_id=item["fact_id"], project_id=item["project_id"], env_id=item["env_id"],
            endpoint_ref=item["endpoint_ref"], pathid=item["pathid"], direction=item["direction"],
            canonical_name=item["canonical_name"], parameter_type=item["parameter_type"],
            required=False, locator=locator, values=item["values"], principal_id=item["principal_id"],
            profile_revision_id=item["profile_revision_id"], scope_key=item["scope_key"],
        ))
    return data, endpoints, tuple(parameters)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    args = parser.parse_args(argv)
    data, endpoints, parameters = _load(args.corpus)
    reports = run_builtin_p0(endpoints, parameters)
    facts = {item.fact_id: item for item in parameters}
    response_ref, request_ref = data["legacy_empty_pair"]
    legacy = legacy_relation_outcome(facts[response_ref], facts[request_ref])
    new_relation = "none"
    for report in reports:
        for match in report.matches:
            output = match.output
            if (
                getattr(output, "producer_ref", "") == response_ref
                and getattr(output, "consumer_ref", "") == request_ref
            ):
                new_relation = output.relation
    payload = {
        "schema_version": "abstract-rule-p0-eval.v1",
        "mode": "offline_dry_run",
        "network_requests": 0,
        "database_writes": 0,
        "rules": [{
            "rule_id": report.rule_id,
            "version": report.rule_version,
            "evaluated_combinations": report.evaluated_combinations,
            "match_count": len(report.matches),
            "rejection_counts": dict(report.rejection_counts),
        } for report in reports],
        "corrected_empty_intersection": {
            "legacy_relation": legacy["relation"],
            "p0_relation": new_relation,
        },
    }
    json.dump(payload, sys.stdout, ensure_ascii=False, sort_keys=True, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
