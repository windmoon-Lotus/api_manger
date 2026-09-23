"""Inspect and advance the blocked plan for one project/environment.

Readiness is derived from recorded facts, never stored.  This tool changes two
things only: the manual step lifecycle (``step``) and the recorded state of a
precondition (``fact``).  Readiness is then re-derived on every read.

Nothing here sends a request.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.db.collection import precondition_fact, unlock_step
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.unlock_plan import (
    FACT_TITLES,
    blocking_summary,
    evaluate_steps,
    list_facts,
    list_steps,
    record_fact,
    seed_default_plan,
)

FACT_STATES = (precondition_fact.SATISFIED, precondition_fact.UNSATISFIED,
               precondition_fact.UNKNOWN)
STEP_STATUSES = (unlock_step.PENDING, unlock_step.IN_PROGRESS, unlock_step.DONE,
                 unlock_step.ABANDONED)


def _scope(parser):
    parser.add_argument("--project-id", default="")
    parser.add_argument("--env-id", default="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect and advance the blocked plan (readiness derived from facts).",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    seed = commands.add_parser("seed", help="Create missing steps and facts (idempotent).")
    _scope(seed)

    status = commands.add_parser("status", help="Show readiness and what blocks what.")
    _scope(status)

    fact = commands.add_parser("fact", help="Record a precondition's state with evidence.")
    _scope(fact)
    fact.add_argument("fact_key", choices=sorted(FACT_TITLES))
    fact.add_argument("state", choices=FACT_STATES)
    fact.add_argument("--evidence-ref", default="")
    fact.add_argument("--trace-id", action="append", default=[],
                      help="Link an observed trace id as evidence. Repeatable.")
    fact.add_argument("--run-id", default="",
                      help="The run that observed this precondition being met.")
    fact.add_argument("--manual-confirmation", action="store_true",
                      help="Record satisfied without referenced evidence. Stored in the note.")
    fact.add_argument("--note", default="")
    fact.add_argument("--value-summary", default="",
                      help="JSON object summarising the observed value.")

    step = commands.add_parser("step", help="Set a step's manual lifecycle status.")
    _scope(step)
    step.add_argument("step_key")
    step.add_argument("status", choices=STEP_STATUSES)
    step.add_argument("--evidence-ref", default="")
    step.add_argument("--note", default="")
    return parser


def _step_report(project_id: str, env_id: str) -> dict:
    steps = list_steps(project_id=project_id, env_id=env_id)
    facts = list_facts(project_id=project_id, env_id=env_id)
    evaluated = {item["step_key"]: item for item in evaluate_steps(steps, facts)}
    fact_state = {
        str(getattr(item, "fact_key", "")): {
            "state": str(getattr(item, "state", "") or ""),
            "title": str(getattr(item, "title", "") or ""),
            "evidence_ref": str(getattr(item, "evidence_ref", "") or ""),
            "satisfied_at": (
                item.satisfied_at.isoformat()
                if getattr(item, "satisfied_at", None) else ""
            ),
        }
        for item in facts
    }
    return {
        "project_id": project_id,
        "env_id": env_id,
        "summary": blocking_summary(steps, facts),
        "facts": fact_state,
        "steps": [
            {"step_key": str(getattr(item, "step_key", "") or ""),
             "title": str(getattr(item, "title", "") or ""),
             "serves": str(getattr(item, "serves", "") or ""),
             "status": str(getattr(item, "status", "") or ""),
             "priority": getattr(item, "priority", None),
             "requires_fact_keys": list(getattr(item, "requires_fact_keys", None) or []),
             "produces_fact_keys": list(getattr(item, "produces_fact_keys", None) or []),
             "readiness": evaluated.get(
                 str(getattr(item, "step_key", "") or ""), {}
             ).get("readiness", ""),
             "blocked_by": evaluated.get(
                 str(getattr(item, "step_key", "") or ""), {}
             ).get("blocked_by", []),
             "downstream_count": evaluated.get(
                 str(getattr(item, "step_key", "") or ""), {}
             ).get("downstream_count", 0)}
            for item in steps
        ],
    }


def main() -> None:
    args = build_parser().parse_args()
    _ensure_mongo_connection()
    project_id, env_id = args.project_id, args.env_id

    if args.command == "seed":
        print(json.dumps(seed_default_plan(project_id=project_id, env_id=env_id),
                         ensure_ascii=False, indent=2, sort_keys=True))
        return

    if args.command == "fact":
        summary = {}
        if args.value_summary:
            try:
                summary = json.loads(args.value_summary)
            except ValueError as exc:
                raise SystemExit("--value-summary must be a JSON object: {}".format(exc))
        record_fact(
            fact_key=args.fact_key, state=args.state, project_id=project_id, env_id=env_id,
            evidence_ref=args.evidence_ref, evidence_trace_ids=args.trace_id,
            satisfied_by_run_id=args.run_id or None,
            note=args.note, value_summary=summary,
            manual_confirmation=args.manual_confirmation,
        )

    if args.command == "step":
        updated = unlock_step.objects(
            project_id=project_id, env_id=env_id, step_key=args.step_key
        ).update_one(
            set__status=args.status,
            set__evidence_ref=args.evidence_ref,
            set__note=args.note,
        )
        if not updated:
            raise SystemExit("unknown step_key: {}".format(args.step_key))

    print(json.dumps(_step_report(project_id, env_id),
                     ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
