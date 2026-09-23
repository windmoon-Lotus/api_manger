"""Search stored request traces across runs as an evidence chain.

Read-only.  This tool sends no requests and returns no values for request
construction: a trace says where an earlier conclusion came from, not what a
current value is.

The point of cross-run search is to answer "has any earlier run already seen
this response" without re-running anything.  The motivating case is an error
signature: two engines used different SQL error dictionaries and the narrower
one ran against the larger workload.

Self-confirmation guard
-----------------------
By default the calling run is excluded, so a stored trace can never be reused
to confirm the conclusion it produced.  Searching every run is possible but must
be asked for explicitly with ``--all-runs``, which prints a warning.
"""
import argparse
import datetime as dt
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.trace_index import (
    ERROR_SIGNATURES,
    build_search_query,
    describe_hit,
    search_prior_evidence,
    search_traces,
    summarize_hits,
)


def _parse_moment(value):
    if not value:
        return None
    text = str(value).strip()
    try:
        return dt.datetime.fromisoformat(text)
    except ValueError:
        parsed = dt.datetime.strptime(text, "%Y-%m-%d")
        return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Search stored request traces across runs (read-only, no network).",
    )
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument(
        "--run-id",
        help="Calling run. Excluded from results so a stored trace cannot confirm "
             "the conclusion it produced.",
    )
    scope.add_argument(
        "--all-runs", action="store_true",
        help="Search every run, including your own. Use only for inventory sweeps.",
    )
    parser.add_argument("--text", help="Substring to find in stored response text.")
    parser.add_argument(
        "--signature", action="append", default=[], choices=sorted(ERROR_SIGNATURES),
        help="Restrict to a known error-signature class. Repeatable.",
    )
    parser.add_argument("--signal-class", action="append", default=[],
                        help="Restrict to a stored signal class. Repeatable.")
    parser.add_argument("--host")
    parser.add_argument("--path")
    parser.add_argument("--pathid", type=int)
    parser.add_argument("--parameter")
    parser.add_argument("--engine")
    parser.add_argument("--check-type")
    parser.add_argument("--project-id")
    parser.add_argument("--env-id")
    parser.add_argument("--account-id", help="Restrict to one account's observations.")
    parser.add_argument("--exclude-account-id",
                        help="Also exclude one account (use when your own writes are attributed to it).")
    parser.add_argument("--after", help="ISO date or datetime lower bound on observed_at.")
    parser.add_argument("--before", help="ISO date or datetime upper bound on observed_at.")
    parser.add_argument("--stable-only", action="store_true",
                        help="Only traces whose baseline was stable.")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--snippet-window", type=int, default=160)
    parser.add_argument("--no-snippets", action="store_true",
                        help="Print provenance only, without response excerpts.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    _ensure_mongo_connection()

    filters = dict(
        text=args.text,
        error_signatures=args.signature or None,
        signal_classes=args.signal_class or None,
        host=args.host,
        path=args.path,
        pathid=args.pathid,
        parameter_name=args.parameter,
        engine=args.engine,
        check_type=args.check_type,
        project_id=args.project_id,
        env_id=args.env_id,
        account_id=args.account_id,
        stable_only=args.stable_only,
        observed_after=_parse_moment(args.after),
        observed_before=_parse_moment(args.before),
    )

    if args.all_runs:
        guard = "all_runs_includes_caller"
        hits = search_traces(limit=args.limit, **filters)
    else:
        guard = "excluded_run:{}".format(args.run_id)
        hits = search_prior_evidence(
            run_id=args.run_id,
            exclude_account_id=args.exclude_account_id,
            limit=args.limit,
            **filters,
        )

    needle = args.text or ""
    report = {
        "guard": guard,
        "query": {key: value for key, value in filters.items() if value not in (None, [], False)},
        "summary": summarize_hits(hits),
        "hits": [
            describe_hit(hit, needle=needle, snippet_window=args.snippet_window)
            for hit in hits
        ],
    }
    if args.all_runs:
        report["warning"] = (
            "Results may include the calling run. Do not treat a match here as "
            "independent confirmation of a conclusion produced by that run."
        )
    if args.no_snippets:
        for hit in report["hits"]:
            hit.pop("snippet", None)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
