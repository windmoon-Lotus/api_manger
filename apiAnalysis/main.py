from apiAnalysis.db.save import *
import argparse
import json
import logging
import sys
from typing import Optional, Sequence
from mongoengine import connect
from mongoengine.connection import get_connection
from apiAnalysis.conf.secret import mongo_database, mongo_user, mongo_password, mongo_host, mongo_port
from apiAnalysis.rule.analysis import analysis
from apiAnalysis.runtime_check import checks_ok, format_checks, run_checks
from apiAnalysis.tool.compose_request import create_request_snapshot
from apiAnalysis.db.collection import raw_data
from apiAnalysis.tool.redact import redact_url
from apiAnalysis.tool.snapshot_runner import replay_snapshot_by_id, replay_snapshots


def _configure_cli_logging(log_level: str = None, quiet: bool = False):
    level_name = (log_level or "INFO").upper()
    if quiet:
        level_name = "WARNING"
    level = getattr(logging, level_name, logging.INFO)
    logging.getLogger().setLevel(level)
    logging.getLogger("apiAnalysis").setLevel(level)
    set_progress_output_enabled(not quiet)


def _ensure_mongo_connection():
    """
    Ensure CLI has a default Mongo connection without requiring apiAnalysis.init().
    """
    try:
        get_connection()
        return
    except Exception:
        pass
    connect(
        mongo_database,
        username=mongo_user,
        password=mongo_password,
        host=mongo_host,
        port=mongo_port,
        connect=False,
    )


def main(override_args: Optional[Sequence[str]] = None):
    parser = argparse.ArgumentParser(
        description="will a mitmproxy dump file or HAR or openapi to a mongodb and analysis."
    )
    parser.add_argument(
        "-i",
        "--input",
        help="The input mitmproxy dump file or HAR dump file or openapi json file (from DevTools)",
        #required=True,
    )

    #parser.add_argument("-p", "--api-prefix", help="The api prefix", required=True)

    parser.add_argument(
        "-e",
        "--examples",
        action="store_true",
        help="Include examples in the mongodb. This might expose sensitive information.",
    )
    parser.add_argument(
        "-hd",
        "--headers",
        action="store_true",
        help="Include headers in the mongodb. This might expose sensitive information.",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["flow", "har", "openapi", "postman"],
        help="Override the input file format auto-detection.",
    )
    parser.add_argument(
        "--base-url",
        help="Root URL for OpenAPI/Postman files that contain relative paths, for example https://api.example.com.",
    )
    parser.add_argument(
        "-p",
        "--parameter-disassemble",
        #default="[0-9]+",
        action="store_true",
        help="Regex to match parameters in the API paths. Path segments that match this regex will be turned into parameter placeholders.",
    )
    parser.add_argument(
        "-s",
        "--suppress-params",
        action="store_true",
        help="Do not include API paths that have the original parameter values, only the ones with placeholders.",
    )
    parser.add_argument(
        "--privilege-tasks",
        action="store_true",
        help="Prepare privilege scan tasks with target filtering.",
    )
    parser.add_argument(
        "--privilege-exec",
        action="store_true",
        help="Execute pending privilege scan tasks.",
    )
    parser.add_argument(
        "--privilege-limit",
        type=int,
        default=20,
        help="Limit privilege task execution count.",
    )
    parser.add_argument(
        "--ai-stub",
        action="store_true",
        help="Populate AI result fields using stub logic.",
    )
    parser.add_argument(
        "--ai-http",
        action="store_true",
        help="Call AI HTTP endpoint and persist result fields.",
    )
    parser.add_argument(
        "--ai-url",
        help="Override AI endpoint URL.",
    )
    parser.add_argument(
        "--ai-key",
        help="Override AI API key.",
    )
    parser.add_argument(
        "--ai-limit",
        type=int,
        default=20,
        help="Limit AI stub execution count.",
    )
    parser.add_argument(
        "--verify-relations-real",
        action="store_true",
        help="Verify weak parameter relations via real replay.",
    )
    parser.add_argument(
        "--verify-limit",
        type=int,
        default=200,
        help="Limit relation count for real replay verification.",
    )
    parser.add_argument(
        "--verify-min-score",
        type=float,
        default=60.0,
        help="Minimum relation score to run real replay verification.",
    )
    parser.add_argument(
        "--account-id",
        help="Bind parameter archive values to account_id when building archives.",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set CLI log level (default: INFO).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce output noise: set log level to WARNING and disable progress bar.",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Run environment checks for Python, MongoDB, Redis, upload dir, and external tools.",
    )
    parser.add_argument(
        "--snapshot-pathid",
        type=int,
        help="Create one reproducible request snapshot for a parsed API path id.",
    )
    parser.add_argument(
        "--snapshot-all",
        action="store_true",
        help="Create reproducible request snapshots for parsed API assets.",
    )
    parser.add_argument(
        "--snapshot-limit",
        type=int,
        default=100,
        help="Limit snapshot creation when --snapshot-all is used.",
    )
    parser.add_argument(
        "--replay-snapshot",
        help="Replay one request snapshot id and print structured evidence.",
    )
    parser.add_argument(
        "--replay-snapshots",
        action="store_true",
        help="Replay recent request snapshots for stage-2 validation.",
    )
    parser.add_argument(
        "--replay-limit",
        type=int,
        default=5,
        help="Limit snapshot replay count when --replay-snapshots is used.",
    )
    parser.add_argument(
        "--replay-domain-regex",
        help="Optional domain regex filter for --replay-snapshots, for example 'example\\\\.com'.",
    )
    args = parser.parse_args(override_args)
    _configure_cli_logging(log_level=args.log_level, quiet=args.quiet)
    if args.doctor:
        checks = run_checks()
        print(format_checks(checks))
        return 0 if checks_ok(checks) else 1
    _ensure_mongo_connection()
    if args.snapshot_pathid is not None:
        snapshot = create_request_snapshot(args.snapshot_pathid, account_id=args.account_id)
        if not snapshot:
            print("snapshot not created: pathid {} not found".format(args.snapshot_pathid))
            return 1
        print("snapshot created: {} pathid={} url={}".format(snapshot.id, snapshot.pathid, redact_url(snapshot.url)))
        return 0
    if args.snapshot_all:
        limit = args.snapshot_limit if args.snapshot_limit and args.snapshot_limit > 0 else 100
        created = 0
        for item in raw_data.objects.order_by("-ptah_id").limit(limit):
            snapshot = create_request_snapshot(item.ptah_id, account_id=args.account_id)
            if snapshot:
                created += 1
        print("snapshots created: {}".format(created))
        return 0
    if args.replay_snapshot:
        result = replay_snapshot_by_id(args.replay_snapshot)
        if not result:
            print("snapshot not found: {}".format(args.replay_snapshot))
            return 1
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("ok") else 2
    if args.replay_snapshots:
        results = replay_snapshots(limit=args.replay_limit, domain_regex=args.replay_domain_regex)
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0 if all(item.get("ok") for item in results) else 2
    #print(args)
    imported_raw_ids = []
    if args.format == "flow" or args.format == "mitmproxy":
        imported_raw_ids = data_generate_mongodb(args.input, "mitm") or []
    elif args.format == "har":
        imported_raw_ids = data_generate_mongodb(args.input, "har") or []
    elif args.format == "openapi":
        data_generate_openapi(args.input, base_url=args.base_url)
    elif args.format == "postman":
        data_generate_postman(args.input, base_url=args.base_url)
        # capture_reader = HarCaptureReader(args.input, progress_callback)
        # try:
        #     for req in capture_reader.captured_requests():
        #         print(req.get_url())
        # except Exception as e:
        #     print("capture_reader", e)
    else:
        pass
    analysis().classify_raw_data()
    call = analysis()
    if args.parameter_disassemble:
        parameter_disassemble_mongodb(raw_ids=imported_raw_ids or None)
        parameter_date_mongodb(raw_ids=imported_raw_ids or None)
        call.parameter_archive(account_id=args.account_id)
        call.infer_weak_relations()
        call.verify_weak_relations()
        call.build_request_compose()
    if args.privilege_tasks:
        call.prepare_privilege_tasks()
    if args.privilege_exec:
        call.execute_privilege_tasks(limit=args.privilege_limit)
    if args.ai_stub:
        call.execute_ai_stub(limit=args.ai_limit)
    if args.ai_http:
        call.execute_ai_http(limit=args.ai_limit, url=args.ai_url, api_key=args.ai_key)
    if args.verify_relations_real:
        call.verify_weak_relations_real(limit=args.verify_limit, min_score=args.verify_min_score)

if __name__ == "__main__":
    sys.exit(main())
