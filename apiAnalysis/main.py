"""Thin CLI for runtime checks and the single import.v1 contract.

Business request execution is deliberately absent.  Queue work through the
dedicated scheduling tools and let ``run_execution_worker.py`` own network I/O.
"""
import argparse
import json
import logging
import sys
from typing import Optional, Sequence

from mongoengine import connect
from mongoengine.connection import get_connection

from apiAnalysis.conf.secret import (
    mongo_database,
    mongo_host,
    mongo_password,
    mongo_port,
    mongo_user,
)
from apiAnalysis.db.save import set_progress_output_enabled
from apiAnalysis.import_pipeline import ImportRequest, execute_import
from apiAnalysis.runtime_check import checks_ok, format_checks, run_checks
from apiAnalysis.version import __version__


def _configure_cli_logging(log_level: str = None, quiet: bool = False):
    level_name = (log_level or "INFO").upper()
    if quiet:
        level_name = "WARNING"
    level = getattr(logging, level_name, logging.INFO)
    logging.getLogger().setLevel(level)
    logging.getLogger("apiAnalysis").setLevel(level)
    set_progress_output_enabled(not quiet)


def _ensure_mongo_connection():
    """Register the CLI Mongo connection without creating a Flask app."""
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Import API evidence through import.v1 or inspect runtime health.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("-i", "--input", help="Input file path.")
    parser.add_argument(
        "-f", "--format",
        choices=["flow", "har", "openapi", "postman", "apifox"],
        help="Explicit importer type.",
    )
    parser.add_argument("--base-url", default="")
    parser.add_argument("--source-id", default="", help="Stable external data-source identity.")
    parser.add_argument("--source-name", default="", help="Human-readable data-source name.")
    parser.add_argument("--project-id", default="")
    parser.add_argument("--env-id", default="")
    parser.add_argument("--account-id", default="")
    parser.add_argument(
        "-p", "--parameter-disassemble", action="store_true",
        help="Run scoped parameter extraction after import.",
    )
    parser.add_argument("--doctor", action="store_true")
    parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO",
    )
    parser.add_argument("--quiet", action="store_true")
    return parser


def main(override_args: Optional[Sequence[str]] = None):
    parser = build_parser()
    args = parser.parse_args(override_args)
    _configure_cli_logging(args.log_level, args.quiet)
    if args.doctor:
        checks = run_checks(include_resolver_check=True)
        print(format_checks(checks))
        return 0 if checks_ok(checks) else 1
    if not args.input or not args.format:
        parser.error("--input and --format are required unless --doctor is used")
    _ensure_mongo_connection()
    outcome = execute_import(ImportRequest(
        source_type=args.format,
        source_path=args.input,
        source_id=args.source_id,
        source_name=args.source_name,
        base_url=args.base_url,
        project_id=args.project_id,
        env_id=args.env_id,
        account_id=args.account_id or None,
        run_parameters=args.parameter_disassemble,
    ))
    print(json.dumps({
        "import_run_id": outcome.run.import_run_id,
        "status": outcome.run.status,
        "summary": outcome.summary,
    }, ensure_ascii=False, sort_keys=True))
    return 0 if outcome.run.status == outcome.run.DONE else 1


if __name__ == "__main__":
    sys.exit(main())
