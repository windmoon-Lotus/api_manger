"""Save, inspect, dry-run and (explicitly) replay persisted read-chain definitions.

Offline by default. Only ``replay`` touches the network and it additionally
requires ``--live`` and ``--i-understand-live-requests`` plus a full account
context, so no accidental business request can be sent from this tool.

Examples::

    py -3.9 tools/interface_chain_cli.py validate --file <definition.json>
    py -3.9 tools/interface_chain_cli.py import --file <def>.json --project-id <project>
    py -3.9 tools/interface_chain_cli.py show --name <chain-name> --project-id <project>
    py -3.9 tools/interface_chain_cli.py dry-run --name <chain-name> --project-id <project> --bind-from-db
    py -3.9 tools/interface_chain_cli.py dry-run --file <def>.json --sources-json <synthetic-sources.json>
    py -3.9 tools/interface_chain_cli.py list --project-id <project>
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.db.collection import raw_data
from apiAnalysis.tool.execution_contract import ExecutionContext
from apiAnalysis.tool.interface_chain import (
    CHAIN_SCHEMA_VERSION,
    ChainDefinitionError,
    ChainLiveExecutionNotConfirmed,
    account_profile_statuses,
    chain_blocker_summary,
    chain_definition_sha256,
    db_endpoint_lookup,
    deserialize_chain_definition,
    dry_run_chain,
    list_chain_definitions,
    load_chain_definition,
    load_chain_definition_file,
    normalize_chain_definition,
    persist_chain_definition,
    replay_chain_live,
    serialize_chain_definition,
)


def _load_definition(args):
    if args.file:
        return load_chain_definition_file(args.file), "file:{}".format(args.file)
    if not args.name or not args.project_id:
        raise ChainDefinitionError("either --file or (--name and --project-id) is required")
    return load_chain_definition(args.name, project_id=args.project_id, env_id=args.env_id or ""), "mongo"


def _apply_account_alias(definition, alias):
    if not alias:
        return definition
    aliases = {item["alias"] for item in definition.get("account_profiles") or []}
    if alias not in aliases:
        raise ChainDefinitionError(
            "account alias '{}' is not declared by the definition ({})".format(
                alias, ", ".join(sorted(aliases)) or "none",
            )
        )
    for step in definition["steps"]:
        step["account_profile"] = alias
    return definition


def _endpoint_lookup(args):
    if not args.bind_from_db:
        return None
    if not args.project_id:
        raise ChainDefinitionError("--bind-from-db requires --project-id")
    return db_endpoint_lookup(args.project_id)


def _load_sources(path):
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ChainDefinitionError("--sources-json must contain an object of response_ref -> response JSON")
    return data


def _print_json(value):
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, default=str))


def command_validate(args):
    definition, origin = _load_definition(args)
    definition = _apply_account_alias(definition, args.account_alias)
    _print_json({
        "origin": origin,
        "name": definition["name"],
        "schema_version": definition["schema_version"],
        "definition_sha256": chain_definition_sha256(definition),
        "step_count": len(definition["steps"]),
        "steps": [
            {
                "step_id": step["step_id"],
                "pathid": step["pathid"],
                "method": step["method"],
                "placeholder_style": step["placeholder_style"],
                "path_template": step["path_template"],
                "account_profile": step["account_profile"],
                "depends_on": step["depends_on"],
                "parameter_count": len(step["parameters"]),
            }
            for step in definition["steps"]
        ],
        "account_binding": account_profile_statuses(definition),
    })
    return 0


def command_import(args):
    if not args.file or not args.project_id:
        raise ChainDefinitionError("import requires --file and --project-id")
    definition = _apply_account_alias(load_chain_definition_file(args.file), args.account_alias)
    document, created = persist_chain_definition(
        definition,
        project_id=args.project_id,
        env_id=args.env_id or "",
        operator=args.operator or "",
        status=args.status,
    )
    _print_json({
        "name": document.name,
        "project_id": document.project_id,
        "env_id": document.env_id,
        "status": document.status,
        "created": created,
        "definition_sha256": document.definition_sha256,
        "step_count": document.step_count,
        "source_ref": document.source_ref,
    })
    return 0


def command_list(args):
    rows = list_chain_definitions(project_id=args.project_id, env_id=args.env_id)
    _print_json({"count": len(rows), "definitions": rows})
    return 0


def command_show(args):
    if not args.name or not args.project_id:
        raise ChainDefinitionError("show requires --name and --project-id")
    definition = load_chain_definition(args.name, project_id=args.project_id, env_id=args.env_id or "")
    if args.canonical:
        sys.stdout.write(serialize_chain_definition(definition))
        return 0
    _print_json(definition)
    return 0


def command_dry_run(args):
    definition, origin = _load_definition(args)
    definition = _apply_account_alias(definition, args.account_alias)
    sources = _load_sources(args.sources_json)
    plan = dry_run_chain(
        definition,
        sources=sources,
        endpoint_lookup=_endpoint_lookup(args),
        step_failures=args.fail_step or [],
    )
    plan["origin"] = origin
    plan["sources_fixture"] = args.sources_json or ""
    plan["blockers"] = chain_blocker_summary(plan)
    plan["network_requests"] = 0
    _print_json(plan)
    if not plan["safe_to_execute"] and not args.allow_blocked:
        return 1
    return 0


def command_replay(args):
    if not args.live or not args.i_understand_live_requests:
        raise ChainLiveExecutionNotConfirmed(
            "replay requires --live and --i-understand-live-requests; no request was sent"
        )
    if not args.name or not args.project_id:
        raise ChainDefinitionError("replay requires --name and --project-id")
    if not args.bind_from_db:
        raise ChainDefinitionError("replay requires --bind-from-db")
    definition = _apply_account_alias(
        load_chain_definition(args.name, project_id=args.project_id, env_id=args.env_id or ""),
        args.account_alias,
    )
    context = ExecutionContext(
        project_id=args.project_id,
        env_id=args.env_id or "",
        account_id=args.account_id or "",
        auth_mode=args.auth_mode,
        auth_provider_id=args.auth_provider_id or "",
        auth_context_ref=args.auth_context_ref or "",
        auth_profile_revision_id=args.auth_profile_revision_id or "",
        auth_realm_revision_id=args.auth_realm_revision_id or "",
        auth_adapter_version_id=args.auth_adapter_version_id or "",
        adapter_id="interface_chain",
        adapter_version="1",
    )
    resolver = None
    if args.auth_mode == "account":
        from apiAnalysis.tool.account_context import resolver_from_environment
        resolver = resolver_from_environment()
    report = replay_chain_live(
        definition,
        context=context,
        endpoint_lookup=db_endpoint_lookup(args.project_id),
        account_context_resolver=resolver,
        sources=_load_sources(args.sources_json),
        allow_live_requests=True,
        operator=args.operator or "",
    )
    _print_json(report)
    return 0 if not report["failed_step_ids"] else 1


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(target, need_definition=True):
        if need_definition:
            target.add_argument("--file", default="")
            target.add_argument("--name", default="")
        target.add_argument("--project-id", default="")
        target.add_argument("--env-id", default="")
        target.add_argument("--account-alias", default="")

    validate = sub.add_parser("validate", help="Offline schema/secret validation.")
    add_common(validate)
    validate.set_defaults(handler=command_validate)

    imp = sub.add_parser("import", help="Save a definition into the project scope.")
    add_common(imp)
    imp.add_argument("--status", default="draft")
    imp.add_argument("--operator", default="")
    imp.set_defaults(handler=command_import)

    listing = sub.add_parser("list", help="List saved definitions.")
    listing.add_argument("--project-id", default="")
    listing.add_argument("--env-id", default="")
    listing.set_defaults(handler=command_list)

    show = sub.add_parser("show", help="Show one saved definition.")
    show.add_argument("--name", required=True)
    show.add_argument("--project-id", required=True)
    show.add_argument("--env-id", default="")
    show.add_argument("--canonical", action="store_true", help="Emit canonical JSON text.")
    show.set_defaults(handler=command_show)

    dry = sub.add_parser("dry-run", help="Resolve bindings and refs in memory; no request.")
    add_common(dry)
    dry.add_argument("--sources-json", default="", help="Local JSON: response_ref -> captured response.")
    dry.add_argument("--bind-from-db", action="store_true", help="Bind steps to imported raw_data assets.")
    dry.add_argument("--fail-step", action="append", default=[], help="Simulate an upstream step failure.")
    dry.add_argument("--allow-blocked", action="store_true", help="Exit 0 even when steps are blocked.")
    dry.set_defaults(handler=command_dry_run)

    replay = sub.add_parser("replay", help="Execute the chain live (explicit confirmation required).")
    replay.add_argument("--name", required=True)
    replay.add_argument("--project-id", required=True)
    replay.add_argument("--env-id", default="")
    replay.add_argument("--account-alias", default="")
    replay.add_argument("--sources-json", default="")
    replay.add_argument("--bind-from-db", action="store_true")
    replay.add_argument("--auth-mode", default="account", choices=["account", "anonymous", "inherit"])
    replay.add_argument("--account-id", default="")
    replay.add_argument("--auth-provider-id", default="")
    replay.add_argument("--auth-context-ref", default="")
    replay.add_argument("--auth-profile-revision-id", default="")
    replay.add_argument("--auth-realm-revision-id", default="")
    replay.add_argument("--auth-adapter-version-id", default="")
    replay.add_argument("--operator", default="")
    replay.add_argument("--live", action="store_true")
    replay.add_argument("--i-understand-live-requests", action="store_true")
    replay.set_defaults(handler=command_replay)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in {"import", "list", "show", "replay"}:
        from apiAnalysis.main import _ensure_mongo_connection
        _ensure_mongo_connection()
    if args.command == "dry-run" and args.bind_from_db:
        from apiAnalysis.main import _ensure_mongo_connection
        _ensure_mongo_connection()
    try:
        return args.handler(args)
    except ChainDefinitionError as exc:
        print(json.dumps({"error": exc.__class__.__name__, "message": str(exc)}, ensure_ascii=False))
        return 1
    except Exception as exc:  # bounded, sanitized CLI failure report
        print(json.dumps({"error": exc.__class__.__name__, "message": str(exc)[:300]}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
