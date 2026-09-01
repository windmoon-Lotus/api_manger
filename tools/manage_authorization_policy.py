"""Manage immutable multi-principal authorization policies from the CLI."""
import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.authorization_policy import (
    activate_authorization_policy,
    add_authorization_policy_rule,
    clone_authorization_policy_version,
    create_authorization_policy_version,
    create_authorization_principal,
)


def _json_object(value, label):
    try:
        result = json.loads(value or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError("{} must be valid JSON".format(label)) from exc
    if not isinstance(result, dict):
        raise ValueError("{} must be a JSON object".format(label))
    return result


def build_parser():
    parser = argparse.ArgumentParser(
        description="Create principals and immutable authorization policy versions.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    principal = commands.add_parser("add-principal")
    principal.add_argument("--project-id", required=True)
    principal.add_argument("--env-id", required=True)
    principal.add_argument("--profile-id", required=True)
    principal.add_argument("--name", required=True)
    principal.add_argument("--role", default="")
    principal.add_argument("--rank", type=int, default=0)
    principal.add_argument("--scope", default="")
    principal.add_argument("--label", action="append", default=[])
    principal.add_argument("--attributes-json", default="{}")

    policy = commands.add_parser("create-policy")
    policy.add_argument("--project-id", required=True)
    policy.add_argument("--env-id", required=True)
    policy.add_argument("--name", required=True)
    policy.add_argument("--principal-id", action="append", required=True)
    policy.add_argument("--relation-id", action="append", required=True)
    policy.add_argument("--resource-family", default="")
    policy.add_argument("--action", default="read")
    policy.add_argument("--default-decision", choices=["allow", "deny", "review"], default="review")
    policy.add_argument("--same-principal-decision", choices=["allow", "deny", "review"], default="allow")
    policy.add_argument("--exclude-self", action="store_true")
    policy.add_argument("--case-budget", type=int, default=100)
    policy.add_argument("--request-budget-per-case", type=int, default=3)
    policy.add_argument("--operator", default="cli")

    rule = commands.add_parser("add-rule")
    rule.add_argument("policy_version_id")
    rule.add_argument("--priority", type=int, default=100)
    rule.add_argument("--subject-json", default="{}")
    rule.add_argument("--owner-json", default="{}")
    rule.add_argument("--scope-relation", choices=["any", "same", "different"], default="any")
    rule.add_argument("--resource-family", default="")
    rule.add_argument("--action", default="read")
    rule.add_argument("--expected-decision", choices=["allow", "deny", "review"], required=True)
    rule.add_argument("--reason-code", action="append", default=[])
    rule.add_argument("--description", default="")

    activate = commands.add_parser("activate")
    activate.add_argument("policy_version_id")

    clone = commands.add_parser("clone")
    clone.add_argument("policy_version_id")
    clone.add_argument("--operator", default="cli")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    _ensure_mongo_connection()
    if args.command == "add-principal":
        item = create_authorization_principal(
            project_id=args.project_id,
            env_id=args.env_id,
            profile_id=args.profile_id,
            name=args.name,
            role_key=args.role,
            privilege_rank=args.rank,
            scope_key=args.scope,
            labels=args.label,
            attributes=_json_object(args.attributes_json, "attributes-json"),
        )
        output = {"principal_id": item.principal_id, "name": item.name}
    elif args.command == "create-policy":
        item = create_authorization_policy_version(
            project_id=args.project_id,
            env_id=args.env_id,
            name=args.name,
            principal_ids=args.principal_id,
            relation_ids=args.relation_id,
            resource_family=args.resource_family,
            action=args.action,
            default_decision=args.default_decision,
            same_principal_decision=args.same_principal_decision,
            include_self=not args.exclude_self,
            case_budget=args.case_budget,
            request_budget_per_case=args.request_budget_per_case,
            created_by=args.operator,
        )
        output = {
            "policy_key": item.policy_key,
            "policy_version_id": item.policy_version_id,
            "version": item.version,
            "lifecycle": item.lifecycle,
        }
    elif args.command == "add-rule":
        item = add_authorization_policy_rule(
            args.policy_version_id,
            priority=args.priority,
            subject_selector=_json_object(args.subject_json, "subject-json"),
            owner_selector=_json_object(args.owner_json, "owner-json"),
            scope_relation=args.scope_relation,
            resource_family=args.resource_family,
            action=args.action,
            expected_decision=args.expected_decision,
            reason_codes=args.reason_code,
            description=args.description,
        )
        output = {"rule_id": item.rule_id, "policy_version_id": item.policy_version_id}
    elif args.command == "activate":
        item = activate_authorization_policy(args.policy_version_id)
        output = {
            "policy_key": item.policy_key,
            "policy_version_id": item.policy_version_id,
            "version": item.version,
            "lifecycle": item.lifecycle,
            "principal_count": len(item.principal_snapshots or []),
            "relation_count": len(item.relation_snapshots or []),
        }
    else:
        item = clone_authorization_policy_version(
            args.policy_version_id, created_by=args.operator,
        )
        output = {
            "policy_key": item.policy_key,
            "policy_version_id": item.policy_version_id,
            "version": item.version,
            "lifecycle": item.lifecycle,
        }
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
