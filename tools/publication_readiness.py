#!/usr/bin/env python3
"""Split the pending change set into publishable and blocked files.

The public-data guard answers "is this tree publishable?".  This tool answers
the question that comes immediately before a commit: "which of my pending
changes may I stage right now, and which must stay out?".

It is a classifier, not a second guard.  It reuses the guard's own scanning
code so the two can never disagree, and it preserves the guard's discipline of
reporting only rule identifier, path and line -- never the matched value.

Nothing is staged, moved or rewritten.  The tool writes a NUL-separated
pathspec file that an operator can feed to `git add --pathspec-file-nul` after
reviewing the classification, which keeps staging explicit instead of relying
on a sweeping `git add -A`.

Usage:

    py -3.9 tools/publication_readiness.py
    py -3.9 tools/publication_readiness.py --write-clean-list out/clean.paths
    py -3.9 tools/publication_readiness.py --fail-on-flagged
"""

import argparse
import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from public_repo_guard import (  # noqa: E402
    GuardError,
    load_config,
    load_local_policy,
    repository_root,
    scan_blob,
    _run_git,
)


def changed_paths(repo_root):
    """Pending changes as Git would show them, including nested untracked files."""
    raw = _run_git(repo_root, ["status", "--porcelain", "-uall"])
    paths = []
    for line in raw.decode("utf-8", errors="surrogateescape").splitlines():
        if len(line) < 4:
            continue
        status, rest = line[:2], line[3:]
        if status.strip() == "D":
            continue
        if "->" in rest:
            rest = rest.split("->", 1)[1]
        paths.append(rest.strip().strip('"').replace("\\", "/"))
    return sorted(set(paths))


def classify(repo_root, paths, config, local_policy):
    clean, blocked = [], []
    for path in paths:
        file_path = repo_root / Path(path)
        if not file_path.is_file():
            continue
        findings = scan_blob(
            file_path.read_bytes(), path, config, scope="pending",
            local_policy=local_policy,
        )
        if findings:
            blocked.append((path, findings))
        else:
            clean.append(path)
    return clean, blocked


def write_pathspec_file(path, clean_paths):
    target = Path(path)
    if not target.is_absolute():
        target = Path.cwd() / target
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as handle:
        for item in clean_paths:
            handle.write(item.encode("utf-8"))
            handle.write(b"\0")
    return target


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=".public-data-guard.json")
    parser.add_argument(
        "--write-clean-list", metavar="PATH",
        help="write a NUL-separated pathspec file for git add --pathspec-file-nul",
    )
    parser.add_argument(
        "--fail-on-flagged", action="store_true",
        help="exit 1 when any pending file is blocked",
    )
    parser.add_argument("--quiet", action="store_true")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    repo_root = repository_root()
    config = load_config(repo_root, args.config)
    local_policy = load_local_policy(repo_root)

    paths = changed_paths(repo_root)
    clean, blocked = classify(repo_root, paths, config, local_policy)

    if not args.quiet:
        print("pending changes: {}".format(len(paths)))
        print("publishable:     {}".format(len(clean)))
        print("blocked:         {}".format(len(blocked)))

        if blocked:
            by_rule = collections.Counter(
                finding.rule for _, findings in blocked for finding in findings
            )
            print()
            print("blocked rules:")
            for rule, count in by_rule.most_common():
                print("  {:<24} {}".format(rule, count))

            print()
            print("blocked files:")
            for path, findings in blocked:
                rules = sorted({finding.rule for finding in findings})
                print("  {}:{}  {}".format(path, len(findings), ",".join(rules)))

        if clean and not blocked:
            print()
            print("every pending change is publishable")

    if args.write_clean_list:
        target = write_pathspec_file(args.write_clean_list, clean)
        if not args.quiet:
            print()
            print("clean pathspec written: {}".format(target))
            print(
                "review it, then stage explicitly with:\n"
                "  git add --pathspec-from-file={} --pathspec-file-nul".format(target)
            )

    return 1 if (args.fail_on_flagged and blocked) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (GuardError, OSError, ValueError) as exc:
        print("publication-readiness: error: {}".format(exc), file=sys.stderr)
        sys.exit(2)
