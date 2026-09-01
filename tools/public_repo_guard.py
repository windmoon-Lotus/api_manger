#!/usr/bin/env python3
"""Fail closed when private test data is about to enter the public repository.

The guard deliberately reports only a rule identifier, path and line number.
It never prints the matched value.  It uses only the Python standard library so
the local hook and CI can run before project dependencies are installed.
"""

import argparse
import fnmatch
import ipaddress
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


DEFAULT_CONFIG = ".public-data-guard.json"
LOCAL_CONFIG_ENV = "PUBLIC_DATA_GUARD_LOCAL_CONFIG"
LOCAL_CONFIG_DEFAULT = ".git/public-data-guard.local.json"

TEXT_EXTENSIONS = {
    ".bat", ".cfg", ".conf", ".css", ".csv", ".env", ".gitignore",
    ".gitattributes", ".html", ".ini", ".js", ".json", ".md", ".mmd",
    ".ps1", ".py", ".rst", ".sh", ".sql", ".toml", ".ts", ".txt",
    ".xml", ".yaml", ".yml",
}

PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)

IPV4_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
URL_RE = re.compile(r"https?://([^/\s\"'<>?#&]+)", re.IGNORECASE)
QUOTED_HOST_RE = re.compile(
    r"[\"']([a-z0-9](?:[a-z0-9-]{0,62}\.)+[a-z]{2,24})[\"']",
    re.IGNORECASE,
)
WINDOWS_PATH_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:\\[^\s\"'<>]+")
USER_HOME_PATH_RE = re.compile(r"/(?:Users|home)/[^/\s\"'<>]+/", re.IGNORECASE)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
KNOWN_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{24,}|sk-[A-Za-z0-9_-]{20,})(?![A-Za-z0-9])"
)
CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret(?:_key)?|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|session[_-]?token)\b\s*[:=]\s*"
    r"[\"']([^\"']{6,})[\"']"
)
AUTH_HEADER_RE = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key)\b"
    r"\s*[:=]\s*[\"']([^\"']{12,})[\"']"
)
URL_CREDENTIAL_RE = re.compile(r"https?://[^/\s:@]+:[^/\s@]+@", re.IGNORECASE)

SAFE_SECRET_MARKERS = (
    "<", "${", "{{", "changeme", "dummy", "example", "fake", "fixture",
    "not-a-real", "placeholder", "redacted", "sample", "test", "xxx",
)

HOST_TLDS = {
    "app", "cloud", "cn", "co", "com", "corp", "dev", "internal", "io",
    "local", "net", "org", "test",
}


@dataclass(frozen=True)
class Finding:
    scope: str
    path: str
    line: int
    rule: str
    message: str


class GuardError(RuntimeError):
    pass


def _run_git(repo_root, arguments, input_bytes=None):
    process = subprocess.run(
        ["git", "-c", "core.quotepath=false"] + list(arguments),
        cwd=str(repo_root),
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise GuardError("git command failed: {}".format(detail or arguments))
    return process.stdout


def repository_root(start=None):
    start = Path(start or Path.cwd()).resolve()
    output = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=str(start),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if output.returncode != 0:
        raise GuardError("public-data guard must run inside a Git repository")
    return Path(output.stdout.decode("utf-8", errors="strict").strip()).resolve()


def load_config(repo_root, config_path=None):
    path = Path(config_path) if config_path else repo_root / DEFAULT_CONFIG
    if not path.is_absolute():
        path = repo_root / path
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise GuardError("unsupported public-data guard schema")
    return data


def load_local_policy(repo_root):
    configured = str(os.getenv(LOCAL_CONFIG_ENV) or "").strip()
    path = Path(configured).expanduser() if configured else repo_root / LOCAL_CONFIG_DEFAULT
    if not path.is_absolute():
        path = repo_root / path
    if not path.exists():
        return {"deny_terms": [], "deny_host_suffixes": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        "deny_terms": [str(item).lower() for item in data.get("deny_terms", []) if str(item).strip()],
        "deny_host_suffixes": [
            str(item).lower().lstrip(".")
            for item in data.get("deny_host_suffixes", [])
            if str(item).strip()
        ],
    }


def _null_paths(raw):
    return [
        value.decode("utf-8", errors="strict").replace("\\", "/")
        for value in raw.split(b"\0")
        if value
    ]


def staged_paths(repo_root):
    return _null_paths(_run_git(
        repo_root,
        ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
    ))


def tracked_paths(repo_root):
    return _null_paths(_run_git(repo_root, ["ls-files", "-z"]))


def worktree_paths(repo_root):
    return _null_paths(_run_git(repo_root, ["ls-files", "-co", "--exclude-standard", "-z"]))


def _matches_glob(path, pattern):
    lowered = path.lower()
    pattern = str(pattern).replace("\\", "/").lower()
    return fnmatch.fnmatch(lowered, pattern) or fnmatch.fnmatch(Path(lowered).name, pattern)


def _is_exempt(config, path, rule):
    for pattern, rules in config.get("content_rule_exemptions", {}).items():
        if _matches_glob(path, pattern) and ("*" in rules or rule in rules):
            return True
    return False


def scan_path(path, config, scope="worktree", local_policy=None):
    local_policy = local_policy or {"deny_terms": [], "deny_host_suffixes": []}
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    lowered = normalized.lower()
    findings = []
    components = [part.lower() for part in Path(normalized).parts]
    forbidden_components = {
        str(item).lower() for item in config.get("forbidden_path_components", [])
    }
    matched_component = next((item for item in components if item in forbidden_components), None)
    if matched_component:
        findings.append(Finding(
            scope, normalized, 0, "forbidden-path",
            "path contains a private or generated-data directory",
        ))
    if any(_matches_glob(normalized, pattern) for pattern in config.get("forbidden_path_globs", [])):
        findings.append(Finding(
            scope, normalized, 0, "forbidden-file-type",
            "file type or local/private naming is not publishable",
        ))
    if any(term in lowered for term in local_policy.get("deny_terms", [])):
        findings.append(Finding(
            scope, normalized, 0, "local-deny-term",
            "path contains a locally configured engagement identifier",
        ))
    return findings


def _allowed_host(host, config):
    host = host.strip().strip("[]").rstrip(".").lower()
    if not host or any(char in host for char in "{}$%*"):
        return True
    if host.startswith("xxx.") or host.endswith(".xxx"):
        return True
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return True
    if host.endswith((".test", ".example", ".invalid", ".localhost")):
        return True
    if host in {"example.com", "example.net", "example.org"}:
        return True
    if host.endswith((".example.com", ".example.net", ".example.org")):
        return True
    for allowed in config.get("allowed_hosts", []):
        allowed = str(allowed).lower().rstrip(".")
        if allowed.startswith("*.") and host.endswith(allowed[1:]):
            return True
        if host == allowed:
            return True
    return False


def _host_from_url_match(value):
    host_port = value.rsplit("@", 1)[-1]
    if host_port.startswith("["):
        return host_port.split("]", 1)[0].lstrip("[")
    return host_port.split(":", 1)[0]


def _is_private_ipv4(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in PRIVATE_NETWORKS)


def _looks_placeholder_secret(value):
    lowered = value.strip().lower()
    if lowered in {"admin123", "normal123"}:
        return True
    return any(marker in lowered for marker in SAFE_SECRET_MARKERS)


def _text_rule(config, path, rule, line_number, scope, message):
    if _is_exempt(config, path, rule):
        return None
    return Finding(scope, path, line_number, rule, message)


def scan_text(text, path, config, scope="worktree", local_policy=None):
    local_policy = local_policy or {"deny_terms": [], "deny_host_suffixes": []}
    findings = []
    for line_number, line in enumerate(text.splitlines(), 1):
        lowered_line = line.lower()

        if PRIVATE_KEY_RE.search(line):
            finding = _text_rule(config, path, "private-key", line_number, scope, "private key material is not publishable")
            if finding:
                findings.append(finding)
        if JWT_RE.search(line) or KNOWN_TOKEN_RE.search(line):
            finding = _text_rule(config, path, "token-format", line_number, scope, "credential-like token format detected")
            if finding:
                findings.append(finding)
        if URL_CREDENTIAL_RE.search(line):
            finding = _text_rule(config, path, "url-credential", line_number, scope, "URL contains embedded credentials")
            if finding:
                findings.append(finding)

        for match in CREDENTIAL_ASSIGNMENT_RE.finditer(line):
            if not _looks_placeholder_secret(match.group(2)):
                finding = _text_rule(config, path, "credential-literal", line_number, scope, "concrete credential assignment detected")
                if finding:
                    findings.append(finding)
                break
        for match in AUTH_HEADER_RE.finditer(line):
            if not _looks_placeholder_secret(match.group(2)):
                finding = _text_rule(config, path, "auth-header-literal", line_number, scope, "concrete authentication or cookie header detected")
                if finding:
                    findings.append(finding)
                break

        if WINDOWS_PATH_RE.search(line) or USER_HOME_PATH_RE.search(line):
            finding = _text_rule(config, path, "absolute-local-path", line_number, scope, "developer-specific absolute path detected")
            if finding:
                findings.append(finding)

        for match in IPV4_RE.finditer(line):
            value = match.group(0)
            if _is_private_ipv4(value):
                finding = _text_rule(config, path, "private-network", line_number, scope, "RFC1918 address detected")
                if finding:
                    findings.append(finding)
                break

        hosts = []
        for match in URL_RE.finditer(line):
            hosts.append(_host_from_url_match(match.group(1)))
        for match in QUOTED_HOST_RE.finditer(line):
            candidate = match.group(1)
            if candidate.rsplit(".", 1)[-1].lower() in HOST_TLDS:
                hosts.append(candidate)
        for host in hosts:
            normalized_host = host.lower().rstrip(".")
            if any(
                normalized_host == suffix or normalized_host.endswith("." + suffix)
                for suffix in local_policy.get("deny_host_suffixes", [])
            ):
                finding = _text_rule(config, path, "local-deny-host", line_number, scope, "host matches a locally configured private suffix")
                if finding:
                    findings.append(finding)
                continue
            if not _allowed_host(normalized_host, config):
                finding = _text_rule(config, path, "unknown-literal-host", line_number, scope, "literal host is not in the reviewed public allowlist")
                if finding:
                    findings.append(finding)

        if any(term in lowered_line for term in local_policy.get("deny_terms", [])):
            finding = _text_rule(config, path, "local-deny-term", line_number, scope, "content contains a locally configured engagement identifier")
            if finding:
                findings.append(finding)

    return findings


def _probably_binary(data, path):
    if b"\0" in data[:8192]:
        return True
    if Path(path).suffix.lower() in TEXT_EXTENSIONS:
        return False
    try:
        data[:65536].decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


def scan_blob(data, path, config, scope="worktree", local_policy=None):
    findings = scan_path(path, config, scope=scope, local_policy=local_policy)
    max_bytes = int(config.get("max_text_file_bytes", 2097152))
    allowed_binary = any(
        _matches_glob(path, pattern) for pattern in config.get("allowed_binary_globs", [])
    )
    if len(data) > max_bytes and not allowed_binary:
        findings.append(Finding(
            scope, path, 0, "oversized-file",
            "file exceeds the public text-size limit and requires provenance review",
        ))
        return findings
    if _probably_binary(data, path):
        if not allowed_binary:
            findings.append(Finding(
                scope, path, 0, "unreviewed-binary",
                "binary artifact is outside an approved public asset directory",
            ))
        return findings
    text = data.decode("utf-8-sig", errors="replace")
    findings.extend(scan_text(
        text, path, config, scope=scope, local_policy=local_policy,
    ))
    return findings


def _worktree_blob(repo_root, path):
    file_path = repo_root / Path(path)
    if not file_path.is_file():
        return None
    return file_path.read_bytes()


def _staged_blob(repo_root, path):
    process = subprocess.run(
        ["git", "show", ":{}".format(path)],
        cwd=str(repo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        return None
    return process.stdout


def scan_named_paths(repo_root, paths, config, scope, local_policy, staged=False):
    findings = []
    for path in sorted(set(paths)):
        data = _staged_blob(repo_root, path) if staged else _worktree_blob(repo_root, path)
        if data is None:
            continue
        findings.extend(scan_blob(
            data, path, config, scope=scope, local_policy=local_policy,
        ))
    return findings


def history_entries(repo_root):
    commits = _run_git(repo_root, ["rev-list", "--all"]).splitlines()
    seen = set()
    for raw_commit in commits:
        commit = raw_commit.decode("ascii")
        raw_tree = _run_git(repo_root, ["ls-tree", "-r", "-z", commit])
        for entry in raw_tree.split(b"\0"):
            if not entry or b"\t" not in entry:
                continue
            meta, raw_path = entry.split(b"\t", 1)
            fields = meta.split()
            if len(fields) != 3 or fields[1] != b"blob":
                continue
            blob_id = fields[2].decode("ascii")
            path = raw_path.decode("utf-8", errors="strict").replace("\\", "/")
            key = (blob_id, path)
            if key in seen:
                continue
            seen.add(key)
            yield commit, blob_id, path


def scan_history(repo_root, config, local_policy):
    findings = []
    for commit, blob_id, path in history_entries(repo_root):
        data = _run_git(repo_root, ["cat-file", "blob", blob_id])
        findings.extend(scan_blob(
            data,
            path,
            config,
            scope="history@{}".format(commit[:12]),
            local_policy=local_policy,
        ))
    return findings


def _deduplicate(findings):
    return sorted(
        set(findings),
        key=lambda item: (item.scope, item.path, item.line, item.rule),
    )


def _write_json_report(path, modes, findings):
    payload = {
        "document_type": "api-manager.public-data-guard",
        "schema_version": 1,
        "modes": modes,
        "ok": not findings,
        "finding_count": len(findings),
        "findings": [asdict(item) for item in findings],
    }
    Path(path).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true", help="scan the staged Git index")
    parser.add_argument("--tracked", action="store_true", help="scan all currently tracked files")
    parser.add_argument("--worktree", action="store_true", help="scan tracked and unignored worktree files")
    parser.add_argument("--history", action="store_true", help="scan every reachable historical blob")
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--json-report")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--max-findings", type=int, default=200)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    repo_root = repository_root()
    config = load_config(repo_root, args.config)
    local_policy = load_local_policy(repo_root)
    modes = []
    findings = []

    if not any((args.staged, args.tracked, args.worktree, args.history)):
        args.staged = True
    if args.staged:
        modes.append("staged")
        findings.extend(scan_named_paths(
            repo_root, staged_paths(repo_root), config, "staged", local_policy, staged=True,
        ))
    if args.tracked:
        modes.append("tracked")
        findings.extend(scan_named_paths(
            repo_root, tracked_paths(repo_root), config, "tracked", local_policy,
        ))
    if args.worktree:
        modes.append("worktree")
        findings.extend(scan_named_paths(
            repo_root, worktree_paths(repo_root), config, "worktree", local_policy,
        ))
    if args.history:
        modes.append("history")
        findings.extend(scan_history(repo_root, config, local_policy))

    findings = _deduplicate(findings)
    if args.json_report:
        _write_json_report(args.json_report, modes, findings)

    if findings and not args.quiet:
        for finding in findings[:max(1, args.max_findings)]:
            location = "{}:{}".format(finding.path, finding.line) if finding.line else finding.path
            print("[BLOCK] {} {} {} - {}".format(
                finding.scope, finding.rule, location, finding.message,
            ))
        if len(findings) > args.max_findings:
            print("[BLOCK] {} additional findings omitted".format(len(findings) - args.max_findings))
    if not args.quiet:
        print("public-data-guard: modes={} findings={}".format(",".join(modes), len(findings)))
    return 1 if findings else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (GuardError, OSError, ValueError, json.JSONDecodeError) as exc:
        print("public-data-guard: error: {}".format(exc), file=sys.stderr)
        sys.exit(2)
