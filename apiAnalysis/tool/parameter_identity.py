"""Normalize flattened parameter occurrences into reusable parameter identities."""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, Iterable, Mapping

from apiAnalysis.tool.parameter_dependency import canonical_name as dependency_canonical_name


NORMALIZATION_VERSION = "parameter-identity-v1"


def normalized_leaf(value: Any) -> str:
    """Return a readable leaf while removing JSON path/array syntax."""
    text = str(value or "").strip().split(".")[-1]
    text = re.sub(r"\[[^\]]*\]", "", text)
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    text = text.replace("-", "_").strip("_").lower()
    text = re.sub(r"[^a-z0-9_]+", "", text)
    return re.sub(r"_+", "_", text)


def parameter_identity(parameter: Any, canonical_hint: Any = "") -> str:
    """Return the conservative alias identity used for aggregation."""
    raw_leaf = normalized_leaf(parameter)
    hinted_leaf = normalized_leaf(canonical_hint)
    candidate = raw_leaf or hinted_leaf
    identity = dependency_canonical_name(candidate)
    if not identity and hinted_leaf:
        identity = dependency_canonical_name(hinted_leaf)
    return identity or candidate or hinted_leaf


def occurrence_alias(parameter: Any, canonical_hint: Any = "") -> str:
    """Return the human-readable alias contributed by one occurrence."""
    return normalized_leaf(parameter) or normalized_leaf(canonical_hint)


def preferred_parameter_name(identity: str, alias_counts: Mapping[str, int]) -> str:
    """Choose a stable display name without losing the internal identity."""
    counts = Counter({str(key): int(value or 0) for key, value in alias_counts.items() if key})
    if not counts:
        return str(identity or "")
    compatible = [name for name in counts if parameter_identity(name) == identity]
    compatible = compatible or list(counts)
    return max(
        compatible,
        key=lambda name: (
            counts[name],
            1 if "_" in name else 0,
            1 if name == identity else 0,
            -len(name),
            name,
        ),
    )


def aggregate_occurrences(rows: Iterable[Any]) -> Dict[str, Dict[str, Any]]:
    """Group request/response documents by normalized identity.

    This helper is deliberately storage-agnostic so import, priority and test
    code can use the same behavior.
    """
    groups: Dict[str, Dict[str, Any]] = {}
    for row in rows or []:
        parameter = str(getattr(row, "parameter", "") or "")
        hint = str(getattr(row, "canonical_name", "") or "")
        identity = parameter_identity(parameter, hint)
        if not identity:
            continue
        group = groups.setdefault(identity, {
            "identity": identity,
            "rows": [],
            "alias_counts": Counter(),
            "raw_paths": set(),
        })
        group["rows"].append(row)
        alias = occurrence_alias(parameter, hint)
        if alias:
            group["alias_counts"][alias] += 1
        if parameter:
            group["raw_paths"].add(parameter)
    for group in groups.values():
        group["parameter"] = preferred_parameter_name(
            group["identity"], group["alias_counts"],
        )
    return groups
