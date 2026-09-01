"""Fail-closed, offline-only P0 protocol for typed analysis rules."""
from __future__ import annotations

import hashlib
import itertools
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple, Type, Union


RULE_SCHEMA_VERSION = "rule.v1"
_VERSIONED_NAME = re.compile(r"^[a-z][a-z0-9_.-]*\.v[1-9][0-9]*$")
_RULE_ID = re.compile(r"^[a-z][a-z0-9_.-]*$")
_INPUT_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class RuleProtocolError(ValueError):
    pass


class RuleBudgetExceeded(RuleProtocolError):
    pass


class UnknownPredicate(RuleProtocolError):
    pass


class UnknownOutputAdapter(RuleProtocolError):
    pass


def _require_exact_keys(value: Mapping[str, Any], allowed: Sequence[str], required: Sequence[str], label: str) -> None:
    if not isinstance(value, Mapping):
        raise RuleProtocolError("{} must be an object".format(label))
    unknown = sorted(set(value) - set(allowed))
    missing = sorted(set(required) - set(value))
    if unknown:
        raise RuleProtocolError("{} contains unknown fields: {}".format(label, ", ".join(unknown)))
    if missing:
        raise RuleProtocolError("{} is missing fields: {}".format(label, ", ".join(missing)))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class Fact:
    fact_id: str
    project_id: str
    env_id: str

    def __post_init__(self) -> None:
        if not str(self.fact_id or "").strip():
            raise ValueError("fact_id is required")


@dataclass(frozen=True)
class EndpointFact(Fact):
    pathid: int
    method: str
    path_template: str
    action: str = ""
    classification_source: str = "none"
    media_type: str = ""
    has_request_body: bool = False
    response_status_codes: Tuple[int, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        if int(self.pathid) < 0 or not str(self.method or "").strip() or not str(self.path_template or "").strip():
            raise ValueError("endpoint pathid, method and path_template are required")
        if self.classification_source not in {"none", "machine", "manual"}:
            raise ValueError("classification_source is invalid")


@dataclass(frozen=True)
class LocatorFact:
    version: int
    direction: str
    position: str
    kind: str
    schema_path: str
    canonical_name: str
    token_kinds: Tuple[str, ...] = ()
    contains_dynamic_property: bool = False

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "LocatorFact":
        if not isinstance(value, Mapping):
            raise ValueError("typed locator is required")
        tokens = tuple(str(item.get("kind") or "") for item in (value.get("tokens") or ()))
        return cls(
            version=int(value.get("version") or 0),
            direction=str(value.get("direction") or ""),
            position=str(value.get("position") or ""),
            kind=str(value.get("kind") or ""),
            schema_path=str(value.get("schema_path") or ""),
            canonical_name=str(value.get("canonical_name") or ""),
            token_kinds=tokens,
            contains_dynamic_property=any(bool(item.get("dynamic")) for item in (value.get("tokens") or ())),
        )


@dataclass(frozen=True)
class ObservationSummaryFact(Fact):
    source_kind: str
    status_class: str = "unknown"
    value_digests: Tuple[str, ...] = ()
    unique_value_count: int = 0
    observed_value_count: int = 0
    min_length: int = 0
    max_length: int = 0
    bounded: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()
        if any(not _DIGEST.fullmatch(value) for value in self.value_digests):
            raise ValueError("observation values must be sha256 digests")
        if len(self.value_digests) > 100:
            raise ValueError("observation digest budget exceeded")


@dataclass(frozen=True)
class ParameterOccurrenceFact(Fact):
    endpoint_ref: str
    pathid: int
    direction: str
    canonical_name: str
    parameter_type: str
    required: bool
    locator: LocatorFact
    category: str
    observation: ObservationSummaryFact
    principal_id: str = ""
    profile_revision_id: str = ""
    scope_key: str = ""

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.direction not in {"request", "response"}:
            raise ValueError("parameter direction is invalid")
        if not self.canonical_name or not self.endpoint_ref:
            raise ValueError("parameter canonical_name and endpoint_ref are required")
        if self.locator.direction != self.direction:
            raise ValueError("locator direction does not match parameter direction")
        if (self.observation.project_id, self.observation.env_id) != (self.project_id, self.env_id):
            raise ValueError("observation context does not match parameter context")


@dataclass(frozen=True)
class PrincipalContextFact(Fact):
    principal_id: str
    profile_revision_id: str
    role_key: str = ""
    privilege_rank: int = 0
    scope_key: str = ""
    labels: Tuple[str, ...] = ()


@dataclass(frozen=True)
class RelationFact(Fact):
    relation_ref: str
    producer_ref: str
    consumer_ref: str
    schema_fingerprint: str = ""
    manual_decision: str = ""
    verified: bool = False


@dataclass(frozen=True)
class ExecutionCapabilityFact(Fact):
    endpoint_ref: str
    operation_kind: str
    fixture_ready: bool
    auth_ready: bool
    readback_ready: bool = False
    cleanup_ready: bool = False


AnyFact = Union[
    EndpointFact, ParameterOccurrenceFact, ObservationSummaryFact,
    PrincipalContextFact, RelationFact, ExecutionCapabilityFact,
]


def summarize_values(*, fact_id: str, project_id: str, env_id: str, source_kind: str,
                     values: Iterable[Any], status_class: str = "unknown",
                     max_digests: int = 100) -> ObservationSummaryFact:
    if not 1 <= int(max_digests) <= 100:
        raise ValueError("max_digests must be between 1 and 100")
    canonical_values = []
    lengths = []
    observed_count = 0
    for value in values or ():
        observed_count += 1
        encoded = _canonical_json(value)
        canonical_values.append(encoded)
        lengths.append(len(encoded.encode("utf-8")))
    unique_values = sorted(set(canonical_values))
    digests = tuple(
        hashlib.sha256(value.encode("utf-8")).hexdigest()
        for value in unique_values[:max_digests]
    )
    return ObservationSummaryFact(
        fact_id=fact_id,
        project_id=project_id,
        env_id=env_id,
        source_kind=source_kind,
        status_class=status_class,
        value_digests=digests,
        unique_value_count=len(unique_values),
        observed_value_count=observed_count,
        min_length=min(lengths) if lengths else 0,
        max_length=max(lengths) if lengths else 0,
        bounded=len(unique_values) > max_digests,
    )


@dataclass(frozen=True)
class PredicateCall:
    name: str
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScoreFeature:
    predicate: PredicateCall
    weight: float


@dataclass(frozen=True)
class RuleScope:
    same_project: bool = False
    same_environment: bool = False
    principal_relation: str = "any"


@dataclass(frozen=True)
class RuleSafety:
    network: str
    mutation: str
    max_matches: int


@dataclass(frozen=True)
class EmitSpec:
    adapter: str
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleSpec:
    schema_version: str
    rule_id: str
    version: int
    kind: str
    enabled: bool
    scope: RuleScope
    inputs: Tuple[str, ...]
    predicates: Tuple[PredicateCall, ...]
    score_base: float
    score_features: Tuple[ScoreFeature, ...]
    emit: EmitSpec
    safety: RuleSafety

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RuleSpec":
        _require_exact_keys(
            value,
            ("schema_version", "rule_id", "version", "kind", "enabled", "scope", "inputs",
             "predicates", "score", "emit", "safety"),
            ("schema_version", "rule_id", "version", "kind", "enabled", "scope", "inputs",
             "predicates", "score", "emit", "safety"),
            "RuleSpec",
        )
        if value["schema_version"] != RULE_SCHEMA_VERSION:
            raise RuleProtocolError("unsupported RuleSpec schema_version")
        if not _RULE_ID.fullmatch(str(value["rule_id"] or "")):
            raise RuleProtocolError("rule_id must be a stable name")
        if type(value["version"]) is not int or value["version"] < 1:
            raise RuleProtocolError("RuleSpec version must be a positive integer")
        if value["kind"] != "offline_inference":
            raise RuleProtocolError("P0 only supports offline_inference rules")
        if type(value["enabled"]) is not bool:
            raise RuleProtocolError("RuleSpec enabled must be boolean")

        scope_value = value["scope"]
        _require_exact_keys(scope_value, ("same_project", "same_environment", "principal_relation"), (), "scope")
        same_project = scope_value.get("same_project", False)
        same_environment = scope_value.get("same_environment", False)
        if type(same_project) is not bool or type(same_environment) is not bool:
            raise RuleProtocolError("scope flags must be boolean")
        principal_relation = str(scope_value.get("principal_relation") or "any")
        if principal_relation not in {
            "any", "same_principal", "different_principal", "same_profile_revision",
            "same_scope", "different_scope",
        }:
            raise RuleProtocolError("scope principal_relation is unsupported")

        raw_inputs = value["inputs"]
        if not isinstance(raw_inputs, list) or not raw_inputs or len(set(raw_inputs)) != len(raw_inputs):
            raise RuleProtocolError("inputs must be a non-empty unique list")
        if any(not _INPUT_NAME.fullmatch(str(item or "")) for item in raw_inputs):
            raise RuleProtocolError("inputs contain an invalid name")

        if not isinstance(value["predicates"], list):
            raise RuleProtocolError("predicates must be a list")
        predicates = tuple(cls._parse_predicate(item, "predicate") for item in value["predicates"])
        score_value = value["score"]
        _require_exact_keys(score_value, ("base", "features"), ("base", "features"), "score")
        base = score_value["base"]
        if type(base) not in {int, float} or not 0.0 <= float(base) <= 1.0:
            raise RuleProtocolError("score base must be between 0 and 1")
        features = []
        if not isinstance(score_value["features"], list):
            raise RuleProtocolError("score features must be a list")
        for item in score_value["features"]:
            _require_exact_keys(item, ("predicate", "args", "weight"), ("predicate", "weight"), "score feature")
            weight = item["weight"]
            if type(weight) not in {int, float} or not -1.0 <= float(weight) <= 1.0:
                raise RuleProtocolError("score feature weight must be between -1 and 1")
            predicate_name = str(item["predicate"] or "")
            if not _VERSIONED_NAME.fullmatch(predicate_name):
                raise RuleProtocolError("score predicate name must be versioned")
            features.append(ScoreFeature(
                predicate=PredicateCall(predicate_name, dict(item.get("args") or {})),
                weight=float(weight),
            ))

        emit_value = value["emit"]
        _require_exact_keys(emit_value, ("adapter", "args"), ("adapter",), "emit")
        adapter = str(emit_value["adapter"] or "")
        if not _VERSIONED_NAME.fullmatch(adapter):
            raise RuleProtocolError("emit adapter must be versioned")

        safety_value = value["safety"]
        _require_exact_keys(safety_value, ("network", "mutation", "max_matches"),
                            ("network", "mutation", "max_matches"), "safety")
        if safety_value["network"] != "forbidden" or safety_value["mutation"] != "forbidden":
            raise RuleProtocolError("P0 rules must forbid network and mutation")
        max_matches = safety_value["max_matches"]
        if type(max_matches) is not int or not 1 <= max_matches <= 100000:
            raise RuleProtocolError("safety.max_matches is out of bounds")

        return cls(
            schema_version=RULE_SCHEMA_VERSION,
            rule_id=str(value["rule_id"]),
            version=int(value["version"]),
            kind="offline_inference",
            enabled=bool(value["enabled"]),
            scope=RuleScope(same_project, same_environment, principal_relation),
            inputs=tuple(str(item) for item in raw_inputs),
            predicates=predicates,
            score_base=float(base),
            score_features=tuple(features),
            emit=EmitSpec(adapter, dict(emit_value.get("args") or {})),
            safety=RuleSafety("forbidden", "forbidden", max_matches),
        )

    @staticmethod
    def _parse_predicate(value: Mapping[str, Any], label: str) -> PredicateCall:
        _require_exact_keys(value, ("name", "args"), ("name",), label)
        name = str(value["name"] or "")
        if not _VERSIONED_NAME.fullmatch(name):
            raise RuleProtocolError("predicate name must be versioned")
        args = value.get("args") or {}
        if not isinstance(args, Mapping):
            raise RuleProtocolError("predicate args must be an object")
        return PredicateCall(name, dict(args))

    @classmethod
    def from_json(cls, value: str) -> "RuleSpec":
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise RuleProtocolError("RuleSpec is not valid JSON") from exc
        return cls.from_mapping(parsed)

    def canonical_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self.to_mapping()).encode("utf-8")).hexdigest()

    def to_mapping(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "rule_id": self.rule_id,
            "version": self.version,
            "kind": self.kind,
            "enabled": self.enabled,
            "scope": {
                "same_project": self.scope.same_project,
                "same_environment": self.scope.same_environment,
                "principal_relation": self.scope.principal_relation,
            },
            "inputs": list(self.inputs),
            "predicates": [
                {"name": item.name, **({"args": dict(item.args)} if item.args else {})}
                for item in self.predicates
            ],
            "score": {
                "base": self.score_base,
                "features": [
                    {"predicate": item.predicate.name, "weight": item.weight,
                     **({"args": dict(item.predicate.args)} if item.predicate.args else {})}
                    for item in self.score_features
                ],
            },
            "emit": {"adapter": self.emit.adapter, **({"args": dict(self.emit.args)} if self.emit.args else {})},
            "safety": {
                "network": self.safety.network,
                "mutation": self.safety.mutation,
                "max_matches": self.safety.max_matches,
            },
        }


@dataclass(frozen=True)
class PredicateResult:
    matched: bool
    value: float
    reason_codes: Tuple[str, ...]


ArgumentValidator = Callable[[Mapping[str, Any]], None]
PredicateEvaluator = Callable[[Mapping[str, Fact], Mapping[str, Any]], PredicateResult]


@dataclass(frozen=True)
class PredicateDefinition:
    name: str
    required_inputs: Mapping[str, Type[Fact]]
    validate_args: ArgumentValidator
    evaluate: PredicateEvaluator


class PredicateRegistry:
    def __init__(self) -> None:
        self._items: Dict[str, PredicateDefinition] = {}

    def register(self, definition: PredicateDefinition) -> None:
        if not _VERSIONED_NAME.fullmatch(definition.name):
            raise RuleProtocolError("predicate name must be versioned")
        if definition.name in self._items:
            raise RuleProtocolError("duplicate predicate: {}".format(definition.name))
        self._items[definition.name] = definition

    def resolve(self, name: str) -> PredicateDefinition:
        try:
            return self._items[name]
        except KeyError as exc:
            raise UnknownPredicate("predicate is not registered: {}".format(name)) from exc


@dataclass(frozen=True)
class EndpointClassificationCandidate:
    endpoint_ref: str
    proposed_action: str
    legacy_action: str
    confidence: float
    reason_codes: Tuple[str, ...]
    score_contributions: Tuple[Tuple[str, str, float], ...]
    existing_action: str
    apply_allowed: bool
    dry_run: bool = True


@dataclass(frozen=True)
class ParameterRelationCandidate:
    producer_ref: str
    consumer_ref: str
    relation: str
    confidence: float
    reason_codes: Tuple[str, ...]
    verified: bool = False
    write_disposition: str = "create_only"
    dry_run: bool = True


TypedOutput = Union[EndpointClassificationCandidate, ParameterRelationCandidate]
OutputEmitter = Callable[[Mapping[str, Fact], RuleSpec, float, Tuple[str, ...],
                          Tuple["ScoreContribution", ...]], TypedOutput]


@dataclass(frozen=True)
class OutputAdapterDefinition:
    name: str
    required_inputs: Mapping[str, Type[Fact]]
    validate_args: ArgumentValidator
    emit: OutputEmitter


class OutputAdapterRegistry:
    def __init__(self) -> None:
        self._items: Dict[str, OutputAdapterDefinition] = {}

    def register(self, definition: OutputAdapterDefinition) -> None:
        if not _VERSIONED_NAME.fullmatch(definition.name):
            raise RuleProtocolError("output adapter name must be versioned")
        if definition.name in self._items:
            raise RuleProtocolError("duplicate output adapter: {}".format(definition.name))
        self._items[definition.name] = definition

    def resolve(self, name: str) -> OutputAdapterDefinition:
        try:
            return self._items[name]
        except KeyError as exc:
            raise UnknownOutputAdapter("output adapter is not registered: {}".format(name)) from exc


@dataclass(frozen=True)
class ScoreContribution:
    predicate: str
    value: float
    weight: float
    contribution: float
    reason_codes: Tuple[str, ...]


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    rule_version: int
    rule_sha256: str
    fact_refs: Tuple[Tuple[str, str], ...]
    score: float
    reason_codes: Tuple[str, ...]
    score_contributions: Tuple[ScoreContribution, ...]
    output: TypedOutput


@dataclass(frozen=True)
class EvaluationReport:
    rule_id: str
    rule_version: int
    evaluated_combinations: int
    matches: Tuple[RuleMatch, ...]
    rejection_counts: Tuple[Tuple[str, int], ...]


class OfflineRuleEngine:
    def __init__(self, predicates: PredicateRegistry, outputs: OutputAdapterRegistry) -> None:
        self.predicates = predicates
        self.outputs = outputs

    def evaluate(self, rule: RuleSpec, facts: Mapping[str, Iterable[Fact]]) -> EvaluationReport:
        if not rule.enabled:
            return EvaluationReport(rule.rule_id, rule.version, 0, (), ())
        if rule.safety.network != "forbidden" or rule.safety.mutation != "forbidden":
            raise RuleProtocolError("offline evaluator requires forbidden network and mutation")
        unknown_inputs = sorted(set(facts) - set(rule.inputs))
        missing_inputs = sorted(set(rule.inputs) - set(facts))
        if unknown_inputs or missing_inputs:
            raise RuleProtocolError("fact inputs do not exactly match RuleSpec inputs")

        predicate_definitions = []
        for call in rule.predicates:
            definition = self.predicates.resolve(call.name)
            definition.validate_args(call.args)
            self._validate_required_inputs(rule, definition.required_inputs, definition.name)
            predicate_definitions.append((call, definition))
        feature_definitions = []
        for feature in rule.score_features:
            definition = self.predicates.resolve(feature.predicate.name)
            definition.validate_args(feature.predicate.args)
            self._validate_required_inputs(rule, definition.required_inputs, definition.name)
            feature_definitions.append((feature, definition))
        output = self.outputs.resolve(rule.emit.adapter)
        output.validate_args(rule.emit.args)
        self._validate_required_inputs(rule, output.required_inputs, output.name)

        ordered_values = []
        for input_name in rule.inputs:
            values = tuple(sorted(facts[input_name], key=lambda item: item.fact_id))
            if not values:
                return EvaluationReport(rule.rule_id, rule.version, 0, (), ())
            ordered_values.append(values)

        matches = []
        rejected = Counter()
        evaluated = 0
        for combination in itertools.product(*ordered_values):
            evaluated += 1
            context = dict(zip(rule.inputs, combination))
            self._validate_context_types(context, predicate_definitions, feature_definitions, output)
            scope_reason = self._scope_rejection(rule.scope, context)
            if scope_reason:
                rejected[scope_reason] += 1
                continue
            reason_codes = []
            hard_failed = False
            for call, definition in predicate_definitions:
                result = definition.evaluate(context, call.args)
                if not isinstance(result, PredicateResult):
                    raise RuleProtocolError("predicate returned an invalid result")
                reason_codes.extend(result.reason_codes)
                if not result.matched:
                    rejected[result.reason_codes[0] if result.reason_codes else "PREDICATE_REJECTED"] += 1
                    hard_failed = True
                    break
            if hard_failed:
                continue

            score = rule.score_base
            contributions = []
            for feature, definition in feature_definitions:
                result = definition.evaluate(context, feature.predicate.args)
                if not 0.0 <= float(result.value) <= 1.0:
                    raise RuleProtocolError("score predicate value must be between 0 and 1")
                contribution = float(result.value) * feature.weight
                score += contribution
                contributions.append(ScoreContribution(
                    predicate=feature.predicate.name,
                    value=float(result.value),
                    weight=feature.weight,
                    contribution=contribution,
                    reason_codes=result.reason_codes,
                ))
                reason_codes.extend(result.reason_codes)
            score = round(max(0.0, min(1.0, score)), 6)
            emitted = output.emit(context, rule, score, tuple(dict.fromkeys(reason_codes)), tuple(contributions))
            match = RuleMatch(
                rule_id=rule.rule_id,
                rule_version=rule.version,
                rule_sha256=rule.canonical_sha256(),
                fact_refs=tuple((name, context[name].fact_id) for name in rule.inputs),
                score=score,
                reason_codes=tuple(dict.fromkeys(reason_codes)),
                score_contributions=tuple(contributions),
                output=emitted,
            )
            matches.append(match)
            if len(matches) > rule.safety.max_matches:
                raise RuleBudgetExceeded("rule match budget exceeded; no truncated result was returned")
        return EvaluationReport(
            rule_id=rule.rule_id,
            rule_version=rule.version,
            evaluated_combinations=evaluated,
            matches=tuple(matches),
            rejection_counts=tuple(sorted(rejected.items())),
        )

    @staticmethod
    def _validate_required_inputs(rule: RuleSpec, required: Mapping[str, Type[Fact]], name: str) -> None:
        missing = sorted(set(required) - set(rule.inputs))
        if missing:
            raise RuleProtocolError("{} requires missing inputs: {}".format(name, ", ".join(missing)))

    @staticmethod
    def _validate_context_types(context: Mapping[str, Fact], predicates: Sequence[Any],
                                features: Sequence[Any], output: OutputAdapterDefinition) -> None:
        definitions = [item[1] for item in predicates] + [item[1] for item in features] + [output]
        for definition in definitions:
            for name, expected_type in definition.required_inputs.items():
                if not isinstance(context[name], expected_type):
                    raise RuleProtocolError("{} input {} has the wrong fact type".format(definition.name, name))

    @staticmethod
    def _scope_rejection(scope: RuleScope, context: Mapping[str, Fact]) -> str:
        values = tuple(context.values())
        if scope.same_project:
            projects = {item.project_id for item in values}
            if "" in projects or len(projects) != 1:
                return "SCOPE_PROJECT_MISMATCH"
        if scope.same_environment:
            environments = {item.env_id for item in values}
            if "" in environments or len(environments) != 1:
                return "SCOPE_ENVIRONMENT_MISMATCH"
        relation = scope.principal_relation
        if relation == "any":
            return ""
        field_name = {
            "same_principal": "principal_id",
            "different_principal": "principal_id",
            "same_profile_revision": "profile_revision_id",
            "same_scope": "scope_key",
            "different_scope": "scope_key",
        }[relation]
        selected = [str(getattr(item, field_name, "") or "") for item in values]
        if not selected or any(not item for item in selected):
            return "SCOPE_PRINCIPAL_CONTEXT_MISSING"
        if relation.startswith("same_") and len(set(selected)) != 1:
            return "SCOPE_PRINCIPAL_RELATION_MISMATCH"
        if relation.startswith("different_") and len(set(selected)) == 1:
            return "SCOPE_PRINCIPAL_RELATION_MISMATCH"
        return ""
