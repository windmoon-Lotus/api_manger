"""Canonical registry for ``parameter_sources`` value provenance.

``build_request_payload`` records, for every filled parameter, where its value
came from (``parameter_sources[name]["source"]``). Several consumers make trust
decisions from that literal. Before this module existed each consumer hard-coded
its own set, so introducing a new provenance literal silently changed behaviour
in every consumer whose default branch means "trustworthy".

Rules for adding a literal:

1. Declare the constant here and add it to every set it belongs to.
2. Never let a new literal fall through to a consumer's default branch by
   accident -- an unlisted literal is treated as resolved by default.
3. Keep the sets explicit even when they are equal, so a future divergence is a
   deliberate edit rather than an oversight.
"""

# --- provenance: value came straight from the imported request parse data ---
SOURCE_REQ_DATA = "req_data"

# --- relationship / provenance: value came from a verified endpoint relation ---
SOURCE_PARAMETER_RELATION = "parameter_relation"

# --- provenance: dependency resolver returned a value but no concrete source ---
SOURCE_PARAMETER_DEPENDENCY = "parameter_dependency"

# --- provenance: value came from a row owned by the requesting account ---
SOURCE_PARAMETER_ARCHIVE = "parameter_archive"

# --- provenance: value came from a project/environment scoped archive row that
# carries no account attribution (offline import is account agnostic by design).
# It is NEVER borrowed across a project or environment boundary, but it is also
# not provably owned by the requesting account.
SOURCE_PARAMETER_ARCHIVE_PROJECT_SCOPED = "parameter_archive_project_scoped"

# --- provenance: value came from a whitelisted canonical alias ---
SOURCE_PARAMETER_DEPENDENCY_ALIAS = "parameter_dependency_alias"

# --- synthetic: placeholder produced from the parameter's declared type ---
SOURCE_EMPTY_DEFAULT = "empty_default"

# --- none: nothing could be resolved ---
SOURCE_UNRESOLVED = "unresolved"

# --- none: optional parameter deliberately left out because it was empty ---
SOURCE_OMITTED_EMPTY_OPTIONAL = "omitted_empty_optional"


# --- value quality: where inside its evidence the value was actually found ---
#
# Provenance answers "whose value is this?"; quality answers "how good is it?".
# They are independent: a project scoped archive row is equally valuable whether
# the value came from the target's response or from a client's request, but only
# the former is evidence that the value is still valid.
#
# ``observed``  the value appears in the evidence's *response* values, i.e. the
#               target itself returned it.
# ``sampled``   the value only appears in the evidence's *request* values. Those
#               were sent by some client, or lifted from an interface document;
#               a document placeholder such as ``123`` lands here. Measured case:
#               ``/filetransfers/dispatcher-remotes`` carried ``transfer_id=123``
#               and the target answered 400, while the synthetic default happened
#               to answer 204.
# ``unknown``   the provenance of the value was not inspected.
VALUE_QUALITY_OBSERVED = "observed"
VALUE_QUALITY_SAMPLED = "sampled"
VALUE_QUALITY_UNKNOWN = "unknown"

# ``placeholder`` the value is documentation/import noise -- a literal such as
#               ``"string"``, ``"example"``, ``123``, or the parameter's declared
#               type default. It names no real resource, so a response to a
#               request carrying it says nothing about authorisation. Measured
#               case: ``/filetransfers/dispatcher-remotes`` carried
#               ``transfer_id=123`` and the target answered 400, while the
#               synthetic default happened to answer 204.
VALUE_QUALITY_PLACEHOLDER = "placeholder"

VALUE_QUALITIES = frozenset({
    VALUE_QUALITY_OBSERVED,
    VALUE_QUALITY_SAMPLED,
    VALUE_QUALITY_UNKNOWN,
    VALUE_QUALITY_PLACEHOLDER,
})

# Qualities that must be surfaced when a *required* parameter depends on them:
# a request-sample value is not proof that the parameter is usable.
REQUEST_SAMPLE_ONLY_QUALITIES = frozenset({
    VALUE_QUALITY_SAMPLED,
})


# Provenance that is provably owned by the requesting account.
ACCOUNT_SCOPED_SOURCES = frozenset({
    SOURCE_PARAMETER_ARCHIVE,
    SOURCE_PARAMETER_DEPENDENCY_ALIAS,
})

# Provenance that is scoped to the same project/environment but carries no
# account attribution. Usable for reads; not sufficient for mutations.
PROJECT_SCOPED_SOURCES = frozenset({
    SOURCE_PARAMETER_ARCHIVE_PROJECT_SCOPED,
})

# A required path parameter must not be sent when its value is synthetic or
# absent. Project-scoped archive values are allowed here -- they are scoped to
# the same project/environment and tagged in the evidence -- but note that being
# project scoped says nothing about value *quality*: check ``value_quality``
# before reading a 4xx as "the endpoint is broken". See
# ``REQUEST_SAMPLE_ONLY_QUALITIES``.
REQUIRED_PATH_BLOCKING_SOURCES = frozenset({
    SOURCE_EMPTY_DEFAULT,
    SOURCE_UNRESOLVED,
})

# Mutations additionally require account-scoped provenance: a value that cannot
# be attributed to the requesting account must not drive a write.
MUTATION_BLOCKING_SOURCES = frozenset({
    SOURCE_EMPTY_DEFAULT,
    SOURCE_UNRESOLVED,
    SOURCE_PARAMETER_ARCHIVE_PROJECT_SCOPED,
})

# Provenance worth surfacing as a request quality warning.
WARNING_SOURCES = frozenset({
    SOURCE_EMPTY_DEFAULT,
})

# Provenance that does not count as "the caller supplied a value".
NOT_PROVIDED_SOURCES = frozenset({
    "",
    SOURCE_EMPTY_DEFAULT,
    SOURCE_OMITTED_EMPTY_OPTIONAL,
})


def is_account_scoped(source: str) -> bool:
    """Return True when the provenance proves the requesting account owns it."""
    return str(source or "") in ACCOUNT_SCOPED_SOURCES


def is_project_scoped(source: str) -> bool:
    """Return True when the provenance is project scoped but unattributed."""
    return str(source or "") in PROJECT_SCOPED_SOURCES


def is_request_sample_only(quality: str) -> bool:
    """Return True when the value was only ever seen in a request."""
    return str(quality or "") in REQUEST_SAMPLE_ONLY_QUALITIES


# Value literals that are almost certainly documentation or import noise rather
# than a real business value. Deliberately excludes ``0`` / ``1`` / ``true``,
# which are legitimate values for many parameters; the synthetic *source*
# (``SOURCE_EMPTY_DEFAULT``) already covers type defaults.
PLACEHOLDER_VALUE_LITERALS = frozenset({
    "", "string", "example", "sample", "demo", "test", "xxx", "xxxx",
    "placeholder", "todo", "fixme", "tbd", "n/a", "none", "null",
    "-", "--", "?", "foo", "bar", "baz", "value", "name", "id",
})


def is_placeholder_value(value) -> bool:
    """Return True when the value itself is documentation noise.

    This inspects the value, not its provenance: a placeholder can arrive
    through ``req_data``, an import, or an archive row, and provenance alone
    cannot tell them apart.
    """
    if value is None:
        return True
    if isinstance(value, (list, dict, tuple, set)):
        return len(value) == 0
    return str(value).strip().lower() in PLACEHOLDER_VALUE_LITERALS


# Verdicts that assert "the target behaved correctly for an authorised
# request".  None of them may rest on an unestablished required value, because
# a placeholder-driven 4xx looks exactly like a correct rejection.
PASS_BLOCKING_VERDICTS = frozenset({
    "no_vuln",
    "isolated_not_found",
    "isolated_blocked",
    "blocked_own_data",
})

REQUIRED_PARAMETER_GATE_REASON = "required_parameter_value_not_established"


def required_parameter_quality_summary(parameter_sources) -> dict:
    """Summarise whether any *required* parameter's value is unestablished.

    Pure function over the ``parameter_sources`` mapping produced by
    ``build_request_payload``.  The result carries provenance labels only --
    never a parameter value -- so it is safe to persist in an evidence summary.

    ``blocks_pass`` is true only when a required parameter's value is provably
    not a real resource reference: either the provenance is synthetic
    (``empty_default`` / ``unresolved``) or the value itself is a placeholder
    literal.  ``request_sample_only`` is surfaced but does not block: a sampled
    value is weak evidence, not proof of absence.
    """
    sources = parameter_sources if isinstance(parameter_sources, dict) else {}
    synthetic = []
    placeholder = []
    sample_only = []
    for name, meta in sources.items():
        if not isinstance(meta, dict) or not meta.get("required"):
            continue
        source = str(meta.get("source") or "")
        quality = str(meta.get("value_quality") or "")
        if source in REQUIRED_PATH_BLOCKING_SOURCES:
            synthetic.append(str(name))
        elif quality == VALUE_QUALITY_PLACEHOLDER:
            placeholder.append(str(name))
        elif is_request_sample_only(quality):
            sample_only.append(str(name))

    def _bounded(names):
        return sorted(names)[:20]

    synthetic = _bounded(synthetic)
    placeholder = _bounded(placeholder)
    sample_only = _bounded(sample_only)
    return {
        "blocks_pass": bool(synthetic or placeholder),
        "synthetic_required": synthetic,
        "placeholder_required": placeholder,
        "request_sample_only_required": sample_only,
    }


def apply_required_parameter_gate(verdict, reasons, confidence, summary):
    """Refuse a pass that rests on an unestablished required value.

    A placeholder-driven 4xx is indistinguishable from a correct rejection, so
    when a required parameter's value was never established the verdict must be
    ``not_evaluable`` rather than a pass.  Non-pass verdicts are returned
    unchanged: the gate exists to prevent false negatives, never to discard a
    finding.
    """
    reasons = list(reasons or [])
    if verdict not in PASS_BLOCKING_VERDICTS:
        return verdict, reasons, confidence
    if not summary or not summary.get("blocks_pass"):
        return verdict, reasons, confidence
    reasons.append(REQUIRED_PARAMETER_GATE_REASON)
    return "not_evaluable", reasons, min(float(confidence or 0.0), 0.6)
