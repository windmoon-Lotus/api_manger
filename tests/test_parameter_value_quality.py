"""Contract tests for archive value *quality* (as opposed to provenance).

Provenance answers "whose value is this?". Quality answers "how good is it?".
A value that only ever appeared in a request may be an interface-document
placeholder (measured case: ``transfer_id=123`` answered 400), so it must never
be read as proof that the parameter was satisfied with a usable value.

These tests also pin the Tier-2 rule from the parameter-archive identity fix:
a project/environment scoped lookup may fall back to rows with *no* account
attribution, and must never borrow a row attributed to another account.
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from apiAnalysis.tool import compose_request, parameter_dependency
from apiAnalysis.tool.parameter_dependency import _archive_value, _value_quality
from apiAnalysis.tool.parameter_sources import (
    ACCOUNT_SCOPED_SOURCES,
    MUTATION_BLOCKING_SOURCES,
    PROJECT_SCOPED_SOURCES,
    REQUEST_SAMPLE_ONLY_QUALITIES,
    SOURCE_PARAMETER_ARCHIVE,
    SOURCE_PARAMETER_ARCHIVE_PROJECT_SCOPED,
    VALUE_QUALITY_OBSERVED,
    VALUE_QUALITY_SAMPLED,
    VALUE_QUALITY_UNKNOWN,
    is_request_sample_only,
)
from apiAnalysis.tool.request_evidence_preview import request_quality_warnings


class _FakeQuery(object):
    def __init__(self, rows):
        self._rows = list(rows)

    def __iter__(self):
        return iter(self._rows)

    def __len__(self):
        return len(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None


class _FakeArchive(object):
    """Minimal stand-in honouring the filters the code actually passes."""

    def __init__(self, rows):
        self.rows = list(rows)

    def objects(self, **kwargs):
        out = []
        for row in self.rows:
            if "account_id" in kwargs and str(row.account_id) != str(kwargs["account_id"]):
                continue
            if "parameter__in" in kwargs and row.parameter not in kwargs["parameter__in"]:
                continue
            if "parameter" in kwargs and row.parameter != kwargs["parameter"]:
                continue
            if "req_pathid__contains" in kwargs and kwargs["req_pathid__contains"] not in (row.req_pathid or []):
                continue
            out.append(row)
        return _FakeQuery(out)


def row(account_id, parameter, req_value, res_value, pathid=7):
    return SimpleNamespace(
        id=1, account_id=account_id, parameter=parameter,
        req_value=list(req_value or []), res_value=list(res_value or []),
        req_pathid=[pathid], res_pathid=[pathid],
    )


def patch_archive(rows):
    """Replace only ``objects`` -- the module level annotations on
    ``_archive_value`` are evaluated at call time from module globals, so
    swapping the whole ``parameter_archive`` symbol breaks them."""
    return patch.object(parameter_dependency.parameter_archive,
                        "objects", _FakeArchive(rows).objects)


class ValueQualityClassificationTests(unittest.TestCase):
    def test_value_seen_in_response_is_observed(self):
        item = row("", "remoteid", ["1670367506"], ["1691227841", "1670367506"])
        self.assertEqual(_value_quality(item, "1670367506"), VALUE_QUALITY_OBSERVED)

    def test_value_only_in_request_is_sampled(self):
        item = row("", "transfer_id", ["123"], ["15857", "15854"])
        self.assertEqual(_value_quality(item, "123"), VALUE_QUALITY_SAMPLED)

    def test_int_and_str_forms_compare_equal(self):
        item = row("", "userid", [], [34981558])
        self.assertEqual(_value_quality(item, "34981558"), VALUE_QUALITY_OBSERVED)

    def test_missing_item_or_value_is_unknown(self):
        self.assertEqual(_value_quality(None, "x"), VALUE_QUALITY_UNKNOWN)
        self.assertEqual(_value_quality(row("", "a", ["x"], []), None), VALUE_QUALITY_UNKNOWN)

    def test_value_found_in_neither_list_is_unknown(self):
        item = row("", "a", ["x"], ["y"])
        self.assertEqual(_value_quality(item, "z"), VALUE_QUALITY_UNKNOWN)


class RegistryInvariantTests(unittest.TestCase):
    def test_project_scoped_is_never_account_scoped(self):
        self.assertNotIn(SOURCE_PARAMETER_ARCHIVE_PROJECT_SCOPED, ACCOUNT_SCOPED_SOURCES)
        self.assertIn(SOURCE_PARAMETER_ARCHIVE_PROJECT_SCOPED, PROJECT_SCOPED_SOURCES)

    def test_project_scoped_cannot_drive_a_mutation(self):
        self.assertIn(SOURCE_PARAMETER_ARCHIVE_PROJECT_SCOPED, MUTATION_BLOCKING_SOURCES)

    def test_account_scoped_archive_may_drive_a_mutation(self):
        self.assertNotIn(SOURCE_PARAMETER_ARCHIVE, MUTATION_BLOCKING_SOURCES)

    def test_request_sample_only_helper(self):
        self.assertTrue(is_request_sample_only(VALUE_QUALITY_SAMPLED))
        self.assertFalse(is_request_sample_only(VALUE_QUALITY_OBSERVED))
        self.assertFalse(is_request_sample_only(VALUE_QUALITY_UNKNOWN))
        self.assertEqual(REQUEST_SAMPLE_ONLY_QUALITIES, frozenset({VALUE_QUALITY_SAMPLED}))


class TierTwoScopeTests(unittest.TestCase):
    """The fallback must use unattributed rows only -- never another account's."""

    def _resolve(self, rows, account_id="owner"):
        with patch_archive(rows):
            return _archive_value(["remoteid"], 7, account_id, exact_path=False,
                                  project_id="p", env_id="default")

    def test_tier_one_wins(self):
        rows = [row("owner", "remoteid", [], ["111"]),
                row("", "remoteid", [], ["222"])]
        value, item = self._resolve(rows)
        self.assertEqual(value, "111")
        self.assertEqual(item.account_id, "owner")

    def test_tier_two_uses_unattributed_rows(self):
        rows = [row("", "remoteid", [], ["222"]), row("peer", "remoteid", [], ["333"])]
        value, item = self._resolve(rows)
        self.assertEqual(value, "222")
        self.assertEqual(item.account_id, "")

    def test_another_accounts_row_is_never_borrowed(self):
        rows = [row("peer", "remoteid", [], ["333"])]
        value, item = self._resolve(rows)
        self.assertIsNone(value)
        self.assertIsNone(item)


class ArchiveLookupQualityTests(unittest.TestCase):
    def test_lookup_reports_request_sample_quality(self):
        rows = [row("", "transfer_id", ["123"], ["15857"])]
        with patch_archive(rows):
            value, source, quality = compose_request._lookup_archive_value(
                "transfer_id", 7, account_id="owner", project_id="p", env_id="default")
        self.assertEqual(value, "123")
        self.assertEqual(source, SOURCE_PARAMETER_ARCHIVE_PROJECT_SCOPED)
        self.assertEqual(quality, VALUE_QUALITY_SAMPLED)

    def test_lookup_returns_unknown_quality_when_nothing_matches(self):
        with patch_archive([]):
            value, source, quality = compose_request._lookup_archive_value(
                "transfer_id", 7, account_id="owner", project_id="p", env_id="default")
        self.assertIsNone(value)
        self.assertIsNone(source)
        self.assertEqual(quality, VALUE_QUALITY_UNKNOWN)

    def test_lookup_never_borrows_another_accounts_row(self):
        rows = [row("peer", "transfer_id", ["123"], ["15857"])]
        with patch_archive(rows):
            value, source, quality = compose_request._lookup_archive_value(
                "transfer_id", 7, account_id="owner", project_id="p", env_id="default")
        self.assertIsNone(value)
        self.assertEqual(quality, VALUE_QUALITY_UNKNOWN)


class QualityWarningTests(unittest.TestCase):
    def _warnings(self, sources):
        snapshot = SimpleNamespace(parameter_sources=sources)
        return request_quality_warnings(snapshot)

    def test_required_request_sample_value_is_warned(self):
        warnings = self._warnings({
            "transfer_id": {"source": SOURCE_PARAMETER_ARCHIVE_PROJECT_SCOPED,
                            "value_quality": VALUE_QUALITY_SAMPLED, "required": True},
        })
        self.assertEqual(
            warnings, ["required_parameter_value_only_seen_in_a_request:transfer_id"])

    def test_observed_value_is_not_warned(self):
        warnings = self._warnings({
            "remoteid": {"source": SOURCE_PARAMETER_ARCHIVE_PROJECT_SCOPED,
                         "value_quality": VALUE_QUALITY_OBSERVED, "required": True},
        })
        self.assertEqual(warnings, [])

    def test_optional_request_sample_value_is_not_warned(self):
        warnings = self._warnings({
            "transfer_id": {"source": SOURCE_PARAMETER_ARCHIVE_PROJECT_SCOPED,
                            "value_quality": VALUE_QUALITY_SAMPLED, "required": False},
        })
        self.assertEqual(warnings, [])

    def test_synthetic_default_warning_still_fires(self):
        warnings = self._warnings({
            "sn": {"source": "empty_default", "value_quality": VALUE_QUALITY_UNKNOWN,
                   "required": True},
        })
        self.assertEqual(warnings, ["required_parameter_uses_synthetic_default:sn"])


if __name__ == "__main__":
    unittest.main()
