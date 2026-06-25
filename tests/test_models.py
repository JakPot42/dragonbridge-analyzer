"""Tests for models.py -- P68 Dragonbridge Analyzer."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from models import (
    FingerprintIndicator,
    ContentSample,
    CheckResult,
    AnalysisReport,
)


class TestFingerprintIndicator:
    def test_construction(self):
        ind = FingerprintIndicator(
            indicator_id="DB-IND-001",
            name="TEMPLATE_REPETITION",
            category="CONTENT",
            description="Near-identical text across accounts",
            source_report="Meta ATR August 2022",
            source_url="transparency.fb.com",
            source_citation="Meta. ATR Aug 2022.",
            threshold_description="Jaccard > 0.85",
            check_requires=["multiple_samples"],
        )
        assert ind.indicator_id == "DB-IND-001"
        assert ind.name == "TEMPLATE_REPETITION"
        assert ind.category == "CONTENT"
        assert "multiple_samples" in ind.check_requires

    def test_check_requires_is_list(self):
        ind = FingerprintIndicator(
            indicator_id="DB-IND-009",
            name="HASHTAG_DENSITY_ANOMALY",
            category="CONTENT",
            description="Excessive hashtags",
            source_report="Meta ATR March 2023",
            source_url="transparency.fb.com",
            source_citation="Meta. ATR Mar 2023.",
            threshold_description="> 8 hashtags",
            check_requires=[],
        )
        assert ind.check_requires == []


class TestContentSample:
    def _make(self, **kwargs):
        defaults = dict(
            sample_id="s_test",
            text="Test text about something",
            platform="twitter",
            language="en",
            timestamp="2024-03-15T14:00:00Z",
            hashtags=["#test"],
            follower_count=1000,
            engagement_count=50,
            is_repost=False,
            source_domain="example.com",
            domain_age_months=24,
            account_created_date="2022-01-15",
        )
        defaults.update(kwargs)
        return ContentSample(**defaults)

    def test_basic_construction(self):
        s = self._make()
        assert s.sample_id == "s_test"
        assert s.platform == "twitter"
        assert s.language == "en"

    def test_hashtags_stored(self):
        s = self._make(hashtags=["#foo", "#bar", "#baz"])
        assert len(s.hashtags) == 3

    def test_optional_fields_default_none(self):
        s = self._make(
            timestamp=None,
            follower_count=None,
            engagement_count=None,
            is_repost=None,
            source_domain=None,
            domain_age_months=None,
            account_created_date=None,
        )
        assert s.timestamp is None
        assert s.follower_count is None
        assert s.shared_by_in_set is None

    def test_shared_by_in_set_default_none(self):
        s = self._make()
        assert s.shared_by_in_set is None

    def test_shared_by_in_set_set_to_list(self):
        s = self._make()
        s.shared_by_in_set = ["s_001", "s_002"]
        assert len(s.shared_by_in_set) == 2

    def test_empty_shared_by_distinct_from_none(self):
        s_none = self._make()
        s_none.shared_by_in_set = None
        s_empty = self._make()
        s_empty.shared_by_in_set = []
        assert s_none.shared_by_in_set is None
        assert s_empty.shared_by_in_set == []


class TestCheckResult:
    def test_matched_result(self):
        r = CheckResult(
            indicator_id="DB-IND-001",
            indicator_name="TEMPLATE_REPETITION",
            category="CONTENT",
            matched=True,
            data_available=True,
            evidence="Jaccard 0.90 between s001 and s002",
            source_citation="Meta ATR Aug 2022",
        )
        assert r.matched is True
        assert r.data_available is True

    def test_absent_result(self):
        r = CheckResult(
            indicator_id="DB-IND-001",
            indicator_name="TEMPLATE_REPETITION",
            category="CONTENT",
            matched=False,
            data_available=True,
            evidence="Max Jaccard 0.30 below threshold",
            source_citation="Meta ATR Aug 2022",
        )
        assert r.matched is False
        assert r.data_available is True

    def test_no_data_result(self):
        r = CheckResult(
            indicator_id="DB-IND-007",
            indicator_name="AUTO_SCHEDULER_SIGNATURE",
            category="TIMING",
            matched=False,
            data_available=False,
            evidence="Only 3 samples with timestamps; need 5",
            source_citation="SIO 2020",
        )
        assert r.data_available is False
        assert r.matched is False


class TestAnalysisReport:
    def _make_result(self, iid, matched, available=True):
        return CheckResult(
            indicator_id=iid,
            indicator_name=iid,
            category="CONTENT",
            matched=matched,
            data_available=available,
            evidence="test",
            source_citation="test citation",
        )

    def test_construction(self):
        results = [self._make_result(f"DB-IND-{i:03d}", True) for i in range(1, 13)]
        report = AnalysisReport(
            set_name="test-set",
            prepared_date="2026-06-25",
            sample_count=5,
            check_results=results,
            matched_count=12,
            assessable_count=12,
            score=100.0,
            tier="CRITICAL",
        )
        assert report.tier == "CRITICAL"
        assert report.score == 100.0
        assert report.matched_count == 12

    def test_brief_text_defaults_empty(self):
        report = AnalysisReport(
            set_name="test",
            prepared_date="2026-06-25",
            sample_count=5,
            check_results=[],
            matched_count=0,
            assessable_count=0,
            score=0.0,
            tier="MINIMAL",
        )
        assert report.brief_text == ""
        assert report.disclaimer == ""

    def test_scores(self):
        report = AnalysisReport(
            set_name="test",
            prepared_date="2026-06-25",
            sample_count=5,
            check_results=[],
            matched_count=6,
            assessable_count=12,
            score=50.0,
            tier="HIGH",
        )
        assert report.score == 50.0
        assert report.tier == "HIGH"
