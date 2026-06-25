"""Tests for seed_data.py -- P68 Dragonbridge Analyzer."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from seed_data import (
    FINGERPRINT_INDICATORS,
    DEMO_SETS,
    DEMO_REPORT_TEXT,
)
from config import INDICATOR_IDS, DEMO_SET_NAMES


# ---------------------------------------------------------------------------
# Indicator database structure
# ---------------------------------------------------------------------------

class TestIndicatorDatabase:
    def test_indicator_count(self):
        assert len(FINGERPRINT_INDICATORS) == 12

    def test_all_ids_present(self):
        ids = [i["indicator_id"] for i in FINGERPRINT_INDICATORS]
        for expected_id in INDICATOR_IDS:
            assert expected_id in ids

    def test_ids_unique(self):
        ids = [i["indicator_id"] for i in FINGERPRINT_INDICATORS]
        assert len(ids) == len(set(ids))

    def test_required_fields(self):
        required = [
            "indicator_id", "name", "category", "description",
            "source_report", "source_url", "source_citation",
            "threshold_description", "check_requires",
        ]
        for ind in FINGERPRINT_INDICATORS:
            for field in required:
                assert field in ind, f"{ind['indicator_id']} missing {field}"

    def test_categories_valid(self):
        valid = {"CONTENT", "TIMING", "ACCOUNT", "NETWORK"}
        for ind in FINGERPRINT_INDICATORS:
            assert ind["category"] in valid, \
                f"{ind['indicator_id']} has invalid category {ind['category']}"

    def test_check_requires_is_list(self):
        for ind in FINGERPRINT_INDICATORS:
            assert isinstance(ind["check_requires"], list), \
                f"{ind['indicator_id']} check_requires is not a list"

    def test_descriptions_not_empty(self):
        for ind in FINGERPRINT_INDICATORS:
            assert len(ind["description"]) > 20, \
                f"{ind['indicator_id']} description too short"

    def test_source_citations_not_empty(self):
        for ind in FINGERPRINT_INDICATORS:
            assert len(ind["source_citation"]) > 20, \
                f"{ind['indicator_id']} source_citation too short"

    def test_ind001_is_template_repetition(self):
        ind = next(i for i in FINGERPRINT_INDICATORS if i["indicator_id"] == "DB-IND-001")
        assert ind["name"] == "TEMPLATE_REPETITION"
        assert ind["category"] == "CONTENT"

    def test_ind001_cites_meta_atr(self):
        ind = next(i for i in FINGERPRINT_INDICATORS if i["indicator_id"] == "DB-IND-001")
        assert "Meta" in ind["source_citation"]
        assert "2022" in ind["source_citation"]

    def test_ind003_cites_sio(self):
        ind = next(i for i in FINGERPRINT_INDICATORS if i["indicator_id"] == "DB-IND-003")
        assert "Stanford" in ind["source_citation"] or "Graphika" in ind["source_citation"]

    def test_ind004_cites_mandiant(self):
        ind = next(i for i in FINGERPRINT_INDICATORS if i["indicator_id"] == "DB-IND-004")
        assert "Mandiant" in ind["source_citation"] or "Google" in ind["source_citation"]

    def test_ind007_cites_sio_2020(self):
        ind = next(i for i in FINGERPRINT_INDICATORS if i["indicator_id"] == "DB-IND-007")
        assert "Stanford" in ind["source_citation"] or "Spamouflage" in ind["source_citation"]

    def test_ind010_cites_meta_2023(self):
        ind = next(i for i in FINGERPRINT_INDICATORS if i["indicator_id"] == "DB-IND-010")
        assert "2023" in ind["source_citation"]

    def test_content_category_count(self):
        content = [i for i in FINGERPRINT_INDICATORS if i["category"] == "CONTENT"]
        assert len(content) >= 3  # IND-001, 005, 009, 010

    def test_timing_category_count(self):
        timing = [i for i in FINGERPRINT_INDICATORS if i["category"] == "TIMING"]
        assert len(timing) >= 2  # IND-002, 006, 007

    def test_account_category_count(self):
        account = [i for i in FINGERPRINT_INDICATORS if i["category"] == "ACCOUNT"]
        assert len(account) >= 2  # IND-003, 004, 008

    def test_network_category_count(self):
        network = [i for i in FINGERPRINT_INDICATORS if i["category"] == "NETWORK"]
        assert len(network) >= 2  # IND-011, 012


# ---------------------------------------------------------------------------
# Demo sets structure
# ---------------------------------------------------------------------------

class TestDemoSets:
    def test_all_set_names_present(self):
        for name in DEMO_SET_NAMES:
            assert name in DEMO_SETS

    def test_each_set_has_five_samples(self):
        for name, samples in DEMO_SETS.items():
            assert len(samples) == 5, f"Set '{name}' has {len(samples)} samples, expected 5"

    def test_sample_ids_unique_within_set(self):
        for name, samples in DEMO_SETS.items():
            ids = [s["sample_id"] for s in samples]
            assert len(ids) == len(set(ids)), f"Set '{name}' has duplicate sample IDs"

    def test_required_sample_fields(self):
        required = ["sample_id", "text", "platform", "language", "timestamp", "hashtags"]
        for name, samples in DEMO_SETS.items():
            for s in samples:
                for field in required:
                    assert field in s, f"Set '{name}' sample missing field '{field}'"

    def test_alpha7_has_english_and_chinese(self):
        alpha = DEMO_SETS["alpha-7"]
        langs = {s["language"] for s in alpha}
        assert "en" in langs
        assert "zh" in langs

    def test_alpha7_all_repost(self):
        alpha = DEMO_SETS["alpha-7"]
        assert all(s.get("is_repost") is True for s in alpha)

    def test_alpha7_all_same_domain(self):
        alpha = DEMO_SETS["alpha-7"]
        domains = {s.get("source_domain") for s in alpha}
        assert len(domains) == 1

    def test_alpha7_domain_young(self):
        alpha = DEMO_SETS["alpha-7"]
        ages = [s.get("domain_age_months") for s in alpha]
        assert all(a is not None and a < 12 for a in ages)

    def test_alpha7_accounts_created_within_4_days(self):
        from datetime import datetime
        alpha = DEMO_SETS["alpha-7"]
        dates = sorted(
            datetime.strptime(s["account_created_date"], "%Y-%m-%d")
            for s in alpha
        )
        span = (dates[-1] - dates[0]).days
        assert span <= 4

    def test_alpha7_hashtag_count_12(self):
        alpha = DEMO_SETS["alpha-7"]
        for s in alpha:
            assert len(s["hashtags"]) == 12

    def test_alpha7_low_engagement(self):
        alpha = DEMO_SETS["alpha-7"]
        for s in alpha:
            ratio = s["engagement_count"] / s["follower_count"]
            assert ratio < 0.001, f"{s['sample_id']} engagement ratio {ratio:.4%} >= 0.1%"

    def test_alpha7_shared_by_in_set(self):
        alpha = DEMO_SETS["alpha-7"]
        for s in alpha:
            assert "shared_by_in_set" in s
            assert len(s["shared_by_in_set"]) == 4

    def test_organic_baseline_all_english(self):
        organic = DEMO_SETS["organic-baseline"]
        assert all(s["language"] == "en" for s in organic)

    def test_organic_baseline_no_repost_majority(self):
        organic = DEMO_SETS["organic-baseline"]
        original = sum(1 for s in organic if not s.get("is_repost", True))
        assert original >= 3

    def test_organic_baseline_good_engagement(self):
        organic = DEMO_SETS["organic-baseline"]
        for s in organic:
            ratio = s["engagement_count"] / s["follower_count"]
            assert ratio > 0.001, f"{s['sample_id']} engagement ratio {ratio:.4%} unexpectedly low"

    def test_organic_baseline_few_hashtags(self):
        organic = DEMO_SETS["organic-baseline"]
        for s in organic:
            assert len(s["hashtags"]) <= 3

    def test_borderline_medium_has_9_hashtags(self):
        borderline = DEMO_SETS["borderline-medium"]
        for s in borderline:
            assert len(s["hashtags"]) == 9

    def test_borderline_medium_all_english(self):
        borderline = DEMO_SETS["borderline-medium"]
        assert all(s["language"] == "en" for s in borderline)

    def test_borderline_medium_accounts_within_7_days(self):
        from datetime import datetime
        borderline = DEMO_SETS["borderline-medium"]
        dates = sorted(
            datetime.strptime(s["account_created_date"], "%Y-%m-%d")
            for s in borderline
        )
        span = (dates[-1] - dates[0]).days
        assert span < 7

    def test_borderline_medium_low_engagement(self):
        borderline = DEMO_SETS["borderline-medium"]
        for s in borderline:
            ratio = s["engagement_count"] / s["follower_count"]
            assert ratio < 0.001

    def test_borderline_medium_partial_repost(self):
        borderline = DEMO_SETS["borderline-medium"]
        reposts = sum(1 for s in borderline if s.get("is_repost"))
        original = sum(1 for s in borderline if not s.get("is_repost"))
        assert reposts >= 1 and original >= 1


# ---------------------------------------------------------------------------
# DEMO_REPORT_TEXT
# ---------------------------------------------------------------------------

class TestDemoReportText:
    def test_ascii_only(self):
        for i, ch in enumerate(DEMO_REPORT_TEXT):
            assert ord(ch) < 128, \
                f"Non-ASCII character at position {i}: {repr(ch)} (ord={ord(ch)})"

    def test_contains_framing_notice(self):
        assert "PATTERN IDENTIFICATION ONLY" in DEMO_REPORT_TEXT

    def test_contains_not_attribution(self):
        text_upper = DEMO_REPORT_TEXT.upper()
        assert "NOT AN ATTRIBUTION CLAIM" in text_upper or "NOT ATTRIBUTION" in text_upper

    def test_all_12_indicators_cited(self):
        for i in range(1, 13):
            iid = f"DB-IND-{i:03d}"
            assert iid in DEMO_REPORT_TEXT, f"{iid} not cited in DEMO_REPORT_TEXT"

    def test_all_indicators_marked_present(self):
        for i in range(1, 13):
            iid = f"DB-IND-{i:03d}"
            assert f"[PRESENT] {iid}" in DEMO_REPORT_TEXT, \
                f"{iid} not marked PRESENT in DEMO_REPORT_TEXT"

    def test_critical_tier_in_report(self):
        assert "CRITICAL" in DEMO_REPORT_TEXT

    def test_score_100_in_report(self):
        assert "100.0" in DEMO_REPORT_TEXT or "100 / 100" in DEMO_REPORT_TEXT or "12 of 12" in DEMO_REPORT_TEXT

    def test_meta_atr_cited(self):
        assert "Meta" in DEMO_REPORT_TEXT

    def test_mandiant_cited(self):
        assert "Mandiant" in DEMO_REPORT_TEXT

    def test_stanford_cited(self):
        assert "Stanford" in DEMO_REPORT_TEXT

    def test_no_em_dashes(self):
        assert "—" not in DEMO_REPORT_TEXT

    def test_recommended_next_steps_section(self):
        assert "RECOMMENDED NEXT STEPS" in DEMO_REPORT_TEXT

    def test_source_reports_section(self):
        assert "SOURCE REPORTS CITED" in DEMO_REPORT_TEXT

    def test_contains_alpha7_set_reference(self):
        assert "Alpha-7" in DEMO_REPORT_TEXT or "alpha-7" in DEMO_REPORT_TEXT
