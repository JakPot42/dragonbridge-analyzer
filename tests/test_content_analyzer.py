"""Tests for content_analyzer.py -- P68 Dragonbridge Analyzer."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from content_analyzer import (
    _bigrams,
    _jaccard_text,
    _jaccard_hashtags,
    _parse_ts,
    _parse_date,
    _tier_from_score,
    check_template_repetition,
    check_cross_platform_velocity,
    check_account_creation_clustering,
    check_engagement_ratio_anomaly,
    check_content_recycling_variation,
    check_multilingual_simultaneity,
    check_auto_scheduler_signature,
    check_zero_original_content,
    check_hashtag_density_anomaly,
    check_ai_generic_phrasing,
    check_inauthentic_amplification_network,
    check_seed_blog_pattern,
    analyze_content_set,
)
from fingerprint_db import get_demo_set
from models import ContentSample


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sample(**kwargs):
    defaults = dict(
        sample_id="s_test",
        text="Some neutral text about everyday topics here.",
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


# ---------------------------------------------------------------------------
# Text similarity helpers
# ---------------------------------------------------------------------------

class TestBigrams:
    def test_basic_bigrams(self):
        bg = _bigrams("hello world foo")
        assert ("hello", "world") in bg
        assert ("world", "foo") in bg

    def test_single_word_empty(self):
        assert _bigrams("hello") == set()

    def test_empty_string_empty(self):
        assert _bigrams("") == set()

    def test_case_lowercased(self):
        bg = _bigrams("Hello World")
        assert ("hello", "world") in bg


class TestJaccardText:
    def test_identical_texts_score_1(self):
        text = "The quick brown fox jumps over the lazy dog"
        assert _jaccard_text(text, text) == 1.0

    def test_empty_texts_score_1(self):
        assert _jaccard_text("", "") == 1.0

    def test_completely_different_score_0(self):
        a = "The cat sat on the mat"
        b = "Quantum physics explains subatomic particles"
        sim = _jaccard_text(a, b)
        assert sim == 0.0

    def test_one_word_change_high_similarity(self):
        a = "The United States is spreading disinformation about China's peaceful rise. Western media's double standards regarding Hong Kong reflect American hegemony. The international community should reject these narratives."
        b = "The United States is spreading disinformation about China's peaceful rise. Western media's double standards regarding Hong Kong reflect American imperialism. The international community should reject these narratives."
        sim = _jaccard_text(a, b)
        assert sim > 0.85, f"Expected > 0.85, got {sim:.3f}"

    def test_two_word_changes_medium_similarity(self):
        a = "The United States is spreading disinformation about China's peaceful rise. Western media's double standards regarding Hong Kong reflect American hegemony. The international community should reject these narratives."
        b = "The United States is spreading disinformation about China's peaceful development. Western media's double standards on Hong Kong reflect American hegemony. The international community should reject these narratives."
        sim = _jaccard_text(a, b)
        assert 0.60 <= sim <= 0.84, f"Expected in [0.60, 0.84], got {sim:.3f}"


class TestJaccardHashtags:
    def test_identical_lists(self):
        tags = ["#foo", "#bar", "#baz"]
        assert _jaccard_hashtags(tags, tags) == 1.0

    def test_no_overlap(self):
        assert _jaccard_hashtags(["#a", "#b"], ["#c", "#d"]) == 0.0

    def test_partial_overlap(self):
        sim = _jaccard_hashtags(["#a", "#b", "#c"], ["#a", "#b", "#d"])
        assert abs(sim - 2 / 4) < 0.001  # 2 in common, 4 total

    def test_case_insensitive(self):
        sim = _jaccard_hashtags(["#FOO", "#BAR"], ["#foo", "#bar"])
        assert sim == 1.0

    def test_empty_both_score_1(self):
        assert _jaccard_hashtags([], []) == 1.0


class TestTierFromScore:
    def test_100_is_critical(self):
        assert _tier_from_score(100.0) == "CRITICAL"

    def test_66_is_critical(self):
        assert _tier_from_score(66.0) == "CRITICAL"

    def test_65_is_high(self):
        assert _tier_from_score(65.9) == "HIGH"

    def test_50_is_high(self):
        assert _tier_from_score(50.0) == "HIGH"

    def test_49_is_medium(self):
        assert _tier_from_score(49.9) == "MEDIUM"

    def test_33_is_medium(self):
        assert _tier_from_score(33.0) == "MEDIUM"

    def test_32_is_low(self):
        assert _tier_from_score(32.9) == "LOW"

    def test_16_is_low(self):
        assert _tier_from_score(16.0) == "LOW"

    def test_0_is_minimal(self):
        assert _tier_from_score(0.0) == "MINIMAL"

    def test_8_is_minimal(self):
        assert _tier_from_score(8.0) == "MINIMAL"


# ---------------------------------------------------------------------------
# Individual indicator checks -- alpha-7 (all 12 should fire)
# ---------------------------------------------------------------------------

@pytest.fixture
def alpha7():
    return get_demo_set("alpha-7")


@pytest.fixture
def organic():
    return get_demo_set("organic-baseline")


@pytest.fixture
def borderline():
    return get_demo_set("borderline-medium")


class TestTemplateRepetition:
    def test_alpha7_fires(self, alpha7):
        r = check_template_repetition(alpha7)
        assert r.matched is True
        assert r.data_available is True

    def test_organic_does_not_fire(self, organic):
        r = check_template_repetition(organic)
        assert r.matched is False

    def test_borderline_does_not_fire(self, borderline):
        # all borderline pairs < 0.85
        r = check_template_repetition(borderline)
        assert r.matched is False

    def test_single_sample_no_data(self):
        r = check_template_repetition([_sample()])
        assert r.data_available is False

    def test_indicator_id(self, alpha7):
        r = check_template_repetition(alpha7)
        assert r.indicator_id == "DB-IND-001"

    def test_evidence_contains_jaccard(self, alpha7):
        r = check_template_repetition(alpha7)
        assert "Jaccard" in r.evidence or "jaccard" in r.evidence.lower()


class TestCrossPlatformVelocity:
    def test_alpha7_fires(self, alpha7):
        r = check_cross_platform_velocity(alpha7)
        assert r.matched is True

    def test_organic_does_not_fire_same_platform(self, organic):
        r = check_cross_platform_velocity(organic)
        assert r.matched is False

    def test_borderline_does_not_fire_too_slow(self, borderline):
        r = check_cross_platform_velocity(borderline)
        assert r.matched is False

    def test_same_platform_not_cross(self):
        s1 = _sample(sample_id="s1", platform="twitter", timestamp="2024-03-15T14:00:00Z",
                     hashtags=["#a", "#b"])
        s2 = _sample(sample_id="s2", platform="twitter", timestamp="2024-03-15T14:05:00Z",
                     hashtags=["#a", "#b"])
        r = check_cross_platform_velocity([s1, s2])
        assert r.matched is False

    def test_different_platform_fast_fires(self):
        tags = [f"#tag{i}" for i in range(10)]
        s1 = _sample(sample_id="s1", platform="facebook", timestamp="2024-03-15T14:00:00Z",
                     hashtags=tags)
        s2 = _sample(sample_id="s2", platform="twitter", timestamp="2024-03-15T14:05:00Z",
                     hashtags=tags)
        r = check_cross_platform_velocity([s1, s2])
        assert r.matched is True

    def test_different_platform_slow_does_not_fire(self):
        tags = [f"#tag{i}" for i in range(10)]
        s1 = _sample(sample_id="s1", platform="facebook", timestamp="2024-03-15T10:00:00Z",
                     hashtags=tags)
        s2 = _sample(sample_id="s2", platform="twitter", timestamp="2024-03-15T14:00:00Z",
                     hashtags=tags)
        r = check_cross_platform_velocity([s1, s2])
        assert r.matched is False


class TestAccountCreationClustering:
    def test_alpha7_fires(self, alpha7):
        r = check_account_creation_clustering(alpha7)
        assert r.matched is True

    def test_organic_does_not_fire(self, organic):
        r = check_account_creation_clustering(organic)
        assert r.matched is False

    def test_borderline_fires(self, borderline):
        r = check_account_creation_clustering(borderline)
        assert r.matched is True

    def test_no_dates_no_data(self):
        s = _sample(account_created_date=None)
        r = check_account_creation_clustering([s, s])
        assert r.data_available is False

    def test_3_accounts_same_day_fires(self):
        samples = [
            _sample(sample_id=f"s{i}", account_created_date="2024-01-01")
            for i in range(3)
        ]
        r = check_account_creation_clustering(samples)
        assert r.matched is True

    def test_accounts_30_days_apart_does_not_fire(self):
        dates = ["2024-01-01", "2024-02-01", "2024-03-01"]
        samples = [
            _sample(sample_id=f"s{i}", account_created_date=d)
            for i, d in enumerate(dates)
        ]
        r = check_account_creation_clustering(samples)
        assert r.matched is False


class TestEngagementRatioAnomaly:
    def test_alpha7_fires(self, alpha7):
        r = check_engagement_ratio_anomaly(alpha7)
        assert r.matched is True

    def test_organic_does_not_fire(self, organic):
        r = check_engagement_ratio_anomaly(organic)
        assert r.matched is False

    def test_borderline_fires(self, borderline):
        r = check_engagement_ratio_anomaly(borderline)
        assert r.matched is True

    def test_no_metadata_no_data(self):
        s = _sample(follower_count=None, engagement_count=None)
        r = check_engagement_ratio_anomaly([s])
        assert r.data_available is False

    def test_very_low_ratio_fires(self):
        s = _sample(follower_count=10000, engagement_count=5)
        r = check_engagement_ratio_anomaly([s])
        assert r.matched is True

    def test_good_ratio_does_not_fire(self):
        s = _sample(follower_count=1000, engagement_count=50)
        r = check_engagement_ratio_anomaly([s])
        assert r.matched is False

    def test_evidence_contains_percentage(self, alpha7):
        r = check_engagement_ratio_anomaly(alpha7)
        assert "%" in r.evidence


class TestContentRecyclingVariation:
    def test_alpha7_fires(self, alpha7):
        r = check_content_recycling_variation(alpha7)
        assert r.matched is True

    def test_organic_does_not_fire(self, organic):
        r = check_content_recycling_variation(organic)
        assert r.matched is False

    def test_borderline_fires(self, borderline):
        r = check_content_recycling_variation(borderline)
        assert r.matched is True

    def test_cross_language_hashtag_overlap_fires(self):
        tags = [f"#tag{i}" for i in range(10)]
        s1 = _sample(sample_id="s1", language="en", hashtags=tags, text="Different english text here today")
        s2 = _sample(sample_id="s2", language="zh", hashtags=tags, text="Different chinese text here today")
        r = check_content_recycling_variation([s1, s2])
        assert r.matched is True

    def test_single_sample_no_data(self):
        r = check_content_recycling_variation([_sample()])
        assert r.data_available is False


class TestMultilingualSimultaneity:
    def test_alpha7_fires(self, alpha7):
        r = check_multilingual_simultaneity(alpha7)
        assert r.matched is True

    def test_organic_does_not_fire_all_english(self, organic):
        r = check_multilingual_simultaneity(organic)
        assert r.matched is False

    def test_borderline_does_not_fire_all_english(self, borderline):
        r = check_multilingual_simultaneity(borderline)
        assert r.matched is False

    def test_two_languages_same_time_fires(self):
        s1 = _sample(sample_id="s1", language="en", timestamp="2024-03-15T14:00:00Z")
        s2 = _sample(sample_id="s2", language="zh", timestamp="2024-03-15T14:30:00Z")
        r = check_multilingual_simultaneity([s1, s2])
        assert r.matched is True

    def test_two_languages_far_apart_does_not_fire(self):
        s1 = _sample(sample_id="s1", language="en", timestamp="2024-03-15T08:00:00Z")
        s2 = _sample(sample_id="s2", language="zh", timestamp="2024-03-16T12:00:00Z")
        r = check_multilingual_simultaneity([s1, s2])
        assert r.matched is False

    def test_single_language_does_not_fire(self):
        samples = [_sample(sample_id=f"s{i}", language="en") for i in range(3)]
        r = check_multilingual_simultaneity(samples)
        assert r.matched is False


class TestAutoSchedulerSignature:
    def test_alpha7_fires(self, alpha7):
        r = check_auto_scheduler_signature(alpha7)
        assert r.matched is True

    def test_organic_does_not_fire(self, organic):
        r = check_auto_scheduler_signature(organic)
        assert r.matched is False

    def test_borderline_fires(self, borderline):
        r = check_auto_scheduler_signature(borderline)
        assert r.matched is True

    def test_fewer_than_5_no_data(self):
        samples = [
            _sample(sample_id=f"s{i}", timestamp=f"2024-03-15T{14+i:02d}:00:00Z")
            for i in range(4)
        ]
        r = check_auto_scheduler_signature(samples)
        assert r.data_available is False

    def test_exact_2h_interval_fires(self):
        timestamps = [
            f"2024-03-15T{10+i*2:02d}:00:00Z" for i in range(5)
        ]
        samples = [
            _sample(sample_id=f"s{i}", timestamp=ts)
            for i, ts in enumerate(timestamps)
        ]
        r = check_auto_scheduler_signature(samples)
        assert r.matched is True

    def test_random_intervals_does_not_fire(self):
        timestamps = [
            "2024-03-10T09:17:00Z",
            "2024-03-11T14:42:00Z",
            "2024-03-13T11:05:00Z",
            "2024-03-15T08:33:00Z",
            "2024-03-18T16:20:00Z",
        ]
        samples = [
            _sample(sample_id=f"s{i}", timestamp=ts)
            for i, ts in enumerate(timestamps)
        ]
        r = check_auto_scheduler_signature(samples)
        assert r.matched is False


class TestZeroOriginalContent:
    def test_alpha7_fires(self, alpha7):
        r = check_zero_original_content(alpha7)
        assert r.matched is True

    def test_organic_does_not_fire(self, organic):
        r = check_zero_original_content(organic)
        assert r.matched is False

    def test_borderline_does_not_fire(self, borderline):
        r = check_zero_original_content(borderline)
        assert r.matched is False

    def test_all_reposts_fires(self):
        samples = [_sample(sample_id=f"s{i}", is_repost=True) for i in range(5)]
        r = check_zero_original_content(samples)
        assert r.matched is True

    def test_mostly_original_does_not_fire(self):
        samples = [_sample(sample_id=f"s{i}", is_repost=(i == 0)) for i in range(5)]
        r = check_zero_original_content(samples)
        assert r.matched is False

    def test_no_data_no_data(self):
        samples = [_sample(sample_id=f"s{i}", is_repost=None) for i in range(5)]
        r = check_zero_original_content(samples)
        assert r.data_available is False


class TestHashtagDensityAnomaly:
    def test_alpha7_fires(self, alpha7):
        r = check_hashtag_density_anomaly(alpha7)
        assert r.matched is True

    def test_organic_does_not_fire(self, organic):
        r = check_hashtag_density_anomaly(organic)
        assert r.matched is False

    def test_borderline_fires(self, borderline):
        r = check_hashtag_density_anomaly(borderline)
        assert r.matched is True

    def test_9_hashtags_fires(self):
        s = _sample(hashtags=[f"#tag{i}" for i in range(9)])
        r = check_hashtag_density_anomaly([s])
        assert r.matched is True

    def test_8_hashtags_does_not_fire(self):
        s = _sample(hashtags=[f"#tag{i}" for i in range(8)])
        r = check_hashtag_density_anomaly([s])
        assert r.matched is False

    def test_3_hashtags_does_not_fire(self):
        s = _sample(hashtags=["#a", "#b", "#c"])
        r = check_hashtag_density_anomaly([s])
        assert r.matched is False

    def test_evidence_contains_count(self, alpha7):
        r = check_hashtag_density_anomaly(alpha7)
        assert "12" in r.evidence


class TestAiGenericPhrasing:
    def test_alpha7_fires(self, alpha7):
        r = check_ai_generic_phrasing(alpha7)
        assert r.matched is True

    def test_organic_does_not_fire(self, organic):
        r = check_ai_generic_phrasing(organic)
        assert r.matched is False

    def test_borderline_does_not_fire(self, borderline):
        r = check_ai_generic_phrasing(borderline)
        assert r.matched is False

    def test_explicit_cib_phrase_fires(self):
        s = _sample(
            text=(
                "The United States is spreading lies. American hegemony must end. "
                "China's peaceful development continues despite opposition."
            )
        )
        r = check_ai_generic_phrasing([s])
        assert r.matched is True

    def test_one_phrase_does_not_fire(self):
        s = _sample(text="American hegemony is a complex topic in international relations.")
        r = check_ai_generic_phrasing([s])
        assert r.matched is False

    def test_evidence_lists_phrases(self, alpha7):
        r = check_ai_generic_phrasing(alpha7)
        assert len(r.evidence) > 0


class TestInauthenticAmplificationNetwork:
    def test_alpha7_fires(self, alpha7):
        r = check_inauthentic_amplification_network(alpha7)
        assert r.matched is True

    def test_organic_does_not_fire(self, organic):
        r = check_inauthentic_amplification_network(organic)
        assert r.matched is False

    def test_borderline_does_not_fire(self, borderline):
        r = check_inauthentic_amplification_network(borderline)
        assert r.matched is False

    def test_no_network_data_no_data(self):
        s1 = _sample(sample_id="s1")
        s2 = _sample(sample_id="s2")
        r = check_inauthentic_amplification_network([s1, s2])
        assert r.data_available is False

    def test_full_closed_loop_fires(self):
        s1 = _sample(sample_id="s1")
        s2 = _sample(sample_id="s2")
        s1.shared_by_in_set = ["s2"]
        s2.shared_by_in_set = ["s1"]
        r = check_inauthentic_amplification_network([s1, s2])
        assert r.matched is True

    def test_zero_sharing_does_not_fire(self):
        s1 = _sample(sample_id="s1")
        s2 = _sample(sample_id="s2")
        s1.shared_by_in_set = []
        s2.shared_by_in_set = []
        r = check_inauthentic_amplification_network([s1, s2])
        assert r.matched is False


class TestSeedBlogPattern:
    def test_alpha7_fires(self, alpha7):
        r = check_seed_blog_pattern(alpha7)
        assert r.matched is True

    def test_organic_does_not_fire_old_domain(self, organic):
        r = check_seed_blog_pattern(organic)
        assert r.matched is False

    def test_borderline_does_not_fire_old_domain(self, borderline):
        r = check_seed_blog_pattern(borderline)
        assert r.matched is False

    def test_no_domain_data_no_data(self):
        s = _sample(source_domain=None, domain_age_months=None)
        r = check_seed_blog_pattern([s])
        assert r.data_available is False

    def test_young_domain_fires(self):
        s = _sample(source_domain="newblog2024.blogspot.com", domain_age_months=3)
        r = check_seed_blog_pattern([s])
        assert r.matched is True

    def test_old_domain_does_not_fire(self):
        s = _sample(source_domain="nytimes.com", domain_age_months=120)
        r = check_seed_blog_pattern([s])
        assert r.matched is False

    def test_evidence_contains_domain(self, alpha7):
        r = check_seed_blog_pattern(alpha7)
        assert "blogspot" in r.evidence.lower() or "chinaperspective" in r.evidence.lower()


# ---------------------------------------------------------------------------
# Full analysis pipeline
# ---------------------------------------------------------------------------

class TestAnalyzeContentSet:
    def test_alpha7_is_critical(self, alpha7):
        report = analyze_content_set(alpha7, set_name="alpha-7")
        assert report.tier == "CRITICAL"

    def test_alpha7_score_100(self, alpha7):
        report = analyze_content_set(alpha7, set_name="alpha-7")
        assert report.score == 100.0

    def test_alpha7_matched_12(self, alpha7):
        report = analyze_content_set(alpha7, set_name="alpha-7")
        assert report.matched_count == 12

    def test_alpha7_assessable_12(self, alpha7):
        report = analyze_content_set(alpha7, set_name="alpha-7")
        assert report.assessable_count == 12

    def test_organic_is_minimal(self, organic):
        report = analyze_content_set(organic, set_name="organic-baseline")
        assert report.tier == "MINIMAL"

    def test_organic_score_zero(self, organic):
        report = analyze_content_set(organic, set_name="organic-baseline")
        assert report.score == 0.0

    def test_organic_matched_zero(self, organic):
        report = analyze_content_set(organic, set_name="organic-baseline")
        assert report.matched_count == 0

    def test_borderline_is_medium(self, borderline):
        report = analyze_content_set(borderline, set_name="borderline-medium")
        assert report.tier == "MEDIUM"

    def test_borderline_matched_5(self, borderline):
        report = analyze_content_set(borderline, set_name="borderline-medium")
        assert report.matched_count == 5

    def test_borderline_specific_indicators_fire(self, borderline):
        report = analyze_content_set(borderline, set_name="borderline-medium")
        fired = {r.indicator_id for r in report.check_results if r.matched}
        assert "DB-IND-003" in fired  # account clustering
        assert "DB-IND-004" in fired  # engagement ratio
        assert "DB-IND-005" in fired  # content recycling
        assert "DB-IND-007" in fired  # auto-scheduler
        assert "DB-IND-009" in fired  # hashtag density

    def test_borderline_specific_indicators_absent(self, borderline):
        report = analyze_content_set(borderline, set_name="borderline-medium")
        fired = {r.indicator_id for r in report.check_results if r.matched}
        assert "DB-IND-001" not in fired  # no template repetition
        assert "DB-IND-006" not in fired  # no multilingual
        assert "DB-IND-008" not in fired  # not zero original
        assert "DB-IND-010" not in fired  # no CIB phrases
        assert "DB-IND-012" not in fired  # established domain

    def test_report_has_12_check_results(self, alpha7):
        report = analyze_content_set(alpha7)
        assert len(report.check_results) == 12

    def test_report_disclaimer_set(self, alpha7):
        report = analyze_content_set(alpha7)
        assert len(report.disclaimer) > 0

    def test_alpha7_all_indicators_data_available(self, alpha7):
        report = analyze_content_set(alpha7)
        for r in report.check_results:
            assert r.data_available is True, \
                f"{r.indicator_id} unexpectedly has data_available=False"

    def test_set_name_stored(self, alpha7):
        report = analyze_content_set(alpha7, set_name="test-name")
        assert report.set_name == "test-name"

    def test_sample_count_stored(self, alpha7):
        report = analyze_content_set(alpha7)
        assert report.sample_count == 5
