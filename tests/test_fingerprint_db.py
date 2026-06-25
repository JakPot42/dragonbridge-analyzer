"""Tests for fingerprint_db.py -- P68 Dragonbridge Analyzer."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fingerprint_db import (
    all_indicators,
    get_indicator,
    indicators_by_category,
    all_demo_sets,
    get_demo_set,
    demo_set_names,
)
from models import FingerprintIndicator, ContentSample
from config import INDICATOR_IDS, DEMO_SET_NAMES


class TestAllIndicators:
    def test_returns_12(self):
        assert len(all_indicators()) == 12

    def test_returns_fingerprint_indicator_objects(self):
        for ind in all_indicators():
            assert isinstance(ind, FingerprintIndicator)

    def test_ids_match_expected(self):
        ids = [i.indicator_id for i in all_indicators()]
        for expected in INDICATOR_IDS:
            assert expected in ids

    def test_cached_same_object(self):
        first = all_indicators()
        second = all_indicators()
        assert first == second


class TestGetIndicator:
    def test_returns_correct_indicator(self):
        ind = get_indicator("DB-IND-001")
        assert ind is not None
        assert ind.indicator_id == "DB-IND-001"
        assert ind.name == "TEMPLATE_REPETITION"

    def test_case_insensitive_lookup(self):
        ind = get_indicator("db-ind-001")
        assert ind is not None
        assert ind.indicator_id == "DB-IND-001"

    def test_returns_none_for_unknown(self):
        assert get_indicator("DB-IND-999") is None
        assert get_indicator("UNKNOWN") is None

    def test_ind009_hashtag_density(self):
        ind = get_indicator("DB-IND-009")
        assert ind is not None
        assert ind.name == "HASHTAG_DENSITY_ANOMALY"

    def test_ind012_seed_blog(self):
        ind = get_indicator("DB-IND-012")
        assert ind is not None
        assert ind.name == "SEED_BLOG_PATTERN"


class TestIndicatorsByCategory:
    def test_content_category(self):
        inds = indicators_by_category("CONTENT")
        assert len(inds) >= 3
        for ind in inds:
            assert ind.category == "CONTENT"

    def test_timing_category(self):
        inds = indicators_by_category("TIMING")
        assert len(inds) >= 2
        for ind in inds:
            assert ind.category == "TIMING"

    def test_account_category(self):
        inds = indicators_by_category("ACCOUNT")
        assert len(inds) >= 2

    def test_network_category(self):
        inds = indicators_by_category("NETWORK")
        assert len(inds) >= 2

    def test_case_insensitive(self):
        lower = indicators_by_category("content")
        upper = indicators_by_category("CONTENT")
        assert len(lower) == len(upper)

    def test_unknown_category_returns_empty(self):
        assert indicators_by_category("UNKNOWN") == []

    def test_all_categories_sum_to_12(self):
        total = sum(
            len(indicators_by_category(cat))
            for cat in ["CONTENT", "TIMING", "ACCOUNT", "NETWORK"]
        )
        assert total == 12


class TestDemoSets:
    def test_returns_all_set_names(self):
        sets = all_demo_sets()
        for name in DEMO_SET_NAMES:
            assert name in sets

    def test_values_are_content_sample_lists(self):
        for name, samples in all_demo_sets().items():
            assert isinstance(samples, list)
            for s in samples:
                assert isinstance(s, ContentSample)

    def test_each_set_has_five_samples(self):
        for name, samples in all_demo_sets().items():
            assert len(samples) == 5, f"Set '{name}' has {len(samples)} samples"

    def test_demo_set_names_returns_list(self):
        names = demo_set_names()
        assert isinstance(names, list)
        assert len(names) == 3

    def test_get_demo_set_alpha7(self):
        samples = get_demo_set("alpha-7")
        assert samples is not None
        assert len(samples) == 5

    def test_get_demo_set_organic(self):
        samples = get_demo_set("organic-baseline")
        assert samples is not None

    def test_get_demo_set_borderline(self):
        samples = get_demo_set("borderline-medium")
        assert samples is not None

    def test_get_demo_set_unknown_returns_none(self):
        assert get_demo_set("nonexistent-set") is None

    def test_alpha7_samples_are_content_samples(self):
        samples = get_demo_set("alpha-7")
        for s in samples:
            assert isinstance(s, ContentSample)
            assert s.sample_id.startswith("s1_")

    def test_organic_sample_ids(self):
        samples = get_demo_set("organic-baseline")
        ids = [s.sample_id for s in samples]
        assert all(sid.startswith("s2_") for sid in ids)

    def test_borderline_sample_ids(self):
        samples = get_demo_set("borderline-medium")
        ids = [s.sample_id for s in samples]
        assert all(sid.startswith("s3_") for sid in ids)

    def test_alpha7_hashtag_lists(self):
        samples = get_demo_set("alpha-7")
        for s in samples:
            assert len(s.hashtags) == 12

    def test_organic_low_hashtags(self):
        samples = get_demo_set("organic-baseline")
        for s in samples:
            assert len(s.hashtags) <= 3

    def test_alpha7_shared_by_populated(self):
        samples = get_demo_set("alpha-7")
        for s in samples:
            assert s.shared_by_in_set is not None
            assert len(s.shared_by_in_set) == 4
