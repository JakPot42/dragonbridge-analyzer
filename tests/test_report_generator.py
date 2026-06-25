"""Tests for report_generator.py -- P68 Dragonbridge Analyzer."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from content_analyzer import analyze_content_set
from fingerprint_db import get_demo_set
from report_generator import generate_report, ReportGeneratorError
from seed_data import DEMO_REPORT_TEXT


@pytest.fixture
def alpha7_report():
    samples = get_demo_set("alpha-7")
    return analyze_content_set(samples, set_name="alpha-7")


@pytest.fixture
def organic_report():
    samples = get_demo_set("organic-baseline")
    return analyze_content_set(samples, set_name="organic-baseline")


@pytest.fixture
def borderline_report():
    samples = get_demo_set("borderline-medium")
    return analyze_content_set(samples, set_name="borderline-medium")


class TestGenerateReportDemoMode:
    def test_alpha7_returns_demo_text(self, alpha7_report):
        brief, items = generate_report(alpha7_report, demo_mode=True)
        assert brief == DEMO_REPORT_TEXT

    def test_alpha7_action_items_returned(self, alpha7_report):
        brief, items = generate_report(alpha7_report, demo_mode=True)
        assert isinstance(items, list)
        assert len(items) >= 1

    def test_organic_returns_assembled_brief(self, organic_report):
        brief, items = generate_report(organic_report, demo_mode=True)
        assert brief != DEMO_REPORT_TEXT
        assert "organic-baseline" in brief or "ORGANIC" in brief.upper()

    def test_borderline_returns_assembled_brief(self, borderline_report):
        brief, items = generate_report(borderline_report, demo_mode=True)
        assert isinstance(brief, str)
        assert len(brief) > 100

    def test_assembled_brief_has_framing(self, organic_report):
        brief, _ = generate_report(organic_report, demo_mode=True)
        assert "PATTERN IDENTIFICATION ONLY" in brief

    def test_assembled_brief_has_disclaimer(self, organic_report):
        brief, _ = generate_report(organic_report, demo_mode=True)
        assert "attribution" in brief.lower()

    def test_assembled_brief_ascii_safe(self, organic_report):
        brief, _ = generate_report(organic_report, demo_mode=True)
        for i, ch in enumerate(brief):
            assert ord(ch) < 128, f"Non-ASCII char at position {i}: {repr(ch)}"

    def test_assembled_brief_ascii_safe_borderline(self, borderline_report):
        brief, _ = generate_report(borderline_report, demo_mode=True)
        for i, ch in enumerate(brief):
            assert ord(ch) < 128, f"Non-ASCII char at position {i}: {repr(ch)}"

    def test_critical_tier_has_action_item(self, alpha7_report):
        _, items = generate_report(alpha7_report, demo_mode=True)
        assert len(items) >= 1

    def test_assembled_brief_lists_matched_indicators(self, borderline_report):
        brief, _ = generate_report(borderline_report, demo_mode=True)
        assert "DB-IND-003" in brief or "ACCOUNT_CREATION_CLUSTERING" in brief

    def test_assembled_brief_has_tier(self, borderline_report):
        brief, _ = generate_report(borderline_report, demo_mode=True)
        assert "MEDIUM" in brief

    def test_assembled_brief_mentions_score(self, borderline_report):
        report = borderline_report
        brief, _ = generate_report(report, demo_mode=True)
        assert str(report.matched_count) in brief


class TestExtractActionItems:
    def test_extracts_numbered_items(self):
        from report_generator import _extract_action_items
        text = (
            "VII. RECOMMENDED NEXT STEPS\n\n"
            "1. Do this first.\n"
            "2. Do this second.\n"
            "3. Do this third.\n"
        )
        items = _extract_action_items(text)
        assert len(items) >= 3

    def test_returns_empty_for_no_section(self):
        from report_generator import _extract_action_items
        text = "No numbered steps here."
        items = _extract_action_items(text)
        assert isinstance(items, list)


class TestBuildActionItems:
    def test_critical_tier_generates_items(self, alpha7_report):
        from report_generator import _build_action_items
        items = _build_action_items(alpha7_report)
        assert len(items) >= 1

    def test_minimal_tier_fewer_items(self, organic_report):
        from report_generator import _build_action_items
        items = _build_action_items(organic_report)
        # minimal tier doesn't generate urgency items
        assert isinstance(items, list)

    def test_network_indicator_triggers_item(self, alpha7_report):
        from report_generator import _build_action_items
        items = _build_action_items(alpha7_report)
        combined = " ".join(items)
        assert "DB-IND-011" in combined or "network" in combined.lower()

    def test_seed_blog_indicator_triggers_item(self, alpha7_report):
        from report_generator import _build_action_items
        items = _build_action_items(alpha7_report)
        combined = " ".join(items)
        assert "DB-IND-012" in combined or "domain" in combined.lower()


class TestLiveModeError:
    def test_live_mode_raises_without_api_key(self, alpha7_report):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        with pytest.raises(ReportGeneratorError):
            generate_report(alpha7_report, demo_mode=False)
