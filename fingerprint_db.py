"""Fingerprint indicator database access -- P68 Dragonbridge Analyzer."""
from __future__ import annotations

from models import FingerprintIndicator, ContentSample
from seed_data import FINGERPRINT_INDICATORS, DEMO_SETS


class FingerprintDBError(Exception):
    pass


_INDICATOR_CACHE: list[FingerprintIndicator] | None = None
_DEMO_CACHE: dict[str, list[ContentSample]] | None = None


def _build_indicator(raw: dict) -> FingerprintIndicator:
    return FingerprintIndicator(
        indicator_id=raw["indicator_id"],
        name=raw["name"],
        category=raw["category"],
        description=raw["description"],
        source_report=raw["source_report"],
        source_url=raw["source_url"],
        source_citation=raw["source_citation"],
        threshold_description=raw["threshold_description"],
        check_requires=list(raw["check_requires"]),
    )


def _build_sample(raw: dict) -> ContentSample:
    return ContentSample(
        sample_id=raw["sample_id"],
        text=raw["text"],
        platform=raw["platform"],
        language=raw["language"],
        timestamp=raw.get("timestamp"),
        hashtags=list(raw.get("hashtags", [])),
        follower_count=raw.get("follower_count"),
        engagement_count=raw.get("engagement_count"),
        is_repost=raw.get("is_repost"),
        source_domain=raw.get("source_domain"),
        domain_age_months=raw.get("domain_age_months"),
        account_created_date=raw.get("account_created_date"),
        shared_by_in_set=raw.get("shared_by_in_set"),
    )


def all_indicators() -> list[FingerprintIndicator]:
    global _INDICATOR_CACHE
    if _INDICATOR_CACHE is None:
        _INDICATOR_CACHE = [_build_indicator(r) for r in FINGERPRINT_INDICATORS]
    return list(_INDICATOR_CACHE)


def get_indicator(indicator_id: str) -> FingerprintIndicator | None:
    for ind in all_indicators():
        if ind.indicator_id.upper() == indicator_id.upper():
            return ind
    return None


def indicators_by_category(category: str) -> list[FingerprintIndicator]:
    return [i for i in all_indicators() if i.category.upper() == category.upper()]


def all_demo_sets() -> dict[str, list[ContentSample]]:
    global _DEMO_CACHE
    if _DEMO_CACHE is None:
        _DEMO_CACHE = {
            name: [_build_sample(r) for r in samples]
            for name, samples in DEMO_SETS.items()
        }
    return dict(_DEMO_CACHE)


def get_demo_set(name: str) -> list[ContentSample] | None:
    return all_demo_sets().get(name)


def demo_set_names() -> list[str]:
    return list(all_demo_sets().keys())
