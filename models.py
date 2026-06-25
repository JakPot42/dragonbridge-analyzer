"""Data models -- Dragonbridge/Spamouflage Behavioral Fingerprint Analyzer (P68)."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FingerprintIndicator:
    indicator_id: str           # "DB-IND-001"
    name: str                   # "TEMPLATE_REPETITION"
    category: str               # CONTENT / TIMING / ACCOUNT / NETWORK
    description: str
    source_report: str          # short label, e.g. "Meta ATR August 2022"
    source_url: str
    source_citation: str        # full bibliographic citation
    threshold_description: str
    check_requires: list[str]   # ["multiple_samples", "timestamps", "account_metadata", ...]


@dataclass
class ContentSample:
    sample_id: str
    text: str
    platform: str               # "facebook" / "twitter" / "youtube" / "telegram" / "unknown"
    language: str               # "en" / "zh" / "ar" / "unknown"
    timestamp: str | None       # ISO 8601 datetime string or None
    hashtags: list[str]
    follower_count: int | None
    engagement_count: int | None  # likes + shares + comments
    is_repost: bool | None
    source_domain: str | None
    domain_age_months: int | None
    account_created_date: str | None  # ISO date "YYYY-MM-DD"
    # None = data not provided; [] = data checked, no within-set sharing found
    shared_by_in_set: list[str] | None = field(default=None)


@dataclass
class CheckResult:
    indicator_id: str
    indicator_name: str
    category: str
    matched: bool
    data_available: bool        # False = insufficient data to assess
    evidence: str               # what matched (or why not / why no data)
    source_citation: str


@dataclass
class AnalysisReport:
    set_name: str
    prepared_date: str
    sample_count: int
    check_results: list[CheckResult]
    matched_count: int
    assessable_count: int       # indicators where data_available=True
    score: float                # matched_count / assessable_count * 100
    tier: str                   # CRITICAL / HIGH / MEDIUM / LOW / MINIMAL
    brief_text: str = ""
    disclaimer: str = ""
