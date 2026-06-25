"""Configuration -- Dragonbridge/Spamouflage Behavioral Fingerprint Analyzer (P68)."""
from __future__ import annotations

DEMO_MODE = True
CLAUDE_MODEL = "claude-haiku-4-5-20251001"

INDICATOR_COUNT = 12
INDICATOR_IDS = [f"DB-IND-{i:03d}" for i in range(1, 13)]

INDICATOR_CATEGORIES = ["CONTENT", "TIMING", "ACCOUNT", "NETWORK"]

# ---------------------------------------------------------------------------
# Tier thresholds (score = matched_count / assessable_count * 100)
# 8/12 = 66.7  -> CRITICAL
# 6/12 = 50.0  -> HIGH
# 4/12 = 33.3  -> MEDIUM
# 2/12 = 16.7  -> LOW
# 0-1/12       -> MINIMAL
# ---------------------------------------------------------------------------
TIER_THRESHOLDS: dict[str, float] = {
    "CRITICAL": 66.0,
    "HIGH":     50.0,
    "MEDIUM":   33.0,
    "LOW":      16.0,
}
TIER_ORDER = ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
TIER_COLORS: dict[str, str] = {
    "CRITICAL": "red",
    "HIGH":     "yellow",
    "MEDIUM":   "blue",
    "LOW":      "green",
    "MINIMAL":  "green",
}

# ---------------------------------------------------------------------------
# Indicator-specific thresholds
# ---------------------------------------------------------------------------

# DB-IND-001: TEMPLATE_REPETITION
TEMPLATE_SIMILARITY_THRESHOLD = 0.85  # Jaccard on word bigrams

# DB-IND-002: CROSS_PLATFORM_VELOCITY
VELOCITY_TIME_WINDOW = 1800           # seconds (30 minutes)
VELOCITY_HASHTAG_THRESHOLD = 0.80     # hashtag Jaccard for cross-language pairs

# DB-IND-003: ACCOUNT_CREATION_CLUSTERING
CLUSTERING_WINDOW_DAYS = 7
CLUSTERING_MIN_ACCOUNTS = 3

# DB-IND-004: ENGAGEMENT_RATIO_ANOMALY
ENGAGEMENT_RATIO_MIN = 0.001          # below 0.1% triggers

# DB-IND-005: CONTENT_RECYCLING_VARIATION
RECYCLING_LOW = 0.60
RECYCLING_HIGH = 0.84

# DB-IND-006: MULTILINGUAL_SIMULTANEITY
MULTILINGUAL_TIME_WINDOW = 7200       # seconds (2 hours)

# DB-IND-007: AUTO_SCHEDULER_SIGNATURE
AUTO_SCHEDULER_MIN_POSTS = 5
AUTO_SCHEDULER_MODE_RATIO = 0.60      # fraction of intervals matching mode bucket
AUTO_SCHEDULER_MODE_BUCKET = 600      # seconds (10-minute bucket)

# DB-IND-008: ZERO_ORIGINAL_CONTENT
ORIGINAL_CONTENT_THRESHOLD = 0.05    # below 5% original triggers

# DB-IND-009: HASHTAG_DENSITY_ANOMALY
HASHTAG_COUNT_THRESHOLD = 8          # strictly greater than 8 triggers

# DB-IND-010: AI_GENERIC_PHRASING
AI_PHRASING_THRESHOLD = 2            # >= 2 documented phrases across all samples

# DB-IND-011: INAUTHENTIC_AMPLIFICATION_NETWORK
AMPLIFICATION_RATIO_THRESHOLD = 0.80

# DB-IND-012: SEED_BLOG_PATTERN
DOMAIN_AGE_THRESHOLD_MONTHS = 12     # strictly less than 12 months triggers

# ---------------------------------------------------------------------------
# Documented CIB generic phrases (from Meta ATR Aug 2022, Mar 2023, Aug 2023)
# Used for DB-IND-010 AI_GENERIC_PHRASING heuristic
# ---------------------------------------------------------------------------
CIB_GENERIC_PHRASES: list[str] = [
    "the united states is spreading",
    "the united states is attempting to",
    "western media spreads disinformation",
    "western media's double standards",
    "western media double standards",
    "china's peaceful rise",
    "china's peaceful development",
    "the international community should",
    "the international community must",
    "democratic hypocrisy",
    "mainstream media bias",
    "protect national sovereignty",
    "global south solidarity",
    "american hegemony",
    "american imperialism",
]

# ---------------------------------------------------------------------------
# Non-attribution disclaimer -- included in all output
# ---------------------------------------------------------------------------
ATTRIBUTION_DISCLAIMER = (
    "PATTERN IDENTIFICATION ONLY -- NOT AN ATTRIBUTION CLAIM. "
    "This analysis identifies patterns consistent with documented CIB "
    "from public takedown reports. It does not identify any actor, "
    "government, or organization as responsible, and cites only public reports."
)

DEMO_SET_NAMES = ["alpha-7", "organic-baseline", "borderline-medium"]
DEMO_SET_HIGH = "alpha-7"
