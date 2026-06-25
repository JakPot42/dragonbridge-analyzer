"""Deterministic content analysis engine -- P68 Dragonbridge Analyzer.

All checks are deterministic (no AI calls). Every CheckResult cites the
specific public report that documented the behavioral indicator.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta

from config import (
    AMPLIFICATION_RATIO_THRESHOLD,
    AI_PHRASING_THRESHOLD,
    AUTO_SCHEDULER_MIN_POSTS,
    AUTO_SCHEDULER_MODE_BUCKET,
    AUTO_SCHEDULER_MODE_RATIO,
    ATTRIBUTION_DISCLAIMER,
    CIB_GENERIC_PHRASES,
    CLUSTERING_MIN_ACCOUNTS,
    CLUSTERING_WINDOW_DAYS,
    DOMAIN_AGE_THRESHOLD_MONTHS,
    ENGAGEMENT_RATIO_MIN,
    HASHTAG_COUNT_THRESHOLD,
    MULTILINGUAL_TIME_WINDOW,
    ORIGINAL_CONTENT_THRESHOLD,
    RECYCLING_HIGH,
    RECYCLING_LOW,
    TEMPLATE_SIMILARITY_THRESHOLD,
    TIER_THRESHOLDS,
    VELOCITY_HASHTAG_THRESHOLD,
    VELOCITY_TIME_WINDOW,
)
from fingerprint_db import get_indicator
from models import AnalysisReport, CheckResult, ContentSample


# ---------------------------------------------------------------------------
# Text similarity helpers
# ---------------------------------------------------------------------------

def _bigrams(text: str) -> set[tuple[str, str]]:
    words = text.lower().split()
    return {(words[i], words[i + 1]) for i in range(len(words) - 1)} if len(words) > 1 else set()


def _jaccard_text(a: str, b: str) -> float:
    ba, bb = _bigrams(a), _bigrams(b)
    if not ba and not bb:
        return 1.0
    if not ba or not bb:
        return 0.0
    return len(ba & bb) / len(ba | bb)


def _jaccard_hashtags(a: list[str], b: list[str]) -> float:
    sa = {h.lower() for h in a}
    sb = {h.lower() for h in b}
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def _parse_ts(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def _parse_date(d: str) -> datetime:
    return datetime.strptime(d, "%Y-%m-%d")


# ---------------------------------------------------------------------------
# Individual indicator checks
# ---------------------------------------------------------------------------

def _cite(indicator_id: str) -> str:
    ind = get_indicator(indicator_id)
    return ind.source_citation if ind else indicator_id


def _result(
    indicator_id: str,
    matched: bool,
    data_available: bool,
    evidence: str,
) -> CheckResult:
    ind = get_indicator(indicator_id)
    name = ind.name if ind else indicator_id
    category = ind.category if ind else "UNKNOWN"
    citation = ind.source_citation if ind else ""
    return CheckResult(
        indicator_id=indicator_id,
        indicator_name=name,
        category=category,
        matched=matched,
        data_available=data_available,
        evidence=evidence,
        source_citation=citation,
    )


def check_template_repetition(samples: list[ContentSample]) -> CheckResult:
    iid = "DB-IND-001"
    if len(samples) < 2:
        return _result(iid, False, False, "Fewer than 2 samples; cannot compare")

    best_pair: tuple[str, str] = ("", "")
    best_sim = 0.0
    for i in range(len(samples)):
        for j in range(i + 1, len(samples)):
            sim = _jaccard_text(samples[i].text, samples[j].text)
            if sim > best_sim:
                best_sim = sim
                best_pair = (samples[i].sample_id, samples[j].sample_id)

    if best_sim > TEMPLATE_SIMILARITY_THRESHOLD:
        return _result(
            iid, True, True,
            f"Max Jaccard {best_sim:.3f} (>{TEMPLATE_SIMILARITY_THRESHOLD}) "
            f"between {best_pair[0]} and {best_pair[1]}",
        )
    return _result(
        iid, False, True,
        f"Max pairwise Jaccard {best_sim:.3f} below threshold {TEMPLATE_SIMILARITY_THRESHOLD}",
    )


def check_cross_platform_velocity(samples: list[ContentSample]) -> CheckResult:
    iid = "DB-IND-002"
    timed = [s for s in samples if s.timestamp is not None]
    platforms = {s.platform for s in timed}
    if len(platforms) < 2:
        return _result(iid, False, True, "All samples on same platform; not cross-platform")

    for i in range(len(timed)):
        for j in range(i + 1, len(timed)):
            si, sj = timed[i], timed[j]
            if si.platform == sj.platform:
                continue
            delta = abs((_parse_ts(sj.timestamp) - _parse_ts(si.timestamp)).total_seconds())
            ht_sim = _jaccard_hashtags(si.hashtags, sj.hashtags)
            if delta < VELOCITY_TIME_WINDOW and ht_sim > VELOCITY_HASHTAG_THRESHOLD:
                return _result(
                    iid, True, True,
                    f"{si.sample_id}({si.platform}) and {sj.sample_id}({sj.platform}) "
                    f"delta {int(delta)}s, hashtag Jaccard {ht_sim:.3f}",
                )

    return _result(
        iid, False, True,
        f"No cross-platform pair within {VELOCITY_TIME_WINDOW}s with hashtag Jaccard "
        f">{VELOCITY_HASHTAG_THRESHOLD}",
    )


def check_account_creation_clustering(samples: list[ContentSample]) -> CheckResult:
    iid = "DB-IND-003"
    dated = [s for s in samples if s.account_created_date is not None]
    if len(dated) < CLUSTERING_MIN_ACCOUNTS:
        return _result(
            iid, False, False,
            f"Fewer than {CLUSTERING_MIN_ACCOUNTS} samples have account_created_date",
        )

    dates = sorted(
        [(s, _parse_date(s.account_created_date)) for s in dated],
        key=lambda x: x[1],
    )
    window = timedelta(days=CLUSTERING_WINDOW_DAYS)
    for i in range(len(dates)):
        in_window = [
            d for d in dates if dates[i][1] <= d[1] <= dates[i][1] + window
        ]
        if len(in_window) >= CLUSTERING_MIN_ACCOUNTS:
            ids = [s.sample_id for s, _ in in_window]
            span = (in_window[-1][1] - in_window[0][1]).days
            return _result(
                iid, True, True,
                f"{len(in_window)} accounts within {span}-day window "
                f"(threshold {CLUSTERING_WINDOW_DAYS} days): {', '.join(ids)}",
            )

    dates_str = [s.account_created_date for s, _ in dates]
    return _result(
        iid, False, True,
        f"No {CLUSTERING_MIN_ACCOUNTS}+ accounts within any {CLUSTERING_WINDOW_DAYS}-day window. "
        f"Dates: {', '.join(dates_str)}",
    )


def check_engagement_ratio_anomaly(samples: list[ContentSample]) -> CheckResult:
    iid = "DB-IND-004"
    measurable = [
        s for s in samples
        if s.follower_count is not None
        and s.engagement_count is not None
        and s.follower_count > 0
    ]
    if not measurable:
        return _result(iid, False, False, "No samples have follower_count and engagement_count")

    low = [
        (s, s.engagement_count / s.follower_count)
        for s in measurable
        if s.engagement_count / s.follower_count < ENGAGEMENT_RATIO_MIN
    ]
    if low:
        worst = min(low, key=lambda x: x[1])
        ids = [s.sample_id for s, _ in low]
        return _result(
            iid, True, True,
            f"{len(low)} of {len(measurable)} accounts below {ENGAGEMENT_RATIO_MIN:.1%} "
            f"engagement threshold. Worst: {worst[0].sample_id} "
            f"({worst[1]:.4%} = {worst[0].engagement_count}/{worst[0].follower_count}). "
            f"Flagged: {', '.join(ids)}",
        )

    all_ratios = [
        f"{s.sample_id}:{s.engagement_count/s.follower_count:.4%}"
        for s in measurable
    ]
    return _result(
        iid, False, True,
        f"All engagement ratios above {ENGAGEMENT_RATIO_MIN:.1%}: {', '.join(all_ratios)}",
    )


def check_content_recycling_variation(samples: list[ContentSample]) -> CheckResult:
    iid = "DB-IND-005"
    if len(samples) < 2:
        return _result(iid, False, False, "Fewer than 2 samples; cannot compare")

    # Text-based recycling: Jaccard in [RECYCLING_LOW, RECYCLING_HIGH]
    best_pair: tuple[str, str] = ("", "")
    best_sim = 0.0
    for i in range(len(samples)):
        for j in range(i + 1, len(samples)):
            sim = _jaccard_text(samples[i].text, samples[j].text)
            if RECYCLING_LOW <= sim <= RECYCLING_HIGH and sim > best_sim:
                best_sim = sim
                best_pair = (samples[i].sample_id, samples[j].sample_id)

    if best_sim > 0:
        return _result(
            iid, True, True,
            f"Text recycling pair: {best_pair[0]}/{best_pair[1]} Jaccard {best_sim:.3f} "
            f"in [{RECYCLING_LOW},{RECYCLING_HIGH}]",
        )

    # Cross-language hashtag overlap as alternate recycling signal
    for i in range(len(samples)):
        for j in range(i + 1, len(samples)):
            si, sj = samples[i], samples[j]
            if si.language == sj.language:
                continue
            ht = _jaccard_hashtags(si.hashtags, sj.hashtags)
            if ht > VELOCITY_HASHTAG_THRESHOLD:
                return _result(
                    iid, True, True,
                    f"Cross-language recycling: {si.sample_id}({si.language}) and "
                    f"{sj.sample_id}({sj.language}) hashtag Jaccard {ht:.3f}",
                )

    return _result(
        iid, False, True,
        f"No text pairs in [{RECYCLING_LOW},{RECYCLING_HIGH}] Jaccard range "
        "and no cross-language hashtag overlap detected",
    )


def check_multilingual_simultaneity(samples: list[ContentSample]) -> CheckResult:
    iid = "DB-IND-006"
    timed = [s for s in samples if s.timestamp is not None]
    languages = {s.language for s in timed if s.language != "unknown"}
    if len(languages) < 2:
        return _result(
            iid, False, True,
            f"Only 1 language detected ({', '.join(languages) or 'unknown'}); "
            "not multilingual",
        )

    window = timedelta(seconds=MULTILINGUAL_TIME_WINDOW)
    for i in range(len(timed)):
        for j in range(i + 1, len(timed)):
            si, sj = timed[i], timed[j]
            if si.language == sj.language or si.language == "unknown" or sj.language == "unknown":
                continue
            delta = abs((_parse_ts(sj.timestamp) - _parse_ts(si.timestamp)).total_seconds())
            if delta <= MULTILINGUAL_TIME_WINDOW:
                return _result(
                    iid, True, True,
                    f"Languages '{si.language}' ({si.sample_id}) and '{sj.language}' "
                    f"({sj.sample_id}) within {int(delta)}s "
                    f"(threshold {MULTILINGUAL_TIME_WINDOW}s)",
                )

    return _result(
        iid, False, True,
        f"Languages present: {', '.join(sorted(languages))}. "
        f"No cross-language pair within {MULTILINGUAL_TIME_WINDOW}s",
    )


def check_auto_scheduler_signature(samples: list[ContentSample]) -> CheckResult:
    iid = "DB-IND-007"
    timed = sorted(
        [s for s in samples if s.timestamp is not None],
        key=lambda s: s.timestamp,
    )
    if len(timed) < AUTO_SCHEDULER_MIN_POSTS:
        return _result(
            iid, False, False,
            f"Only {len(timed)} samples with timestamps; "
            f"need {AUTO_SCHEDULER_MIN_POSTS}",
        )

    intervals = [
        int(abs((_parse_ts(timed[k + 1].timestamp) - _parse_ts(timed[k].timestamp)).total_seconds()))
        for k in range(len(timed) - 1)
    ]

    buckets: dict[int, int] = {}
    for iv in intervals:
        key = (iv // AUTO_SCHEDULER_MODE_BUCKET) * AUTO_SCHEDULER_MODE_BUCKET
        buckets[key] = buckets.get(key, 0) + 1

    mode_key = max(buckets, key=buckets.__getitem__)
    mode_count = buckets[mode_key]
    mode_ratio = mode_count / len(intervals)

    if mode_key > 0 and mode_ratio >= AUTO_SCHEDULER_MODE_RATIO:
        return _result(
            iid, True, True,
            f"Mode interval {mode_key}s ({mode_key // 3600}h {(mode_key % 3600) // 60}m), "
            f"frequency {mode_count}/{len(intervals)} = {mode_ratio:.0%} "
            f"(threshold {AUTO_SCHEDULER_MODE_RATIO:.0%})",
        )

    return _result(
        iid, False, True,
        f"No regular interval pattern. Mode {mode_key}s at "
        f"{mode_ratio:.0%} frequency (need {AUTO_SCHEDULER_MODE_RATIO:.0%}). "
        f"Intervals: {intervals}",
    )


def check_zero_original_content(samples: list[ContentSample]) -> CheckResult:
    iid = "DB-IND-008"
    with_data = [s for s in samples if s.is_repost is not None]
    if not with_data:
        return _result(iid, False, False, "No samples have is_repost data")

    original = [s for s in with_data if not s.is_repost]
    ratio = len(original) / len(with_data)

    if ratio < ORIGINAL_CONTENT_THRESHOLD:
        reposts = [s.sample_id for s in with_data if s.is_repost]
        return _result(
            iid, True, True,
            f"Original content ratio {ratio:.1%} (threshold <{ORIGINAL_CONTENT_THRESHOLD:.0%}). "
            f"{len(reposts)} of {len(with_data)} are reposts: {', '.join(reposts)}",
        )
    return _result(
        iid, False, True,
        f"Original content ratio {ratio:.1%} above threshold {ORIGINAL_CONTENT_THRESHOLD:.0%}",
    )


def check_hashtag_density_anomaly(samples: list[ContentSample]) -> CheckResult:
    iid = "DB-IND-009"
    if not samples:
        return _result(iid, False, False, "No samples provided")

    over_threshold = [
        s for s in samples if len(s.hashtags) > HASHTAG_COUNT_THRESHOLD
    ]
    if over_threshold:
        worst = max(over_threshold, key=lambda s: len(s.hashtags))
        ids = [s.sample_id for s in over_threshold]
        return _result(
            iid, True, True,
            f"{len(over_threshold)} samples exceed {HASHTAG_COUNT_THRESHOLD} hashtag threshold. "
            f"Max: {worst.sample_id} with {len(worst.hashtags)} hashtags. "
            f"Samples: {', '.join(ids)}",
        )

    counts = [f"{s.sample_id}:{len(s.hashtags)}" for s in samples]
    return _result(
        iid, False, True,
        f"All samples at or below {HASHTAG_COUNT_THRESHOLD} hashtag threshold: "
        f"{', '.join(counts)}",
    )


def check_ai_generic_phrasing(samples: list[ContentSample]) -> CheckResult:
    iid = "DB-IND-010"
    if not samples:
        return _result(iid, False, False, "No samples provided")

    all_text = " ".join(s.text for s in samples).lower()
    matched_phrases = [p for p in CIB_GENERIC_PHRASES if p in all_text]

    if len(matched_phrases) >= AI_PHRASING_THRESHOLD:
        return _result(
            iid, True, True,
            f"{len(matched_phrases)} documented CIB generic phrases detected "
            f"(threshold >= {AI_PHRASING_THRESHOLD}): "
            f"{'; '.join(matched_phrases[:5])}{'...' if len(matched_phrases) > 5 else ''}",
        )
    return _result(
        iid, False, True,
        f"Only {len(matched_phrases)} documented generic phrases found "
        f"(need >= {AI_PHRASING_THRESHOLD}): "
        f"{', '.join(matched_phrases) if matched_phrases else 'none'}",
    )


def check_inauthentic_amplification_network(samples: list[ContentSample]) -> CheckResult:
    iid = "DB-IND-011"
    n = len(samples)
    if n < 2:
        return _result(iid, False, False, "Fewer than 2 samples; cannot assess network")

    network_data = [s for s in samples if s.shared_by_in_set is not None]
    if not network_data:
        return _result(
            iid, False, False,
            "No samples have shared_by_in_set data (set to [] if no sharing found)",
        )

    sample_ids = {s.sample_id for s in samples}
    total_within = sum(
        len([sid for sid in (s.shared_by_in_set or []) if sid in sample_ids])
        for s in network_data
    )
    max_possible = n * (n - 1)
    ratio = total_within / max_possible if max_possible > 0 else 0.0

    if ratio > AMPLIFICATION_RATIO_THRESHOLD:
        return _result(
            iid, True, True,
            f"Cross-reference ratio {ratio:.2f} ({total_within}/{max_possible} possible) "
            f"exceeds threshold {AMPLIFICATION_RATIO_THRESHOLD}",
        )
    return _result(
        iid, False, True,
        f"Cross-reference ratio {ratio:.2f} ({total_within}/{max_possible}) "
        f"below threshold {AMPLIFICATION_RATIO_THRESHOLD}",
    )


def check_seed_blog_pattern(samples: list[ContentSample]) -> CheckResult:
    iid = "DB-IND-012"
    with_domain = [
        s for s in samples
        if s.source_domain is not None and s.domain_age_months is not None
    ]
    if not with_domain:
        return _result(
            iid, False, False,
            "No samples have both source_domain and domain_age_months data",
        )

    young = [s for s in with_domain if s.domain_age_months < DOMAIN_AGE_THRESHOLD_MONTHS]
    if young:
        worst = min(young, key=lambda s: s.domain_age_months)
        return _result(
            iid, True, True,
            f"{len(young)} sample(s) from domain(s) younger than "
            f"{DOMAIN_AGE_THRESHOLD_MONTHS} months. "
            f"Youngest: '{worst.source_domain}' ({worst.domain_age_months} months old). "
            f"Samples: {', '.join(s.sample_id for s in young)}",
        )

    domains = list({s.source_domain for s in with_domain})
    return _result(
        iid, False, True,
        f"All source domains >= {DOMAIN_AGE_THRESHOLD_MONTHS} months old: "
        f"{', '.join(domains[:3])}",
    )


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

_CHECKS = [
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
]


def _tier_from_score(score: float) -> str:
    if score >= TIER_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    if score >= TIER_THRESHOLDS["HIGH"]:
        return "HIGH"
    if score >= TIER_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    if score >= TIER_THRESHOLDS["LOW"]:
        return "LOW"
    return "MINIMAL"


def analyze_content_set(
    samples: list[ContentSample],
    set_name: str = "Unnamed Set",
    prepared_date: str = "",
) -> AnalysisReport:
    from datetime import date

    if not prepared_date:
        prepared_date = date.today().isoformat()

    results = [fn(samples) for fn in _CHECKS]

    assessable = [r for r in results if r.data_available]
    matched = [r for r in assessable if r.matched]

    assessable_count = len(assessable)
    matched_count = len(matched)
    score = (matched_count / assessable_count * 100.0) if assessable_count > 0 else 0.0
    tier = _tier_from_score(score)

    return AnalysisReport(
        set_name=set_name,
        prepared_date=prepared_date,
        sample_count=len(samples),
        check_results=results,
        matched_count=matched_count,
        assessable_count=assessable_count,
        score=round(score, 1),
        tier=tier,
        disclaimer=ATTRIBUTION_DISCLAIMER,
    )
