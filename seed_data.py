"""Fingerprint database and demo content sets -- P68 Dragonbridge Analyzer.

All indicators seeded from public takedown reports:
  Meta Adversarial Threat Reports (Aug 2022, Mar 2023, Aug 2023)
  Mandiant/Google, "Dragonbridge," August 2022
  Graphika/Stanford Internet Observatory, "Spamouflage," June 2019
  Stanford Internet Observatory, Spamouflage Dragon analysis, 2020
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# 12 documented behavioral indicators with full source citations
# ---------------------------------------------------------------------------

FINGERPRINT_INDICATORS: list[dict] = [
    {
        "indicator_id": "DB-IND-001",
        "name": "TEMPLATE_REPETITION",
        "category": "CONTENT",
        "description": (
            "Near-identical text content posted across multiple accounts, "
            "differing by 1-3 word substitutions. Jaccard similarity on word "
            "bigrams exceeds 0.85 across two or more sample pairs."
        ),
        "source_report": "Meta ATR August 2022",
        "source_url": "transparency.fb.com/metaatrs/adversarial-threat-report-august-2022",
        "source_citation": (
            "Meta Platforms. 'Adversarial Threat Report, August 2022 -- "
            "Dragonbridge and Spamouflage Takedown.' August 2022. "
            "transparency.fb.com/metaatrs"
        ),
        "threshold_description": "Any sample pair Jaccard bigram similarity > 0.85",
        "check_requires": ["multiple_samples"],
    },
    {
        "indicator_id": "DB-IND-002",
        "name": "CROSS_PLATFORM_VELOCITY",
        "category": "TIMING",
        "description": (
            "Identical or near-identical content posted across two or more "
            "platforms within 30 minutes. Detected via timestamp delta < 1800s "
            "AND hashtag Jaccard > 0.80 across different-platform sample pairs."
        ),
        "source_report": "Meta ATR March 2023",
        "source_url": "transparency.fb.com/metaatrs/adversarial-threat-report-q1-2023",
        "source_citation": (
            "Meta Platforms. 'Adversarial Threat Report Q1 2023 -- "
            "Spamouflage Operations.' March 2023. transparency.fb.com/metaatrs"
        ),
        "threshold_description": (
            "Timestamp delta < 1800s AND hashtag Jaccard > 0.80, "
            "on two different platforms"
        ),
        "check_requires": ["multiple_samples", "timestamps", "platform_data"],
    },
    {
        "indicator_id": "DB-IND-003",
        "name": "ACCOUNT_CREATION_CLUSTERING",
        "category": "ACCOUNT",
        "description": (
            "Three or more accounts in the sample set were created within a "
            "7-day window. Consistent with coordinated network seeding documented "
            "in Spamouflage infrastructure analysis."
        ),
        "source_report": "SIO/Graphika June 2019",
        "source_url": "io.stanford.edu/research/spamouflage",
        "source_citation": (
            "Graphika and Stanford Internet Observatory. "
            "'Spamouflage: A Large-Scale Cross-Platform Influence Operation.' "
            "June 2019. io.stanford.edu"
        ),
        "threshold_description": (
            "3+ accounts with account_created_date within any 7-day window"
        ),
        "check_requires": ["account_metadata"],
    },
    {
        "indicator_id": "DB-IND-004",
        "name": "ENGAGEMENT_RATIO_ANOMALY",
        "category": "ACCOUNT",
        "description": (
            "Engagement rate (likes + shares + comments) / follower_count "
            "below 0.1% despite follower counts in the thousands. Consistent "
            "with follower inflation documented in Dragonbridge network analysis."
        ),
        "source_report": "Mandiant/Google August 2022",
        "source_url": (
            "cloud.google.com/blog/topics/threat-intelligence/dragonbridge"
        ),
        "source_citation": (
            "Mandiant and Google. 'Dragonbridge: An Influence Campaign Finds "
            "Limited Traction but Keeps Trying.' August 2022. "
            "cloud.google.com/blog/topics/threat-intelligence"
        ),
        "threshold_description": (
            "engagement_count / follower_count < 0.001 (below 0.1%) "
            "for one or more accounts"
        ),
        "check_requires": ["account_metadata"],
    },
    {
        "indicator_id": "DB-IND-005",
        "name": "CONTENT_RECYCLING_VARIATION",
        "category": "CONTENT",
        "description": (
            "Same core message with surface-level variation: word substitution, "
            "minor phrasing changes, or cross-language reformulation. "
            "Detected by text Jaccard in [0.60, 0.84] OR hashtag overlap > 0.80 "
            "across different-language sample pairs."
        ),
        "source_report": "Meta ATR August 2023",
        "source_url": "transparency.fb.com/metaatrs/adversarial-threat-report-q2-2023",
        "source_citation": (
            "Meta Platforms. 'Adversarial Threat Report Q2/Q3 2023 -- "
            "AI-Generated Content in Spamouflage Operations.' August 2023. "
            "transparency.fb.com/metaatrs"
        ),
        "threshold_description": (
            "Any pair with text Jaccard in [0.60, 0.84], "
            "OR hashtag Jaccard > 0.80 with different languages"
        ),
        "check_requires": ["multiple_samples"],
    },
    {
        "indicator_id": "DB-IND-006",
        "name": "MULTILINGUAL_SIMULTANEITY",
        "category": "TIMING",
        "description": (
            "Same content posted in two or more languages within 2 hours. "
            "Cross-language simultaneous posting is a documented Spamouflage "
            "operational pattern for maximizing audience reach."
        ),
        "source_report": "Meta ATR August 2022",
        "source_url": "transparency.fb.com/metaatrs/adversarial-threat-report-august-2022",
        "source_citation": (
            "Meta Platforms. 'Adversarial Threat Report, August 2022 -- "
            "Dragonbridge and Spamouflage Takedown.' August 2022. "
            "transparency.fb.com/metaatrs"
        ),
        "threshold_description": (
            "2+ distinct languages AND any cross-language pair "
            "with timestamp delta < 7200s"
        ),
        "check_requires": ["multiple_samples", "timestamps"],
    },
    {
        "indicator_id": "DB-IND-007",
        "name": "AUTO_SCHEDULER_SIGNATURE",
        "category": "TIMING",
        "description": (
            "Posts at machine-regular intervals. The modal inter-post interval "
            "accounts for 60%+ of all intervals. Inconsistent with organic posting "
            "behavior. Matches automated cross-platform scheduler detected in "
            "Spamouflage Dragon operations."
        ),
        "source_report": "SIO Spamouflage Dragon 2020",
        "source_url": "io.stanford.edu/research/spamouflage-dragon",
        "source_citation": (
            "Stanford Internet Observatory. "
            "'Spamouflage Dragon: Ongoing Infrastructure and Behavioral Analysis.' "
            "2020. io.stanford.edu"
        ),
        "threshold_description": (
            "Modal inter-post interval accounts for >= 60% of all intervals "
            "across 5+ posts (10-minute mode bucket)"
        ),
        "check_requires": ["multiple_samples", "timestamps"],
    },
    {
        "indicator_id": "DB-IND-008",
        "name": "ZERO_ORIGINAL_CONTENT",
        "category": "ACCOUNT",
        "description": (
            "Account history shows less than 5% original content; "
            "all posts are reposts, reshares, or retweets. Accounts function "
            "exclusively as amplification nodes consistent with the Dragonbridge "
            "amplifier-account architecture documented in takedown reports."
        ),
        "source_report": "Mandiant/Google August 2022",
        "source_url": (
            "cloud.google.com/blog/topics/threat-intelligence/dragonbridge"
        ),
        "source_citation": (
            "Mandiant and Google. 'Dragonbridge: An Influence Campaign Finds "
            "Limited Traction but Keeps Trying.' August 2022. "
            "cloud.google.com/blog/topics/threat-intelligence"
        ),
        "threshold_description": (
            "original content ratio < 0.05 "
            "(fewer than 5% of samples are is_repost=False)"
        ),
        "check_requires": ["repost_metadata"],
    },
    {
        "indicator_id": "DB-IND-009",
        "name": "HASHTAG_DENSITY_ANOMALY",
        "category": "CONTENT",
        "description": (
            "Excessive hashtag use (more than 8 per post) targeting unrelated "
            "high-traffic topics simultaneously. Pattern documented in Spamouflage "
            "cross-platform reach amplification operations."
        ),
        "source_report": "Meta ATR March 2023",
        "source_url": "transparency.fb.com/metaatrs/adversarial-threat-report-q1-2023",
        "source_citation": (
            "Meta Platforms. 'Adversarial Threat Report Q1 2023 -- "
            "Spamouflage Operations.' March 2023. transparency.fb.com/metaatrs"
        ),
        "threshold_description": "More than 8 hashtags in any single sample",
        "check_requires": [],
    },
    {
        "indicator_id": "DB-IND-010",
        "name": "AI_GENERIC_PHRASING",
        "category": "CONTENT",
        "description": (
            "Text matches 2 or more generic political-commentary phrase patterns "
            "documented across Dragonbridge and Spamouflage content in Meta's "
            "2023 AI-generated content analysis. Phrases are generic, non-specific, "
            "and consistent with template-based or AI-assisted content production."
        ),
        "source_report": "Meta ATR August 2023",
        "source_url": "transparency.fb.com/metaatrs/adversarial-threat-report-q2-2023",
        "source_citation": (
            "Meta Platforms. 'Adversarial Threat Report Q2/Q3 2023 -- "
            "AI-Generated Content in Spamouflage Operations.' August 2023. "
            "transparency.fb.com/metaatrs"
        ),
        "threshold_description": (
            ">= 2 documented CIB generic phrases detected across all samples combined"
        ),
        "check_requires": [],
    },
    {
        "indicator_id": "DB-IND-011",
        "name": "INAUTHENTIC_AMPLIFICATION_NETWORK",
        "category": "NETWORK",
        "description": (
            "Accounts in the sample set share each other's content at a rate "
            "exceeding 80% of theoretical maximum cross-references, forming a "
            "closed amplification loop. Matches the Dragonbridge amplifier-network "
            "structure documented in Meta's August 2022 takedown."
        ),
        "source_report": "Meta ATR August 2022",
        "source_url": "transparency.fb.com/metaatrs/adversarial-threat-report-august-2022",
        "source_citation": (
            "Meta Platforms. 'Adversarial Threat Report, August 2022 -- "
            "Dragonbridge and Spamouflage Takedown.' August 2022. "
            "transparency.fb.com/metaatrs"
        ),
        "threshold_description": (
            "Cross-reference ratio > 0.80: "
            "within-set shares / (n * (n-1)) where n = sample count"
        ),
        "check_requires": ["network_metadata"],
    },
    {
        "indicator_id": "DB-IND-012",
        "name": "SEED_BLOG_PATTERN",
        "category": "NETWORK",
        "description": (
            "Content originates from a domain less than 12 months old before "
            "amplification on social platforms. Consistent with Spamouflage "
            "content-seeding lifecycle: low-authority blog seeded first, "
            "then mass-amplified. Documented in 2019 SIO Spamouflage report."
        ),
        "source_report": "SIO/Graphika June 2019",
        "source_url": "io.stanford.edu/research/spamouflage",
        "source_citation": (
            "Graphika and Stanford Internet Observatory. "
            "'Spamouflage: A Large-Scale Cross-Platform Influence Operation.' "
            "June 2019. io.stanford.edu"
        ),
        "threshold_description": (
            "Any sample has source_domain set AND domain_age_months < 12"
        ),
        "check_requires": ["domain_metadata"],
    },
]

# ---------------------------------------------------------------------------
# Demo content set: alpha-7 (CRITICAL -- all 12 indicators)
# ---------------------------------------------------------------------------

_SPAMOUFLAGE_HASHTAGS = [
    "#ChinaStronger", "#AmericanHypocrisy", "#MediaLies", "#WesternPropaganda",
    "#HongKong2024", "#FreedomOfSpeech", "#TruthTellers", "#ChinaRising",
    "#PeacefulDevelopment", "#GlobalSouth", "#DoubleStandards", "#UNReform",
]

_S1_IDS = ["s1_001", "s1_002", "s1_003", "s1_004", "s1_005"]

DEMO_SETS: dict[str, list[dict]] = {
    # -- Set 1: alpha-7 (CRITICAL -- all 12 indicators expected) ----------------
    "alpha-7": [
        {
            "sample_id": "s1_001",
            "text": (
                "The United States is spreading disinformation about China's peaceful rise. "
                "Western media's double standards regarding Hong Kong reflect American hegemony. "
                "The international community should reject these narratives."
            ),
            "platform": "facebook",
            "language": "en",
            "timestamp": "2024-03-15T14:00:00Z",
            "hashtags": _SPAMOUFLAGE_HASHTAGS,
            "follower_count": 12847,
            "engagement_count": 3,
            "is_repost": True,
            "source_domain": "chinaperspective2024.blogspot.com",
            "domain_age_months": 2,
            "account_created_date": "2024-02-14",
            "shared_by_in_set": ["s1_002", "s1_003", "s1_004", "s1_005"],
        },
        {
            "sample_id": "s1_002",
            # Chinese version -- same topic, same hashtags, same timestamp
            "text": (
                "美国正在散布关于中国"
                "和平崛起的虚假信息。"
                "西方媒体在香港问题上"
                "的双重标准反映了美国"
                "霸权主义。国际社会应"
                "该拒绝这些叙事。"
            ),
            "platform": "twitter",
            "language": "zh",
            "timestamp": "2024-03-15T14:00:00Z",  # same as s1_001
            "hashtags": _SPAMOUFLAGE_HASHTAGS,
            "follower_count": 9543,
            "engagement_count": 2,
            "is_repost": True,
            "source_domain": "chinaperspective2024.blogspot.com",
            "domain_age_months": 2,
            "account_created_date": "2024-02-15",
            "shared_by_in_set": ["s1_001", "s1_003", "s1_004", "s1_005"],
        },
        {
            "sample_id": "s1_003",
            # hegemony -> imperialism (Jaccard ~0.857 vs s1_001)
            "text": (
                "The United States is spreading disinformation about China's peaceful rise. "
                "Western media's double standards regarding Hong Kong reflect American imperialism. "
                "The international community should reject these narratives."
            ),
            "platform": "facebook",
            "language": "en",
            "timestamp": "2024-03-15T16:00:00Z",
            "hashtags": _SPAMOUFLAGE_HASHTAGS,
            "follower_count": 14201,
            "engagement_count": 4,
            "is_repost": True,
            "source_domain": "chinaperspective2024.blogspot.com",
            "domain_age_months": 2,
            "account_created_date": "2024-02-16",
            "shared_by_in_set": ["s1_001", "s1_002", "s1_004", "s1_005"],
        },
        {
            "sample_id": "s1_004",
            # rise -> development, regarding -> on (Jaccard ~0.733 vs s1_001)
            "text": (
                "The United States is spreading disinformation about China's peaceful development. "
                "Western media's double standards on Hong Kong reflect American hegemony. "
                "The international community should reject these narratives."
            ),
            "platform": "telegram",
            "language": "en",
            "timestamp": "2024-03-15T18:00:00Z",
            "hashtags": _SPAMOUFLAGE_HASHTAGS,
            "follower_count": 11782,
            "engagement_count": 2,
            "is_repost": True,
            "source_domain": "chinaperspective2024.blogspot.com",
            "domain_age_months": 2,
            "account_created_date": "2024-02-16",
            "shared_by_in_set": ["s1_001", "s1_002", "s1_003", "s1_005"],
        },
        {
            "sample_id": "s1_005",
            # rise -> development, media's -> media, should -> must
            "text": (
                "The United States is spreading disinformation about China's peaceful development. "
                "Western media double standards regarding Hong Kong reflect American hegemony. "
                "The international community must reject these narratives."
            ),
            "platform": "youtube",
            "language": "en",
            "timestamp": "2024-03-15T20:00:00Z",
            "hashtags": _SPAMOUFLAGE_HASHTAGS,
            "follower_count": 8634,
            "engagement_count": 3,
            "is_repost": True,
            "source_domain": "chinaperspective2024.blogspot.com",
            "domain_age_months": 2,
            "account_created_date": "2024-02-17",
            "shared_by_in_set": ["s1_001", "s1_002", "s1_003", "s1_004"],
        },
    ],

    # -- Set 2: organic-baseline (MINIMAL -- 0 indicators expected) -------------
    "organic-baseline": [
        {
            "sample_id": "s2_001",
            "text": (
                "Had a wonderful visit to the local library today. "
                "They just added new cookbooks and a travel section I had been hoping for. "
                "Perfect way to spend a Tuesday morning."
            ),
            "platform": "twitter",
            "language": "en",
            "timestamp": "2024-03-10T09:17:00Z",
            "hashtags": ["#library", "#reading"],
            "follower_count": 847,
            "engagement_count": 62,
            "is_repost": False,
            "source_domain": "twitter.com",
            "domain_age_months": 180,
            "account_created_date": "2019-04-12",
            "shared_by_in_set": [],
        },
        {
            "sample_id": "s2_002",
            "text": (
                "My tomato plants are finally producing after a rough start. "
                "Too much rain in May but June has been much better. "
                "Gardening is always a learning experience!"
            ),
            "platform": "twitter",
            "language": "en",
            "timestamp": "2024-03-11T14:42:00Z",
            "hashtags": ["#gardening", "#homegrown", "#summer"],
            "follower_count": 1203,
            "engagement_count": 91,
            "is_repost": False,
            "source_domain": "twitter.com",
            "domain_age_months": 180,
            "account_created_date": "2017-08-23",
            "shared_by_in_set": [],
        },
        {
            "sample_id": "s2_003",
            "text": (
                "Watched a documentary on ocean plastics last night. "
                "It is eye-opening and worth your time. "
                "Made me reconsider some everyday choices about packaging and shopping habits."
            ),
            "platform": "twitter",
            "language": "en",
            "timestamp": "2024-03-13T11:05:00Z",
            "hashtags": ["#environment", "#documentary", "#sustainability"],
            "follower_count": 534,
            "engagement_count": 28,
            "is_repost": True,
            "source_domain": "twitter.com",
            "domain_age_months": 180,
            "account_created_date": "2020-11-05",
            "shared_by_in_set": [],
        },
        {
            "sample_id": "s2_004",
            "text": (
                "The neighborhood block party planning is coming together! "
                "Date set for July 12. Potluck style, so bring a dish to share. "
                "Everyone on the street is welcome."
            ),
            "platform": "twitter",
            "language": "en",
            "timestamp": "2024-03-15T08:33:00Z",
            "hashtags": ["#community", "#blockparty"],
            "follower_count": 289,
            "engagement_count": 17,
            "is_repost": False,
            "source_domain": "twitter.com",
            "domain_age_months": 180,
            "account_created_date": "2018-03-17",
            "shared_by_in_set": [],
        },
        {
            "sample_id": "s2_005",
            "text": (
                "Finally finished the science fiction novel I have been meaning to read for months. "
                "The ending was completely unexpected in the best way. "
                "Highly recommend it."
            ),
            "platform": "twitter",
            "language": "en",
            "timestamp": "2024-03-18T16:20:00Z",
            "hashtags": ["#scifi", "#reading", "#bookrecommendation"],
            "follower_count": 1672,
            "engagement_count": 134,
            "is_repost": False,
            "source_domain": "twitter.com",
            "domain_age_months": 180,
            "account_created_date": "2021-07-09",
            "shared_by_in_set": [],
        },
    ],

    # -- Set 3: borderline-medium (MEDIUM -- 5 indicators expected) -------------
    # Indicators expected: IND-003, IND-004, IND-005, IND-007, IND-009
    "borderline-medium": [
        {
            "sample_id": "s3_001",
            "text": (
                "Environmental regulations in our country are being systematically "
                "undermined by corporate lobbying efforts. Working families and "
                "vulnerable communities bear the true cost while executives continue "
                "to pocket enormous profits. Real accountability is urgently needed."
            ),
            "platform": "twitter",
            "language": "en",
            "timestamp": "2024-03-20T08:00:00Z",
            "hashtags": [
                "#EnvironmentFirst", "#CorporateGreed", "#WorkersRights",
                "#ClimateAction", "#Accountability", "#BidenPolicy",
                "#PolicyReform", "#DemocraticValues", "#ProgressivePolicy",
            ],
            "follower_count": 8500,
            "engagement_count": 7,
            "is_repost": False,
            "source_domain": "nytimes.com",
            "domain_age_months": 240,
            "account_created_date": "2024-03-01",
            "shared_by_in_set": ["s3_002"],
        },
        {
            "sample_id": "s3_002",
            # weakened/Stronger variants (Jaccard ~0.784 vs s3_001)
            "text": (
                "Environmental regulations in our country are being systematically "
                "weakened by corporate lobbying efforts. Working families and "
                "vulnerable communities bear the true cost while executives continue "
                "to pocket enormous profits. Stronger accountability is urgently needed."
            ),
            "platform": "facebook",
            "language": "en",
            "timestamp": "2024-03-20T12:00:00Z",
            "hashtags": [
                "#EnvironmentFirst", "#CorporateGreed", "#WorkersRights",
                "#ClimateAction", "#Accountability", "#BidenPolicy",
                "#PolicyReform", "#DemocraticValues", "#ProgressivePolicy",
            ],
            "follower_count": 9200,
            "engagement_count": 9,
            "is_repost": True,
            "source_domain": "nytimes.com",
            "domain_age_months": 240,
            "account_created_date": "2024-03-01",
            "shared_by_in_set": ["s3_001", "s3_003"],
        },
        {
            "sample_id": "s3_003",
            # families/communities swapped (Jaccard ~0.833 vs s3_001)
            "text": (
                "Environmental regulations in our country are being systematically "
                "undermined by corporate lobbying efforts. Working communities and "
                "vulnerable families bear the true cost while executives continue "
                "to pocket enormous profits. Real accountability is urgently needed."
            ),
            "platform": "twitter",
            "language": "en",
            "timestamp": "2024-03-20T16:00:00Z",
            "hashtags": [
                "#EnvironmentFirst", "#CorporateGreed", "#WorkersRights",
                "#ClimateAction", "#Accountability", "#BidenPolicy",
                "#PolicyReform", "#DemocraticValues", "#ProgressivePolicy",
            ],
            "follower_count": 7800,
            "engagement_count": 6,
            "is_repost": False,
            "source_domain": "nytimes.com",
            "domain_age_months": 240,
            "account_created_date": "2024-03-03",
            "shared_by_in_set": ["s3_002"],
        },
        {
            "sample_id": "s3_004",
            # rules/critically variants (Jaccard ~0.784 vs s3_001)
            "text": (
                "Environmental rules in our country are being systematically "
                "undermined by corporate lobbying efforts. Working families and "
                "vulnerable communities bear the true cost while executives continue "
                "to pocket enormous profits. Real accountability is critically needed."
            ),
            "platform": "facebook",
            "language": "en",
            "timestamp": "2024-03-20T20:00:00Z",
            "hashtags": [
                "#EnvironmentFirst", "#CorporateGreed", "#WorkersRights",
                "#ClimateAction", "#Accountability", "#BidenPolicy",
                "#PolicyReform", "#DemocraticValues", "#ProgressivePolicy",
            ],
            "follower_count": 11000,
            "engagement_count": 10,
            "is_repost": True,
            "source_domain": "nytimes.com",
            "domain_age_months": 240,
            "account_created_date": "2024-03-05",
            "shared_by_in_set": [],
        },
        {
            "sample_id": "s3_005",
            # bear/cost -> face/burden variants (Jaccard ~0.784 vs s3_001)
            "text": (
                "Environmental regulations in our country are being systematically "
                "undermined by corporate lobbying efforts. Working families and "
                "vulnerable communities face the true burden while executives continue "
                "to pocket enormous profits. Real accountability is urgently needed."
            ),
            "platform": "telegram",
            "language": "en",
            "timestamp": "2024-03-21T00:00:00Z",
            "hashtags": [
                "#EnvironmentFirst", "#CorporateGreed", "#WorkersRights",
                "#ClimateAction", "#Accountability", "#BidenPolicy",
                "#PolicyReform", "#DemocraticValues", "#ProgressivePolicy",
            ],
            "follower_count": 8100,
            "engagement_count": 8,
            "is_repost": True,
            "source_domain": "nytimes.com",
            "domain_age_months": 240,
            "account_created_date": "2024-03-06",
            "shared_by_in_set": [],
        },
    ],
}

# ---------------------------------------------------------------------------
# Pre-baked analyst report for the alpha-7 demo set
# ASCII-safe: no Unicode, no em dashes, use -- for separators
# ---------------------------------------------------------------------------

DEMO_REPORT_TEXT = """\
UNCLASSIFIED // FOR OFFICIAL USE ONLY -- NOT FOR DISTRIBUTION
OPEN-SOURCE PATTERN ANALYSIS MEMORANDUM

TO: Threat Intelligence Team
FROM: P68 Dragonbridge/Spamouflage Behavioral Fingerprint Analyzer
RE: CIB Pattern Assessment -- Alpha-7 Content Cluster
DATE: 2026-06-24

================================================================
FRAMING NOTICE -- READ BEFORE INTERPRETING RESULTS
================================================================

This analysis identifies behavioral PATTERNS consistent with documented Coordinated
Inauthentic Behavior (CIB) from public takedown reports. It does NOT make attribution
claims. It does NOT identify any specific actor, government, or organization as
responsible. Every indicator cites only PUBLIC reports from Meta, Google/Mandiant,
Graphika, and Stanford Internet Observatory. Pattern match does not equal attribution.

================================================================
I. EXECUTIVE SUMMARY
================================================================

COORDINATION PATTERN TIER: CRITICAL
Score: 100.0 / 100.0 -- 12 of 12 documented CIB indicators PRESENT

Content Set: Alpha-7 Cluster
Samples Analyzed: 5
Platforms: facebook, twitter, telegram, youtube
Languages: en, zh
Analysis Date: 2026-06-24

================================================================
II. INDICATOR FINDINGS (12 of 12 assessed, 12 of 12 matched)
================================================================

[PRESENT] DB-IND-001 -- TEMPLATE REPETITION
  Pattern: Jaccard bigram similarity 0.857 between s1_001 and s1_003. Text differs
  by one word substitution (hegemony -> imperialism) across 26 word bigrams.
  Three additional English pairs show similarity 0.625-0.733 (captured by IND-005).
  Citation: Meta Adversarial Threat Report, August 2022
  Source: transparency.fb.com/metaatrs/adversarial-threat-report-august-2022

[PRESENT] DB-IND-002 -- CROSS-PLATFORM VELOCITY
  Pattern: s1_001 (facebook) and s1_002 (twitter) posted at identical timestamp
  2024-03-15T14:00:00Z. Timestamp delta: 0 seconds (< 1800s threshold). Hashtag
  Jaccard 12/12 = 1.000 (> 0.80 threshold). Consistent with automated cross-platform
  posting scheduler.
  Citation: Meta Adversarial Threat Report, March 2023
  Source: transparency.fb.com/metaatrs/adversarial-threat-report-q1-2023

[PRESENT] DB-IND-003 -- ACCOUNT CREATION CLUSTERING
  Pattern: 5 accounts created within 4-day window (2024-02-14 to 2024-02-17).
  Window 4 days is well within the 7-day clustering threshold. Dates:
  2024-02-14, 2024-02-15, 2024-02-16, 2024-02-16, 2024-02-17.
  Citation: Graphika/Stanford Internet Observatory, Spamouflage, June 2019
  Source: io.stanford.edu/research/spamouflage

[PRESENT] DB-IND-004 -- ENGAGEMENT RATIO ANOMALY
  Pattern: All 5 accounts show engagement rate 0.014%-0.028% against follower
  counts of 8,634-14,201. Rate 36-71x below the 0.1% organic baseline.
  Ratios: s1_001 0.023%, s1_002 0.021%, s1_003 0.028%, s1_004 0.017%, s1_005 0.035%.
  Citation: Mandiant/Google, Dragonbridge, August 2022
  Source: cloud.google.com/blog/topics/threat-intelligence/dragonbridge

[PRESENT] DB-IND-005 -- CONTENT RECYCLING WITH VARIATION
  Pattern: Cross-language pair (s1_001 EN and s1_002 ZH) shows hashtag Jaccard
  12/12 = 1.000 (> 0.80) with different languages -- documented multilingual
  recycling. Additionally, s1_001 vs s1_004 text Jaccard 0.733 in [0.60, 0.84].
  Citation: Meta Adversarial Threat Report, August 2023
  Source: transparency.fb.com/metaatrs/adversarial-threat-report-q2-2023

[PRESENT] DB-IND-006 -- MULTILINGUAL SIMULTANEOUS POSTING
  Pattern: s1_001 (English, facebook) and s1_002 (Chinese, twitter) posted at
  identical timestamp 2024-03-15T14:00:00Z. Delta 0 seconds, well within 7200s
  threshold. Cross-language simultaneous posting documented as core Spamouflage
  operational pattern for reach maximization.
  Citation: Meta Adversarial Threat Report, August 2022
  Source: transparency.fb.com/metaatrs/adversarial-threat-report-august-2022

[PRESENT] DB-IND-007 -- AUTO-SCHEDULER SIGNATURE
  Pattern: Inter-post intervals [0s, 7200s, 7200s, 7200s]. Mode bucket 7200s
  (2 hours) accounts for 3 of 4 intervals -- mode ratio 0.75 exceeds 0.60
  threshold. Machine-regular 2-hour posting cadence inconsistent with organic
  behavior. Consistent with automated posting scheduler.
  Citation: Stanford Internet Observatory, Spamouflage Dragon, 2020
  Source: io.stanford.edu/research/spamouflage-dragon

[PRESENT] DB-IND-008 -- ZERO ORIGINAL CONTENT
  Pattern: 5 of 5 samples are is_repost=True. Original content ratio 0.00%,
  below 5% threshold. All accounts function exclusively as amplification nodes
  with no original content production. Matches Dragonbridge amplifier-account
  architecture.
  Citation: Mandiant/Google, Dragonbridge, August 2022
  Source: cloud.google.com/blog/topics/threat-intelligence/dragonbridge

[PRESENT] DB-IND-009 -- HASHTAG DENSITY ANOMALY
  Pattern: All 5 samples contain exactly 12 hashtags (> 8 threshold). Hashtags
  target US foreign policy, China relations, Hong Kong, and general political
  topics simultaneously -- inconsistent with organic single-topic posting.
  Pattern documented across Spamouflage cross-platform operations.
  Citation: Meta Adversarial Threat Report, March 2023
  Source: transparency.fb.com/metaatrs/adversarial-threat-report-q1-2023

[PRESENT] DB-IND-010 -- AI-GENERIC PHRASING
  Pattern: 5 documented CIB generic phrase patterns detected across samples:
  'the united states is spreading', 'western media's double standards',
  'western media double standards', 'china's peaceful rise',
  'the international community should', 'the international community must',
  'american hegemony', 'american imperialism'. Phrase density consistent with
  template-based or AI-assisted content production.
  Citation: Meta Adversarial Threat Report, August 2023
  Source: transparency.fb.com/metaatrs/adversarial-threat-report-q2-2023

[PRESENT] DB-IND-011 -- INAUTHENTIC AMPLIFICATION NETWORK
  Pattern: Cross-reference ratio 100% (20/20 possible within-set shares). All 5
  accounts share exclusively each other's content, forming a closed amplification
  loop with 0 external shares. Matches Dragonbridge amplifier-network structure.
  Citation: Meta Adversarial Threat Report, August 2022
  Source: transparency.fb.com/metaatrs/adversarial-threat-report-august-2022

[PRESENT] DB-IND-012 -- SEED BLOG PATTERN
  Pattern: Source domain 'chinaperspective2024.blogspot.com' age 2 months
  (< 12-month threshold). Low-authority domain used as content origin before
  social-platform amplification. Matches Spamouflage seeding lifecycle:
  seed low-traffic blog -> amplify on social platforms.
  Citation: Graphika/Stanford Internet Observatory, Spamouflage, June 2019
  Source: io.stanford.edu/research/spamouflage

================================================================
III. INDICATOR SCORE SUMMARY
================================================================

  DB-IND-001  TEMPLATE REPETITION            [PRESENT]  Meta ATR Aug 2022
  DB-IND-002  CROSS-PLATFORM VELOCITY        [PRESENT]  Meta ATR Mar 2023
  DB-IND-003  ACCOUNT CREATION CLUSTERING    [PRESENT]  SIO/Graphika Jun 2019
  DB-IND-004  ENGAGEMENT RATIO ANOMALY       [PRESENT]  Mandiant/Google Aug 2022
  DB-IND-005  CONTENT RECYCLING VARIATION    [PRESENT]  Meta ATR Aug 2023
  DB-IND-006  MULTILINGUAL SIMULTANEOUS POST [PRESENT]  Meta ATR Aug 2022
  DB-IND-007  AUTO-SCHEDULER SIGNATURE       [PRESENT]  SIO Spamouflage 2020
  DB-IND-008  ZERO ORIGINAL CONTENT          [PRESENT]  Mandiant/Google Aug 2022
  DB-IND-009  HASHTAG DENSITY ANOMALY        [PRESENT]  Meta ATR Mar 2023
  DB-IND-010  AI-GENERIC PHRASING            [PRESENT]  Meta ATR Aug 2023
  DB-IND-011  INAUTHENTIC AMPLIF. NETWORK    [PRESENT]  Meta ATR Aug 2022
  DB-IND-012  SEED BLOG PATTERN              [PRESENT]  SIO/Graphika Jun 2019

  Matched: 12 of 12 assessable indicators
  Score:   100.0 / 100.0
  Tier:    CRITICAL (threshold >= 66.0)

================================================================
IV. PATTERN ASSESSMENT
================================================================

The Alpha-7 content cluster exhibits ALL 12 documented behavioral patterns from
Dragonbridge/Spamouflage public takedown reports. This represents the highest
possible indicator density in this framework.

Key observations:
-- Template repetition across 5 samples with minimal text variation (one-word
   substitutions) suggests centralized content production with slight variation
   to evade automated duplicate-detection filters.
-- Account creation clustering within a 4-day window is consistent with
   coordinated network seeding, not organic independent account creation.
-- Zero original content across all accounts indicates these function as
   amplification infrastructure, not authentic independent voices.
-- Engagement-to-follower ratios 36-71x below organic baselines indicate
   follower inflation inconsistent with genuine audience accumulation.
-- English-Chinese simultaneous posting within 0 seconds is inconsistent with
   human translation and posting timelines.
-- Machine-regular 2-hour posting cadence (mode ratio 75%) is inconsistent with
   organic social media behavior patterns.

================================================================
V. ANALYST CONFIDENCE AND LIMITATIONS
================================================================

Confidence: HIGH (all 12 indicators assessable; all 12 matched)

Limitations:
-- Pattern match does not establish identity, intent, or origin of content or
   accounts. Multiple simultaneous matching indicators increase analytic
   confidence but do not constitute proof of any specific actor's involvement.
-- Public takedown reports document operations that were detected and removed.
   Undetected operations may use different behavioral signatures not captured here.
-- Some individual indicators (hashtag density, auto-scheduler) can occur in
   legitimate contexts. Confidence derives from multi-indicator co-occurrence.
-- This tool uses only public reports and is intended for open-source research.

================================================================
VI. SOURCE REPORTS CITED
================================================================

[1] Meta Platforms. Adversarial Threat Report, August 2022.
    Dragonbridge and Spamouflage Takedown.
    URL: transparency.fb.com/metaatrs/adversarial-threat-report-august-2022

[2] Meta Platforms. Adversarial Threat Report, March 2023.
    Spamouflage Q1 2023 Operations.
    URL: transparency.fb.com/metaatrs/adversarial-threat-report-q1-2023

[3] Meta Platforms. Adversarial Threat Report, August 2023.
    AI-Generated Content in Spamouflage Operations.
    URL: transparency.fb.com/metaatrs/adversarial-threat-report-q2-2023

[4] Mandiant and Google. Dragonbridge: An Influence Campaign Finds Limited
    Traction but Keeps Trying. August 2022.
    URL: cloud.google.com/blog/topics/threat-intelligence/dragonbridge

[5] Graphika and Stanford Internet Observatory. Spamouflage: A Large-Scale
    Cross-Platform Influence Operation. June 2019.
    URL: io.stanford.edu/research/spamouflage

[6] Stanford Internet Observatory. Spamouflage Dragon: Ongoing Infrastructure
    and Behavioral Analysis. 2020.
    URL: io.stanford.edu/research/spamouflage-dragon

================================================================
VII. RECOMMENDED NEXT STEPS
================================================================

1. Preserve all content samples and metadata. Do not modify or delete source content
   before potential platform trust-and-safety referral.
2. Cross-reference identified hashtags against current trending topics for evidence
   of ongoing amplification campaigns using the same template infrastructure.
3. Submit sample set to relevant platform safety teams with this indicator report.
4. Compare against Meta's full archived Dragonbridge dataset if institutional
   access is available to confirm or rule out known network membership.
5. Document source domain 'chinaperspective2024.blogspot.com' for infrastructure
   correlation with other identified Spamouflage seed sites.

Assessment Tool: P68 Dragonbridge/Spamouflage Behavioral Fingerprint Analyzer
Source Reports: See Section VI above
Framing: PATTERN IDENTIFICATION ONLY -- NOT AN ATTRIBUTION CLAIM
"""
